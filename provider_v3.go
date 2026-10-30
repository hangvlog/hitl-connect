package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// One control and a bounded number of idle slots per device. A paired slot is
// transferred to the process context, never to the control generation context.
func serveV3(ctx context.Context, c *Config) error {
	unlock, locked, err := tryProfileLock(filepath.Dir(c.path), ".provider.lock")
	if err != nil {
		return err
	}
	if !locked {
		return errors.New("PROVIDER_ALREADY_RUNNING")
	}
	defer unlock()
	if c.runtime == nil {
		c.runtime = newProviderRuntime()
	}
	instance := newTransportTrace()
	pool := c.IdleChannels
	if pool == 0 {
		pool = 2
	}
	var sessions sync.WaitGroup
	defer sessions.Wait()
	active := make(chan struct{}, c.capacity().ProviderConnections)
	dials := make(chan struct{}, 8)
	backoff := reconnectBackoff{}
	budget := budgetFor(c, "ssh")
	fmt.Printf("serving device=%s services=%d protocol=v3\n", c.ID, len(c.Services))
	for ctx.Err() == nil {
		started := time.Now()
		var online time.Time
		err = providerGeneration(ctx, c, instance, pool, active, dials, &sessions, func() { online = time.Now() })
		if ctx.Err() != nil {
			return nil
		}
		if stopped := budget.failure(); stopped != nil {
			return stopped
		}
		reportLifecycle(c, instance, "control", "closed", "control", err, time.Since(started), nil)
		if !online.IsZero() && time.Since(online) >= reconnectStable {
			backoff = reconnectBackoff{}
		}
		if err := budget.wait(ctx, backoff.next()); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	return nil
}

func providerGeneration(ctx context.Context, c *Config, instance string, pool int, active, dials chan struct{}, sessions *sync.WaitGroup, ready func()) error {
	endpoint, err := relayURL(c)
	if err != nil {
		return err
	}
	ws, err := openRelay(ctx, c, endpoint)
	var rejected *relayFailure
	if c.recovery != nil && errors.As(err, &rejected) && rejected.status == 401 && ctx.Err() == nil {
		if err = c.recovery.lock(ctx); err != nil {
			return err
		}
		err = registerProvider(ctx, c)
		c.recovery.unlock()
		if err == nil {
			ws, err = openRelay(ctx, c, endpoint)
		}
	}
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1024)
	handshakeCtx, cancelBudget, budgetErr := budgetFor(c, "ssh").attempt(ctx)
	if budgetErr != nil {
		return budgetErr
	}
	defer cancelBudget()
	handshakeCtx, cancel := context.WithTimeout(handshakeCtx, 10*time.Second)
	defer cancel()
	payload, _ := json.Marshal(Hello{Role: "control", InstanceID: instance})
	if err = ws.Write(handshakeCtx, websocket.MessageText, payload); err != nil {
		return err
	}
	kind, data, err := ws.Read(handshakeCtx)
	var registered struct {
		State           string `json:"state"`
		Generation      string `json:"generation"`
		HeartbeatMs     int    `json:"heartbeatMs"`
		MaxIdleChannels int    `json:"maxIdleChannels"`
	}
	if err != nil {
		return pairingError(err)
	}
	if kind != websocket.MessageText || json.Unmarshal(data, &registered) != nil || registered.State != "registered" || registered.Generation == "" {
		return errors.New("CONTROL_PROTOCOL_REJECTED")
	}
	heartbeatInterval := time.Duration(registered.HeartbeatMs) * time.Millisecond
	if heartbeatInterval < 500*time.Millisecond || heartbeatInterval > 20*time.Second {
		heartbeatInterval = 20 * time.Second
	}
	c.runtime.control(true)
	stopHealthy := budgetFor(c, "ssh").online()
	defer stopHealthy()
	ready()
	defer c.runtime.control(false)
	reportLifecycle(c, instance, "control", "online", "control", nil, 0, nil)
	generationCtx, stop := context.WithCancel(ctx)
	c.runtime.mu.Lock()
	c.runtime.idleCancel = stop
	if c.runtime.draining {
		stop()
	}
	c.runtime.mu.Unlock()
	var workers sync.WaitGroup
	// Stop and join idle workers only; established sessions remain on ctx.
	defer func() { stop(); ws.CloseNow(); workers.Wait() }()
	maximum := registered.MaxIdleChannels
	if maximum == 0 {
		maximum = 4
	} // Older relays retain their advertised wire contract.
	maximum = min(maximum, c.capacity().MaxIdleChannels)
	pool = min(pool, maximum)
	for i := 0; i < maximum; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			providerSlot(generationCtx, ctx, c, registered.Generation, active, dials, sessions, i, pool, maximum)
		}()
	}
	replies := make(chan error, 1)
	go func() {
		var lastSeq int64
		for {
			readCtx, cancel := context.WithTimeout(ctx, 3*heartbeatInterval)
			kind, data, err := ws.Read(readCtx)
			cancel()
			if err != nil {
				replies <- err
				return
			}
			var ack struct {
				State string `json:"state"`
				Seq   int64  `json:"seq"`
			}
			if kind != websocket.MessageText || json.Unmarshal(data, &ack) != nil || ack.State != "ack" || ack.Seq <= lastSeq {
				replies <- errors.New("CONTROL_PROTOCOL_REJECTED")
				return
			}
			lastSeq = ack.Seq
			c.runtime.control(true)
		}
	}()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	var seq int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-replies:
			return err
		case <-ticker.C:
			if generationCtx.Err() != nil && !c.runtime.isDraining() {
				return errors.New("DRAIN_RESUMED")
			}
			seq++
			payload, _ := json.Marshal(map[string]any{"type": "heartbeat", "seq": seq, "draining": c.runtime.isDraining()})
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := ws.Write(writeCtx, websocket.MessageText, payload)
			cancel()
			if err != nil {
				return err
			}
		}
	}
}

func providerSlot(idleCtx, sessionCtx context.Context, c *Config, generation string, active, dials chan struct{}, sessions *sync.WaitGroup, index, base, maximum int) {
	backoff := reconnectBackoff{}
	for idleCtx.Err() == nil {
		if index >= desiredIdle(base, maximum, c.runtime.activeCount()) {
			select {
			case <-idleCtx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		// Reserve provider capacity before pairing, so saturation queues at the
		// relay instead of dropping a caller that already completed pairing.
		select {
		case active <- struct{}{}:
		case <-idleCtx.Done():
			return
		}
		// dialRelay releases this semaphore immediately after the WSS handshake,
		// not after waiting for a caller to consume the idle slot.
		select {
		case dials <- struct{}{}:
		case <-idleCtx.Done():
			<-active
			return
		}
		hello := Hello{Role: "accept", Generation: generation}
		slotCtx := idleCtx
		cancelSlot := func() {}
		if index >= base {
			slotCtx, cancelSlot = context.WithTimeout(idleCtx, 10*time.Second)
		}
		ws, paired, err := dialRelayWithReady(slotCtx, c, hello, func() { <-dials })
		expired := slotCtx.Err() != nil
		cancelSlot()
		if err != nil {
			<-active
			if expired && idleCtx.Err() == nil {
				continue
			}
			if idleCtx.Err() != nil {
				return
			}
			reportLifecycle(c, newTransportTrace(), "accept", "failed", "pool", err, 0, nil)
			if budgetFor(c, "ssh").wait(idleCtx, backoff.next()) != nil {
				return
			}
			continue
		}
		backoff = reconnectBackoff{}
		if !c.runtime.begin() {
			<-active
			if paired.stopHealthy != nil {
				paired.stopHealthy()
			}
			ws.CloseNow()
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer c.runtime.end()
			defer func() { <-active }()
			acceptSession(sessionCtx, c, ws, paired, c.Services[paired.Service])
		}()
	}
}
