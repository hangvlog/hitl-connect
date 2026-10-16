package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type providerRuntime struct {
	mu             sync.Mutex
	active         int
	draining       bool
	changed        chan struct{}
	idleCancel     context.CancelFunc
	controlSeen    time.Time
	controlOnline  bool
	idle           int
	serviceReadyAt time.Time
}

func newProviderRuntime() *providerRuntime { return &providerRuntime{changed: make(chan struct{})} }
func (r *providerRuntime) notify()         { close(r.changed); r.changed = make(chan struct{}) }
func (r *providerRuntime) begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining {
		return false
	}
	r.active++
	r.notify()
	return true
}
func (r *providerRuntime) activeCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.active }
func (r *providerRuntime) end()             { r.mu.Lock(); defer r.mu.Unlock(); r.active--; r.notify() }
func (r *providerRuntime) isDraining() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.draining }
func (r *providerRuntime) drain(ctx context.Context) error {
	r.mu.Lock()
	if r.draining {
		r.mu.Unlock()
		return errors.New("UPDATE_ALREADY_DRAINING")
	}
	r.draining = true
	if r.idleCancel != nil {
		r.idleCancel()
	}
	r.notify()
	for r.active > 0 {
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			r.mu.Lock()
			r.draining = false
			r.notify()
			r.mu.Unlock()
			return errors.New("UPDATE_DEFERRED_ACTIVE_SESSIONS")
		case <-changed:
		}
		r.mu.Lock()
	}
	// A failed installer/SCM stop must not leave a live provider paused forever.
	// The updater gets a bounded window to stop the drained process.
	time.AfterFunc(65*time.Second, r.resume)
	r.mu.Unlock()
	return nil
}
func (r *providerRuntime) resume() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.draining = false
	r.notify()
}

// Existing authorized v3 providers run inside the panel/service process. No
// child watchdog, account change, new startup registration or extra service.
func (g *guiSession) startProviderV3(r guiRequest, c *Config) error {
	c.runtime = newProviderRuntime()
	c.recovery = &enrollmentRecovery{}
	c.sshAccount = r.User
	if err := g.savePlan(r, true); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	g.mu.Lock()
	g.runtime = c.runtime
	g.cancel = cancel
	g.done = done
	g.state.Running = true
	g.state.Configured = true
	generation := g.generation
	g.mu.Unlock()
	go func() {
		defer close(done)
		err := registerProviderUntilAvailable(ctx, c)
		if err == nil && r.User != "" {
			err = ensureSSHGrant(c, r.User)
		}
		if err == nil {
			key, e := os.ReadFile(localPath(c, "connection-key-ssh.txt"))
			if e == nil {
				g.mu.Lock()
				g.invitation = strings.TrimSpace(string(key))
				g.state.HasInvitation = true
				g.mu.Unlock()
			}
			g.step("relay", "working", "正在连接中继；设备在线状态由独立控制通道确认")
			err = serve(ctx, c)
		}
		g.mu.Lock()
		if g.generation == generation {
			g.state.Running = false
			g.state.HasInvitation = false
			g.runtime = nil
		}
		g.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			g.connectionError(err)
		}
	}()
	return nil
}
func (g *guiSession) drainProvider(ctx context.Context) error {
	g.mu.Lock()
	runtime := g.runtime
	running := g.state.Running
	g.mu.Unlock()
	if !running {
		return nil
	}
	if runtime == nil {
		return errors.New("UPDATE_DRAIN_UNSUPPORTED")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return runtime.drain(ctx)
}
func drainManagedBeforeUpgrade(ctx context.Context, root string) error {
	c, err := load(filepath.Join(root, "public-host", "config.json"))
	if err != nil {
		return errors.New("UPDATE_DRAIN_CONFIG_UNAVAILABLE")
	}
	if c.Protocol != "v3" {
		return errors.New("UPDATE_DRAIN_UNSUPPORTED")
	}
	d, err := agentSession(root)
	if err != nil {
		return errors.New("UPDATE_DRAIN_UNAVAILABLE")
	}
	var result struct {
		OK bool `json:"ok"`
	}
	return agentCall(ctx, d, "drain", &guiRequest{}, &result)
}

func (r *providerRuntime) control(online bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controlOnline = online
	if online {
		r.controlSeen = time.Now()
	}
}
func (r *providerRuntime) pool(delta int) { r.mu.Lock(); defer r.mu.Unlock(); r.idle += delta }
func (r *providerRuntime) ready()         { r.mu.Lock(); defer r.mu.Unlock(); r.serviceReadyAt = time.Now() }
func (r *providerRuntime) project(state *guiState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state.ProtocolVersion = 3
	state.ActiveSessions = r.active
	state.IdleChannels = r.idle
	state.ControlState = "offline"
	if r.controlOnline {
		state.ControlState = "online"
		if time.Since(r.controlSeen) > 40*time.Second {
			state.ControlState = "suspect"
		}
	}
	if r.draining {
		state.ControlState = "draining"
	}
	if !r.controlSeen.IsZero() {
		state.ControlSeenAt = r.controlSeen.UTC().Format(time.RFC3339)
	}
	if !r.serviceReadyAt.IsZero() {
		state.ServiceReadyAt = r.serviceReadyAt.UTC().Format(time.RFC3339)
	}
}
