package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const reconnectLimit = 2 * time.Hour

var errReconnectStopped = errors.New("RECONNECT_STOPPED: automatic reconnect stopped after 2 hours; start manually to retry")
var errReconnectState = errors.New("RECONNECT_STATE_UNAVAILABLE: cannot read or save reconnect state")

type reconnectState struct {
	FirstFailure time.Time `json:"firstFailure,omitempty"`
	Stopped      bool      `json:"stopped"`
}

// Separate SSH and HTTP outage clocks: a working SSH channel must not keep a
// broken HTTP publisher retrying forever. No credentials enter this file.
type reconnectBudget struct {
	mu               sync.Mutex
	file             string
	state            reconnectState
	loadErr          error
	epoch            uint64
	onlineCount      int
	healthGeneration uint64
	healthTimer      *time.Timer
}

var reconnectBudgets sync.Map

func budgetFor(c *Config, channel string) *reconnectBudget {
	key := c.path + "\x00" + channel
	file := ""
	if c.path == "" {
		key = c.Relay + "\x00" + channel
	} else {
		file = filepath.Join(filepath.Dir(c.path), "reconnect-"+channel+".json")
	}
	if b, ok := reconnectBudgets.Load(key); ok {
		return b.(*reconnectBudget)
	}
	b := &reconnectBudget{file: file}
	if file != "" {
		b.loadErr = readJSON(file, &b.state)
		if os.IsNotExist(b.loadErr) {
			b.loadErr = nil
		}
	}
	actual, _ := reconnectBudgets.LoadOrStore(key, b)
	return actual.(*reconnectBudget)
}

func (b *reconnectBudget) saveLocked() {
	if b.file != "" {
		b.loadErr = privateJSON(b.file, b.state)
	}
}

func (b *reconnectBudget) checkLocked(now time.Time) error {
	if b.loadErr != nil {
		return errReconnectState
	}
	if !b.state.Stopped && !b.state.FirstFailure.IsZero() && !now.Before(b.state.FirstFailure.Add(reconnectLimit)) {
		b.state.Stopped = true
		b.epoch++
		b.stopHealthyTimerLocked()
		b.saveLocked()
	}
	if b.state.Stopped {
		return errReconnectStopped
	}
	return nil
}

func (b *reconnectBudget) attempt(ctx context.Context) (context.Context, context.CancelFunc, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(time.Now()); err != nil {
		return ctx, func() {}, err
	}
	if !b.state.FirstFailure.IsZero() {
		limited, cancel := context.WithDeadline(ctx, b.state.FirstFailure.Add(reconnectLimit))
		return limited, cancel, nil
	}
	return ctx, func() {}, nil
}

func (b *reconnectBudget) failure() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.epoch++
	if b.state.FirstFailure.IsZero() {
		b.state.FirstFailure = time.Now()
		b.saveLocked()
	}
	err := b.checkLocked(time.Now())
	if err == nil {
		b.scheduleHealthyLocked()
	}
	return err
}

func (b *reconnectBudget) result(err error, parent context.Context) error {
	if err == nil || errors.Is(parent.Err(), context.Canceled) {
		return err
	}
	if stopped := b.failure(); stopped != nil {
		return stopped
	}
	return err
}

func (b *reconnectBudget) wait(ctx context.Context, delay time.Duration) error {
	limited, cancel, err := b.attempt(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	err = waitReconnect(limited, delay)
	b.mu.Lock()
	defer b.mu.Unlock()
	if parentErr := ctx.Err(); parentErr != nil {
		return parentErr
	}
	if stopped := b.checkLocked(time.Now()); stopped != nil {
		return stopped
	}
	return err
}

func (b *reconnectBudget) stopHealthyTimerLocked() {
	if b.healthTimer != nil {
		b.healthTimer.Stop()
		b.healthTimer = nil
	}
}

// Overlapping acknowledged connections share uptime. Re-arm after a failure,
// rather than permanently invalidating a still-live control/idle connection.
func (b *reconnectBudget) scheduleHealthyLocked() {
	b.stopHealthyTimerLocked()
	if b.onlineCount == 0 || b.state.Stopped || b.state.FirstFailure.IsZero() {
		return
	}
	epoch, generation := b.epoch, b.healthGeneration
	b.healthTimer = time.AfterFunc(reconnectStable, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.onlineCount > 0 && b.epoch == epoch && b.healthGeneration == generation && !b.state.Stopped {
			b.state = reconnectState{}
			b.saveLocked()
			b.healthTimer = nil
		}
	})
}

// Only continuous acknowledged uptime clears the outage, never an HTTP 101.
func (b *reconnectBudget) online() func() {
	b.mu.Lock()
	generation := b.healthGeneration
	closed := false
	b.onlineCount++
	if b.onlineCount == 1 {
		b.scheduleHealthyLocked()
	}
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !closed && b.healthGeneration == generation {
			b.onlineCount--
			if b.onlineCount == 0 {
				b.stopHealthyTimerLocked()
				b.healthGeneration++
			}
		}
		closed = true
	}
}

// Only the explicit local start action resets a stopped clock. Automatic
// resume, diagnosis, child recovery and opening the panel must not call this.
func (b *reconnectBudget) manualReset() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.epoch++
	b.stopHealthyTimerLocked()
	b.state = reconnectState{}
	b.loadErr = nil
	b.saveLocked()
	return b.loadErr
}

func (g *guiSession) resetReconnectLimit(request guiRequest) error {
	r, err := g.resolveRequest(request)
	if err != nil {
		return err
	}
	g.mu.Lock()
	stopped := g.state.Problem != nil && g.state.Problem.Code == "RECONNECT_STOPPED"
	g.mu.Unlock()
	if stopped {
		g.stop()
	}
	c, err := load(filepath.Join(g.base, "public-"+r.Role, "config.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, channel := range []string{"ssh", "http"} {
		if err = budgetFor(c, channel).manualReset(); err != nil {
			return err
		}
	}
	gate := retryGate(c.Relay)
	gate.mu.Lock()
	gate.epoch++
	gate.open, gate.next, gate.healthySince, gate.backoff = false, time.Time{}, time.Time{}, reconnectBackoff{}
	close(gate.changed)
	gate.changed = make(chan struct{})
	gate.mu.Unlock()
	return nil
}

func (g *guiSession) reconnectProblem() *connectionProblem {
	c, err := load(filepath.Join(g.base, "public-"+g.state.Role, "config.json"))
	if err != nil {
		return nil
	}
	b := budgetFor(c, "ssh")
	b.mu.Lock()
	err = b.checkLocked(time.Now())
	b.mu.Unlock()
	if err != nil {
		return describeConnectionError(err)
	}
	return nil
}

func isReconnectStopped(err error) bool {
	return errors.Is(err, errReconnectStopped) || errors.Is(err, errReconnectState)
}
