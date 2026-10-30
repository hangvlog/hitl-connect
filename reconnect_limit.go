package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var errReconnectStopped = errors.New("RECONNECT_STOPPED: legacy automatic stop; start manually to retry")
var errReconnectState = errors.New("RECONNECT_STATE_UNAVAILABLE: cannot read or save reconnect state")

type reconnectState struct {
	FirstFailure time.Time     `json:"firstFailure,omitempty"`
	Stopped      bool          `json:"stopped"`
	Delay        time.Duration `json:"delay,omitempty"`
	TierAttempts int           `json:"tierAttempts,omitempty"`
	NextAttempt  time.Time     `json:"nextAttempt,omitempty"`
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
	changed          chan struct{}
	relay            string
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
	b := &reconnectBudget{file: file, relay: c.Relay}
	if file != "" {
		b.loadErr = readJSON(file, &b.state)
		if os.IsNotExist(b.loadErr) {
			b.loadErr = nil
		}
		// Old automatic-stop files are no longer an outage policy. The separate
		// connection plan still preserves explicit user stop/resume intent.
		if b.loadErr == nil && b.state.Stopped {
			b.state.Stopped = false
			b.saveLocked()
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
	return nil
}

func (b *reconnectBudget) attempt(ctx context.Context) (context.Context, context.CancelFunc, error) {
	err := b.await(ctx)
	return ctx, func() {}, err
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
	if ctx.Err() != nil {
		return ctx.Err()
	}
	b.mu.Lock()
	if err := b.checkLocked(time.Now()); err != nil {
		b.mu.Unlock()
		return err
	}
	if b.state.FirstFailure.IsZero() || delay <= 0 {
		b.mu.Unlock()
		return waitReconnect(ctx, delay)
	}
	if !time.Now().Before(b.state.NextAttempt) {
		backoff := reconnectBackoff{delay: b.state.Delay, tierAttempts: b.state.TierAttempts}
		// Retry-After may extend the schedule, but cannot raise the daily cap.
		delay = max(backoff.next(), min(delay, 24*time.Hour))
		b.state.Delay, b.state.TierAttempts = backoff.delay, backoff.tierAttempts
		b.state.NextAttempt = time.Now().Add(delay)
		b.saveLocked()
		fmt.Fprintf(os.Stderr, "reconnect scheduled: delay=%s next=%s\n", delay.Round(time.Second), b.state.NextAttempt.Format(time.RFC3339))
	}
	b.mu.Unlock()
	return b.await(ctx)
}

func (b *reconnectBudget) wakeLocked() {
	if b.changed != nil {
		close(b.changed)
	}
	b.changed = make(chan struct{})
}

func (b *reconnectBudget) await(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		// The GUI and v2 worker are separate processes. Explicit Start writes
		// a cleared state; a sleeping worker must observe it without restart.
		if b.file != "" && !b.state.NextAttempt.IsZero() {
			var saved reconnectState
			if err := readJSON(b.file, &saved); err != nil {
				b.loadErr = err
			} else if saved.FirstFailure.IsZero() && saved.NextAttempt.IsZero() {
				b.epoch++
				b.state = saved
				b.stopHealthyTimerLocked()
				if b.relay != "" {
					retryGate(b.relay).healthy()
				}
			}
		}
		if err := b.checkLocked(time.Now()); err != nil {
			b.mu.Unlock()
			return err
		}
		delay := time.Until(b.state.NextAttempt)
		if delay <= 0 {
			b.mu.Unlock()
			return nil
		}
		if b.changed == nil {
			b.changed = make(chan struct{})
		}
		changed := b.changed
		b.mu.Unlock()
		if b.file != "" {
			delay = min(delay, time.Second)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
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
			b.wakeLocked()
			b.healthTimer = nil
			if b.relay != "" {
				retryGate(b.relay).healthy()
			}
		}
	})
}

func retryMinimum() time.Duration { return time.Nanosecond }

type reconnectView struct {
	FirstFailure        time.Time `json:"firstFailure"`
	NextAttempt         time.Time `json:"nextAttempt"`
	NominalDelaySeconds int64     `json:"nominalDelaySeconds"`
	TierAttempts        int       `json:"tierAttempts"`
}

// Read the worker's durable state, including when GUI and v2 worker differ.
func retryView(base, role, channel string) *reconnectView {
	var state reconnectState
	if readJSON(filepath.Join(base, "public-"+role, "reconnect-"+channel+".json"), &state) != nil || state.FirstFailure.IsZero() {
		return nil
	}
	return &reconnectView{state.FirstFailure, state.NextAttempt, int64(state.Delay / time.Second), state.TierAttempts}
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
	b.wakeLocked()
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
