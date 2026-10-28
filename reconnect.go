package main

import (
	"context"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const reconnectInitial = 5 * time.Second
const reconnectMaximum = 5 * time.Minute
const reconnectStable = time.Minute

// Positive jitter never makes retries earlier than the exponential schedule.
type reconnectBackoff struct{ delay time.Duration }

func (b *reconnectBackoff) next() time.Duration {
	if b.delay == 0 {
		b.delay = reconnectInitial
	} else {
		b.delay = min(reconnectMaximum, b.delay*2)
	}
	return b.delay + time.Duration(rand.Int64N(int64(b.delay/5)+1))
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// RFC 9110 allows seconds or HTTP dates. Bound untrusted delays to 24 hours.
func retryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds > 0 {
			return time.Duration(min(seconds, 86400)) * time.Second
		}
		return 0
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return min(date.Sub(now), 24*time.Hour)
	}
	return 0
}

// One gate per relay origin and process, shared by all profiles, SSH pool slots,
// HTTP publications and enrollment. A failed wave admits one recovery probe,
// rather than letting every waiting connection independently retry the server.
type relayRetryGate struct {
	mu           sync.Mutex
	changed      chan struct{}
	active       int
	epoch        uint64
	open         bool
	next         time.Time
	healthySince time.Time
	backoff      reconnectBackoff
}

var relayRetryGates sync.Map

func retryGate(endpoint string) *relayRetryGate {
	u, _ := url.Parse(endpoint)
	scheme := u.Scheme
	if scheme == "ws" {
		scheme = "http"
	}
	if scheme == "wss" {
		scheme = "https"
	}
	key := scheme + "://" + strings.ToLower(u.Host)
	g, _ := relayRetryGates.LoadOrStore(key, &relayRetryGate{changed: make(chan struct{})})
	return g.(*relayRetryGate)
}

func (g *relayRetryGate) acquire(ctx context.Context) (uint64, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		g.mu.Lock()
		delay := time.Until(g.next)
		if (!g.open && g.active < 8) || (g.open && g.active == 0 && delay <= 0) {
			g.active++
			epoch := g.epoch
			g.mu.Unlock()
			return epoch, nil
		}
		changed := g.changed
		g.mu.Unlock()
		if delay <= 0 {
			delay = time.Hour
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// transportOK includes ordinary HTTP refusals: they prove the server is up.
// Authorization errors are handled by the caller, never by bypassing policy.
func (g *relayRetryGate) finish(epoch uint64, transportOK, unavailable bool, after time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	now := time.Now()
	if epoch == g.epoch {
		if unavailable {
			if !g.healthySince.IsZero() && now.Sub(g.healthySince) >= reconnectStable {
				g.backoff = reconnectBackoff{}
			}
			g.epoch++
			g.open = true
			g.healthySince = time.Time{}
			g.next = now.Add(max(g.backoff.next(), after))
		} else if transportOK {
			g.open = false
			g.next = time.Time{}
			if g.healthySince.IsZero() {
				g.healthySince = now
			}
			if now.Sub(g.healthySince) >= reconnectStable {
				g.backoff = reconnectBackoff{}
			}
		}
	} else if unavailable && now.Add(after).After(g.next) {
		// An already in-flight response may request a longer server cooldown.
		g.next = now.Add(after)
	}
	close(g.changed)
	g.changed = make(chan struct{})
}
