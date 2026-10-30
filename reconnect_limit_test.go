package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestReconnectLimitExactBoundaryAndStableRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{}
		if err := b.failure(); err != nil {
			t.Fatal(err)
		}
		first := b.state.FirstFailure
		for i := 0; i < 119; i++ {
			stop := b.online()
			time.Sleep(30 * time.Second)
			stop() // Flapping must not reset the outage.
			time.Sleep(30 * time.Second)
			if err := b.failure(); err != nil {
				t.Fatal(err)
			}
		}
		if b.state.FirstFailure != first {
			t.Fatal("flaps reset first failure")
		}
		time.Sleep(59 * time.Second)
		_, cancel, err := b.attempt(context.Background())
		cancel()
		if err != nil {
			t.Fatalf("stopped before two hours: %v", err)
		}
		time.Sleep(time.Second)
		if _, _, err = b.attempt(context.Background()); !errors.Is(err, errReconnectStopped) {
			t.Fatalf("two-hour boundary: %v", err)
		}
		time.Sleep(24 * time.Hour)
		if _, _, err = b.attempt(context.Background()); !errors.Is(err, errReconnectStopped) {
			t.Fatal("automatically resumed")
		}
		if err = b.manualReset(); err != nil {
			t.Fatal(err)
		}
		if err = b.failure(); err != nil {
			t.Fatal(err)
		}
		stop := b.online()
		time.Sleep(reconnectStable)
		synctest.Wait()
		stop()
		if !b.state.FirstFailure.IsZero() {
			t.Fatal("stable acknowledged connection did not reset outage")
		}
	})
}

func TestReconnectLimitPreventsRequestsAndPersistsUntilManualStart(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	base := t.TempDir()
	dir := filepath.Join(base, "public-connect")
	if err := initialize("limit-fixture", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := budgetFor(c, "ssh")
	b.state.FirstFailure = time.Now().Add(-reconnectLimit)
	b.saveLocked()
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := openRelay(context.Background(), c, server.URL+"/v3/session")
			if !errors.Is(err, errReconnectStopped) {
				t.Errorf("got %v", err)
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 0 {
		t.Fatal("expired retry budget sent requests")
	}
	if err = registerProviderUntilAvailable(context.Background(), c); !errors.Is(err, errReconnectStopped) {
		t.Fatalf("enrollment ignored stop: %v", err)
	}
	// Simulate restarting the process, retaining only the private state file.
	reconnectBudgets.Delete(c.path + "\x00ssh")
	b = budgetFor(c, "ssh")
	if _, _, err = b.attempt(context.Background()); !errors.Is(err, errReconnectStopped) {
		t.Fatal("restart lost stopped state")
	}
	g := newGUI(base, "must-not-run")
	if err = g.savePlan(guiRequest{Role: "connect", Listen: "127.0.0.1:22499"}, true); err != nil {
		t.Fatal(err)
	}
	if err = g.ensureConnection(guiRequest{}); !errors.Is(err, errReconnectStopped) {
		t.Fatalf("auto resume bypassed stop: %v", err)
	}
	before, _ := os.ReadFile(c.path)
	if err = g.resetReconnectLimit(guiRequest{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = openRelay(ctx, c, server.URL+"/v3/session")
	if err == nil || calls.Load() != 1 {
		t.Fatalf("manual reset did not allow exactly one request: %d %v", calls.Load(), err)
	}
	after, _ := os.ReadFile(c.path)
	if string(before) != string(after) {
		t.Fatal("manual reset changed identity")
	}
	if p := describeConnectionError(errReconnectStopped); p.Retryable || p.Code != "RECONNECT_STOPPED" {
		t.Fatalf("bad stopped status: %+v", p)
	}
}

func TestReconnectLimitHTTPStopsAtDeadlineInsideLongCooldown(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(503)
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("http-limit-fixture", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if _, err := saveHTTPPublication(config, "example", "127.0.0.1:8000", true); err != nil {
		t.Fatal(err)
	}
	c, err := load(config)
	if err != nil {
		t.Fatal(err)
	}
	b := budgetFor(c, "http")
	b.state.FirstFailure = time.Now().Add(-reconnectLimit + 300*time.Millisecond)
	b.saveLocked()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if err = runHTTPPublications(ctx, config); !errors.Is(err, errReconnectStopped) {
		t.Fatalf("publisher did not stop: %v", err)
	}
	if time.Since(started) > time.Second || calls.Load() != 1 {
		t.Fatalf("deadline/requests: %s %d", time.Since(started), calls.Load())
	}
	if err = runHTTPPublications(ctx, config); !errors.Is(err, errReconnectStopped) || calls.Load() != 1 {
		t.Fatal("publisher restarted itself")
	}
	if _, cancel, err := budgetFor(c, "ssh").attempt(ctx); err != nil {
		t.Fatal("HTTP outage stopped independent SSH channel")
	} else {
		cancel()
	}
	if err = b.manualReset(); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectLimitCancellationAndStateReadFailure(t *testing.T) {
	b := &reconnectBudget{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = b.result(context.Canceled, ctx)
	if !b.state.FirstFailure.IsZero() {
		t.Fatal("manual cancellation started outage clock")
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_ = b.result(context.DeadlineExceeded, deadline)
	if b.state.FirstFailure.IsZero() {
		t.Fatal("connection timeout did not start outage clock")
	}
	if err := b.wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	b.loadErr = os.ErrPermission
	if _, _, err := b.attempt(context.Background()); !errors.Is(err, errReconnectState) {
		t.Fatal("unreadable state allowed network")
	}
}

// A busy v2 provider replaces each waiting slot with a short session while
// opening the next slot. Their overlapping lifetimes are continuous uptime.
func TestReconnectLimitShortSessionHandoffsClearOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{}
		_ = b.failure()
		stop := b.online()
		for i := 0; i < 1500; i++ { // 125 minutes, beyond the original outage deadline.
			time.Sleep(5 * time.Second)
			next := b.online()
			stop()
			stop = next
			_, cancel, err := b.attempt(context.Background())
			cancel()
			if err != nil {
				t.Fatalf("healthy short sessions stopped at handoff %d: %v", i, err)
			}
		}
		synctest.Wait()
		stop()
		if !b.state.FirstFailure.IsZero() {
			t.Fatal("continuous acknowledged uptime across short sessions did not clear outage")
		}
	})
}

func TestReconnectLimitHealthyChannelRecoversAfterConcurrentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{}
		stop := b.online()
		defer stop()
		time.Sleep(10 * time.Second)
		_ = b.failure()
		time.Sleep(59 * time.Second)
		synctest.Wait()
		b.mu.Lock()
		cleared := b.state.FirstFailure.IsZero()
		b.mu.Unlock()
		if cleared {
			t.Fatal("failure cleared without a full healthy minute")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if !b.state.FirstFailure.IsZero() {
			t.Fatal("a live acknowledged channel never recovered after a concurrent failure")
		}
	})
}

func TestReconnectLimitLiveChannelCannotUndoStoppedState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{}
		_ = b.failure()
		time.Sleep(reconnectLimit - 30*time.Second)
		stop := b.online()
		defer stop()
		time.Sleep(30 * time.Second)
		if _, _, err := b.attempt(context.Background()); !errors.Is(err, errReconnectStopped) {
			t.Fatal(err)
		}
		time.Sleep(reconnectStable)
		synctest.Wait()
		if !b.state.Stopped {
			t.Fatal("health timer resumed stopped connection")
		}
	})
}
