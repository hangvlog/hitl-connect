package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestReconnectLimitContinuesBeyondTwoHoursAndPersists(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{}
		_ = b.failure()
		for i := 0; i < 30; i++ {
			started := time.Now()
			if err := b.wait(context.Background(), time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(started)
			if elapsed > 24*time.Hour || elapsed <= 0 {
				t.Fatalf("invalid wait %s", elapsed)
			}
			if err := b.failure(); err != nil {
				t.Fatal(err)
			}
		}
		if b.state.Stopped || b.state.Delay != 24*time.Hour {
			t.Fatal("long outage did not settle at daily retries")
		}
		stop := b.online()
		time.Sleep(reconnectStable)
		synctest.Wait()
		stop()
		if !b.state.FirstFailure.IsZero() || b.state.Delay != 0 {
			t.Fatal("stable recovery did not clear backoff")
		}
	})
}

func TestReconnectLimitCooldownPersistsAndManualStartWakes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "reconnect-ssh.json")
		c := &Config{path: filepath.Join(filepath.Dir(file), "config.json")}
		state := reconnectState{FirstFailure: time.Now().Add(-48 * time.Hour), Delay: 4 * time.Hour, TierAttempts: 3, NextAttempt: time.Now().Add(4 * time.Hour)}
		if err := privateJSON(file, state); err != nil {
			t.Fatal(err)
		}
		b := budgetFor(c, "ssh")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, _, err := b.attempt(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("restart lost cooldown", err)
		}
		done := make(chan error, 1)
		go func() { _, _, err := b.attempt(context.Background()); done <- err }()
		synctest.Wait()
		if err := b.manualReset(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var saved reconnectState
		if err := readJSON(file, &saved); err != nil || saved.Delay != 0 || !saved.NextAttempt.IsZero() {
			t.Fatal("manual start did not persist reset", err)
		}
	})
}

func TestReconnectLimitHTTPKeepsCooldownAndIndependentSSH(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(503)
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("http-retry-fixture", dir, server.URL); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = runHTTPPublications(ctx, config)
	b := budgetFor(c, "http")
	if calls.Load() != 1 || time.Until(b.state.NextAttempt) < 23*time.Hour || b.state.Stopped {
		t.Fatal("HTTP retry schedule lost", calls.Load(), b.state)
	}
	if _, _, err := budgetFor(c, "ssh").attempt(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectLimitLegacyStopMigrationPreservesManualPlan(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "public-host")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := &Config{path: filepath.Join(dir, "config.json")}
	file := filepath.Join(dir, "reconnect-ssh.json")
	if err := privateJSON(file, reconnectState{FirstFailure: time.Now().Add(-72 * time.Hour), Stopped: true}); err != nil {
		t.Fatal(err)
	}
	if err := privateJSON(filepath.Join(base, "connection-plan.json"), connectionPlan{Version: 1, Role: "host", Resume: false}); err != nil {
		t.Fatal(err)
	}
	b := budgetFor(c, "ssh")
	if b.state.Stopped {
		t.Fatal("legacy timeout remained permanent")
	}
	p, err := readConnectionPlan(base)
	if err != nil || p.Resume {
		t.Fatal("manual stop plan changed", err)
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

func TestReconnectLimitFlapsKeepLongTierAndExternalStartWakes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &reconnectBudget{file: filepath.Join(t.TempDir(), "reconnect-ssh.json")}
		b.state = reconnectState{FirstFailure: time.Now(), Delay: 4 * time.Hour, TierAttempts: 3, NextAttempt: time.Now().Add(4 * time.Hour)}
		b.saveLocked()
		for i := 0; i < 5; i++ {
			stop := b.online()
			time.Sleep(30 * time.Second)
			stop()
			_ = b.failure()
		}
		if b.state.Delay != 4*time.Hour || b.state.FirstFailure.IsZero() {
			t.Fatal("flapping cleared long tier")
		}
		done := make(chan error, 1)
		go func() { _, _, err := b.attempt(context.Background()); done <- err }()
		synctest.Wait()
		// Simulate GUI Start in another process, without sharing Go memory.
		if err := privateJSON(b.file, reconnectState{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("external Start did not wake worker")
		}
	})
}
