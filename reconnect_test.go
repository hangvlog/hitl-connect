package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHTTPPublication503DoesNotPollEverySecond(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("retry-fixture", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if _, err := saveHTTPPublication(config, "example", "127.0.0.1:8000", true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3200*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := runHTTPPublications(ctx, config); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("503 outage: %d requests in 3.2s, want one initial attempt", n)
	}
	if time.Since(started) > 4*time.Second {
		t.Fatal("stop did not cancel retry wait promptly")
	}
}

func TestReconnectScheduleAndRetryAfter(t *testing.T) {
	b := reconnectBackoff{}
	for i, seconds := range []int{5, 10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120, 10240, 14400, 14400, 14400, 14400, 14400, 14400, 28800, 28800, 28800, 57600, 57600, 57600, 86400, 86400} {
		d := b.next()
		base := time.Duration(seconds) * time.Second
		if d < base-base/5 || d > base {
			t.Fatalf("attempt %d: %s", i+1, d)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"120", 120 * time.Second}, {now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{"garbage", 0}, {"-5", 0}, {"9223372036854775807", 24 * time.Hour},
	} {
		if got := retryAfter(tc.value, now); got != tc.want {
			t.Fatalf("Retry-After %q: %s", tc.value, got)
		}
	}
}

func TestRelayOutageSharesCooldownAcrossHTTPSSHAndEnrollment(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(503)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			if i%3 == 0 {
				_ = enrollmentRequestContext(ctx, server.URL+"/enroll/provider", map[string]string{}, &struct{}{})
			} else {
				ws, _ := openRelay(ctx, &Config{}, server.URL+[]string{"/http-v1/session", "/v3/session"}[i%2])
				if ws != nil {
					ws.CloseNow()
				}
			}
		}(i)
	}
	workers.Wait()
	if n := calls.Load(); n < 1 || n > 8 {
		t.Fatalf("64 concurrent attempts made %d requests, want <=8 initial requests", n)
	}
	gate := retryGate(server.URL)
	gate.mu.Lock()
	remaining := time.Until(gate.next)
	gate.next = time.Now() // Advance the cooldown without waiting two minutes.
	gate.mu.Unlock()
	if remaining < 118*time.Second {
		t.Fatalf("ignored Retry-After: %s", remaining)
	}
	before := calls.Load()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _, _ = openRelay(ctx2, &Config{}, server.URL+"/http-v1/session") }()
	}
	workers.Wait()
	if n := calls.Load() - before; n != 1 {
		t.Fatalf("recovery wave made %d requests, want one probe", n)
	}
}

func TestRelayCooldownRecoveryAndCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, _, _ = ws.Read(r.Context())
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := openRelay(ctx, &Config{}, server.URL)
	if err == nil {
		t.Fatal("503 accepted")
	}
	short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err = openRelay(short, &Config{}, server.URL); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	started := time.Now()
	ws, err := openRelay(ctx, &Config{}, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ws.CloseNow()
	if calls.Load() != 2 || time.Since(started) < 3900*time.Millisecond {
		t.Fatalf("cooldown bypassed: calls=%d elapsed=%s", calls.Load(), time.Since(started))
	}
}

func TestHTTPPublicationRecoversAfter503(t *testing.T) {
	var calls atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	published := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		if _, _, err = ws.Read(r.Context()); err != nil {
			return
		}
		if err = ws.Write(r.Context(), websocket.MessageText, []byte(`{"state":"published"}`)); err != nil {
			return
		}
		close(published)
		_, _, _ = ws.Read(r.Context())
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("recovery-fixture", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if _, err := saveHTTPPublication(config, "example", "127.0.0.1:8000", true); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runHTTPPublications(ctx, config) }()
	select {
	case <-published:
	case <-ctx.Done():
		t.Fatal("publication did not recover")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop blocked")
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected requests: %d", calls.Load())
	}
}
