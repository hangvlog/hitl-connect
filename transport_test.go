package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coder/websocket"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Run a real SSH command over the provider's TLS/framing path. The command
// succeeds before the caller closes its short-lived encrypted session.
func TestProviderShortSSHSessionDoesNotStartOutage(t *testing.T) {
	key, host := loginSigner(t), loginSigner(t)
	address, _, _ := loginFixture(t, key.PublicKey(), "fixture\\tester\r\n", 0, host)
	dir := t.TempDir()
	if err := initialize("session-fixture", dir, "https://relay.example.invalid"); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var identity Identity
	if err = readJSON(filepath.Join(dir, "identity.json"), &identity); err != nil {
		t.Fatal(err)
	}
	// A generic loopback service uses the same system-SSH forwarding path,
	// with fixture mutual TLS trust, without installing OS accounts/services.
	service := Service{Target: address, Allow: []string{identity.ID}}
	c.Peers[identity.ID] = Peer{Certificate: identity.Certificate, Services: []string{"fixture"}}
	c.Services["fixture"] = service
	paired := Paired{State: "paired", Peer: identity.ID, Service: "fixture"}
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		ws, e := websocket.Accept(w, r, nil)
		if e != nil {
			return
		}
		acceptSession(r.Context(), c, ws, paired, service)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	encrypted, err := secure(ctx, c, ws, paired, false)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()
	conn, channels, requests, err := ssh.NewClientConn(&sshFrameConn{Conn: encrypted}, address, &ssh.ClientConfig{
		User: "tester", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("whoami")
	if err != nil || string(output) != "fixture\\tester\r\n" {
		t.Fatalf("SSH command: %q %v", output, err)
	}
	session.Close()
	client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("provider session did not finish")
	}
	b := budgetFor(c, "ssh")
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.state.FirstFailure.IsZero() {
		t.Fatal("successful short SSH command started provider outage clock")
	}
}

func TestSecureFailureClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"timeout", context.DeadlineExceeded, true},
		{"eof", io.EOF, true},
		{"restart", websocket.CloseError{Code: websocket.StatusServiceRestart, Reason: "private-peer-text"}, true},
		{"policy", websocket.CloseError{Code: websocket.StatusPolicyViolation, Reason: "private-peer-text"}, false},
		{"certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, false},
		{"pin", errors.New("peer certificate pin mismatch: private-peer-text"), false},
		{"cancel", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := secureError("TLS handshake", tc.err)
			if !errors.Is(err, tc.err) {
				t.Fatal("lost cause")
			}
			p := describeConnectionError(fmt.Errorf("SSH_ACCESS_UNAVAILABLE: %w", err))
			if p.Retryable != tc.retry || strings.Contains(p.Message, "private-peer-text") {
				t.Fatalf("unsafe classification: %+v", p)
			}
		})
	}
}

// An interrupted TLS exchange is not a rejected device identity. Exercise the
// actual WebSocket/TLS path so a generic replacement error cannot hide it.
func TestInterruptedTLSHandshakeCanRecover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		_, _, _ = ws.Read(r.Context()) // Receive the TLS ClientHello, then disconnect.
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("handshake-test", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var identity Identity
	if err = readJSON(filepath.Join(dir, "identity.json"), &identity); err != nil {
		t.Fatal(err)
	}
	c.Peers[identity.ID] = Peer{Certificate: identity.Certificate, Services: []string{"ssh"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, err = secure(ctx, c, ws, Paired{Peer: identity.ID, Service: "ssh"}, false)
	if err == nil {
		t.Fatal("interrupted TLS succeeded")
	}
	p := describeConnectionError(fmt.Errorf("SSH_ACCESS_UNAVAILABLE: %w", err))
	if !p.Retryable || p.Side != "network" {
		t.Fatalf("transient handshake stopped recovery: %+v", p)
	}
}

func TestDialPairingRecovery(t *testing.T) {
	for _, reason := range []string{"TARGET_OFFLINE", "TARGET_BUSY", "DATA_CHANNEL_UNAVAILABLE", "TARGET_DENIED", "private-peer-text", "HTTP_503", "HTTP_403", "CANCEL", "DIAL_TIMEOUT", "ALWAYS_OFFLINE"} {
		t.Run(reason, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if reason == "DIAL_TIMEOUT" && calls.Add(1) == 1 {
					<-r.Context().Done()
					return
				}
				if strings.HasPrefix(reason, "HTTP_") && calls.Add(1) == 1 {
					status := 503
					if reason == "HTTP_403" {
						status = 403
					}
					w.WriteHeader(status)
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
				if reason == "ALWAYS_OFFLINE" {
					calls.Add(1)
					_ = ws.Close(websocket.StatusPolicyViolation, "TARGET_OFFLINE")
					return
				}
				if !strings.HasPrefix(reason, "HTTP_") && reason != "DIAL_TIMEOUT" && calls.Add(1) == 1 {
					if reason == "TARGET_OFFLINE" {
						time.Sleep(5 * time.Second)
					}
					_ = ws.Close(websocket.StatusPolicyViolation, reason)
					return
				}
				_ = ws.Write(r.Context(), websocket.MessageText, []byte(`{"state":"paired","peer":"provider","service":"ssh","sessionId":"fixture"}`))
				_, _, _ = ws.Read(r.Context())
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if reason == "CANCEL" {
				cancel()
			}
			ws, _, err := connect(ctx, &Config{Relay: server.URL}, Hello{Role: "dial", Target: "provider", Service: "ssh"})
			if ws != nil {
				ws.CloseNow()
			}
			retry := reason == "TARGET_OFFLINE" || reason == "TARGET_BUSY" || reason == "DATA_CHANNEL_UNAVAILABLE" || reason == "HTTP_503" || reason == "DIAL_TIMEOUT"
			if reason == "HTTP_403" {
				var failure *relayFailure
				if !errors.As(err, &failure) || failure.stage != "websocket" {
					t.Fatal("HTTP rejection mislabeled as TCP failure", err)
				}
			}
			if retry {
				if err != nil || calls.Load() != 2 {
					t.Fatalf("temporary pairing failure was not recovered: attempts=%d error=%v", calls.Load(), err)
				}
			} else if reason == "ALWAYS_OFFLINE" {
				if err == nil || calls.Load() != 3 {
					t.Fatalf("retry limit: calls=%d error=%v", calls.Load(), err)
				}
			} else if err == nil || (reason != "CANCEL" && calls.Load() != 1) || describeConnectionError(err).Retryable || strings.Contains(err.Error(), "private-peer-text") {
				t.Fatalf("policy rejection retried or leaked: attempts=%d error=%v", calls.Load(), err)
			}
		})
	}
}

func TestTransportLogIsolationAndRedaction(t *testing.T) {
	received := make(chan transportLogRecord, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var record transportLogRecord
		_ = json.NewDecoder(r.Body).Decode(&record)
		select {
		case received <- record:
		default:
		}
		w.WriteHeader(500)
	}))
	defer server.Close()
	sink := &transportLogSink{queue: make(chan transportLogJob, 2)}
	record := transportRecord("test-trace", "dial", 1, time.Second, false, errors.New("secret password token private body"))
	sink.submit(server.URL+"/api/front/client-log/report", record)
	select {
	case got := <-received:
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "secret") || got.SessionID != "test-trace" || got.Source != "hitl-connect" || len(got.AppVersion) > 32 {
			t.Fatal(string(b))
		}
	case <-time.After(time.Second):
		t.Fatal("no log record")
	}
	time.Sleep(25 * time.Millisecond)
	if len(received) != 0 {
		t.Fatal("logger recursively retried failure")
	}
	close(sink.queue)
	// A stalled consumer cannot block the caller, even when the queue is full.
	blocked := &transportLogSink{queue: make(chan transportLogJob, 1)}
	blocked.once.Do(func() {})
	start := time.Now()
	for i := 0; i < 100; i++ {
		blocked.submit(server.URL+"/api/front/client-log/report", record)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("logging blocked tunnel")
	}
}

func TestProviderDrainDefersWithoutClosingActiveSession(t *testing.T) {
	r := newProviderRuntime()
	if !r.begin() {
		t.Fatal("admission")
	}
	idle, cancel := context.WithCancel(context.Background())
	r.idleCancel = cancel
	ctx, done := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer done()
	if err := r.drain(ctx); err == nil {
		t.Fatal("active update was allowed")
	}
	if idle.Err() == nil || r.isDraining() {
		t.Fatal("idle pool or deferred admission incorrect")
	}
	if r.active != 1 {
		t.Fatal("active session was terminated")
	}
	r.end()
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.begin() {
		t.Fatal("new session admitted during update")
	}
}
func TestEstablishmentDeadlineDoesNotExtendBetweenStages(t *testing.T) {
	deadline := time.Now().Add(20 * time.Millisecond)
	paired := Paired{deadline: deadline}
	if got := stageDeadline(paired, 7*time.Second); !got.Equal(deadline) {
		t.Fatal("stage extended total deadline")
	}
}

func TestSessionCloseDiagnostics(t *testing.T) {
	if runtime.GOOS == "windows" && lifecycleCode(streamError("local", "read", syscall.Errno(10054))) != "CONNECTION_RESET" {
		t.Fatal("Winsock reset was not classified")
	}
	for _, tc := range []struct {
		err  error
		code string
	}{
		{io.ErrUnexpectedEOF, "TRANSPORT_TRUNCATED"},
		{streamError("local", "read", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), "CONNECTION_RESET"},
		{fmt.Errorf("read: %w", websocket.CloseError{Code: websocket.StatusGoingAway, Reason: "private-peer-text"}), "WEBSOCKET_CLOSED"},
	} {
		if got := lifecycleCode(tc.err); got != tc.code {
			t.Fatalf("got %s want %s", got, tc.code)
		}
	}
	err := streamError("peer", "read", io.ErrUnexpectedEOF)
	if !errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "private-peer-text") {
		t.Fatal("lost cause or unsafe text")
	}
}

func TestForwardWaitsForCapacityWithoutDroppingExistingConnections(t *testing.T) {
	entered := make(chan struct{}, 16)
	release := make(chan struct{}, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		if _, _, err = ws.Read(r.Context()); err != nil {
			return
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = ws.Close(websocket.StatusPolicyViolation, "TARGET_DENIED")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	c := &Config{Relay: server.URL, Capacity: capacitySettings{CallerConnections: 8}, Peers: map[string]Peer{"provider": {Services: []string{"ssh"}}}}
	done := make(chan error, 1)
	go func() { done <- forward(ctx, c, "provider", "ssh", address) }()
	defer func() { cancel(); <-done }()
	var first net.Conn
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		first, err = net.Dial("tcp", address)
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	connections := []net.Conn{first}
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for i := 1; i < 9; i++ {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("first eight not admitted")
		}
	}
	queued := connections[8]
	queued.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, err = queued.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("ninth connection dropped instead of waiting: %v", err)
	}
	queued.SetReadDeadline(time.Time{})
	release <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("queued connection did not enter after capacity freed")
	}
}

func TestCallerReadinessClearsStaleTransportFailureWithoutInventingLogin(t *testing.T) {
	g := newGUI(t.TempDir(), "unused")
	g.state.Running, g.state.Role = true, "connect"
	g.processLine("end-to-end TLS handshake failed: transport timed out", g.generation)
	g.processLine("tunnel-ready", g.generation)
	state := agentStateResult("status", g.state)
	if !state.OK || state.LoginVerified {
		t.Fatalf("stale failure or fabricated login: %+v", state)
	}
	for _, step := range g.state.Steps {
		if (step.ID == "relay" || step.ID == "tunnel") && step.Status != "passed" {
			t.Fatal(step)
		}
	}
	g.state.Problem = describeConnectionError(errors.New("provider identity changed"))
	g.processLine("tunnel-ready", g.generation)
	if g.state.Problem == nil {
		t.Fatal("readiness erased identity rejection")
	}
	g.processLine("end-to-end TLS handshake failed: transport timed out", g.generation)
	g.processLine("tunnel-ready", g.generation+1)
	if agentStateResult("status", g.state).OK {
		t.Fatal("stale process changed state")
	}
}

func TestForwardAdmissionIsBoundedAndCancelable(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		slots := make(chan struct{}, 1)
		slots <- struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		if canceled {
			cancel()
		}
		err := waitForwardSlot(ctx, slots)
		cancel()
		want := errLocalCapacity
		if canceled {
			want = context.Canceled
		}
		if !errors.Is(err, want) || len(slots) != 1 {
			t.Fatalf("admission changed active connections: %v", err)
		}
	}
}
