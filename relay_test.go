package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRelayEndpoints(t *testing.T) {
	for _, tc := range []struct{ base, socket, enroll string }{
		{"https://gateway.example.invalid/hitl/device-tunnel", "wss://gateway.example.invalid/hitl/local-http-relay/connect/hitl-connect/v2/session", "https://gateway.example.invalid/hitl/device-tunnel/enroll"},
		{"wss://gateway.example.invalid/hitl/device-tunnel/", "wss://gateway.example.invalid/hitl/local-http-relay/connect/hitl-connect/v2/session", "https://gateway.example.invalid/hitl/device-tunnel/enroll"},
		{"https://relay.example.invalid/api/device-tunnel", "wss://relay.example.invalid/api/device-tunnel/connect/v2/session", "https://relay.example.invalid/api/device-tunnel/enroll"},
		{"https://custom.example/relay", "wss://custom.example/relay/connect/v2/session", "https://custom.example/relay/enroll"},
		{"http://127.0.0.1:8083/", "ws://127.0.0.1:8083/connect/v2/session", "http://127.0.0.1:8083/enroll"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			ws, err := relayURL(&Config{Relay: tc.base})
			if err != nil || ws != tc.socket {
				t.Fatalf("socket = %q, %v", ws, err)
			}
			enroll, err := enrollmentURL(tc.base)
			if err != nil || enroll != tc.enroll {
				t.Fatalf("enroll = %q, %v", enroll, err)
			}
		})
	}
}

func TestRelayRejectsUnsafeAddresses(t *testing.T) {
	for _, base := range []string{"http://gateway.example.invalid/hitl/device-tunnel", "https://user:password@example.com", "https://example.com?token=secret", "https://example.com/#fragment"} {
		if _, err := relayURL(&Config{Relay: base}); err == nil {
			t.Errorf("socket accepted %q", base)
		}
		if _, err := enrollmentURL(base); err == nil {
			t.Errorf("enrollment accepted %q", base)
		}
	}
}

func TestProviderRelayIsExplicitAndPrivate(t *testing.T) {
	base := t.TempDir()
	profile := filepath.Join(base, "public-host")
	if err := prepareProviderRelay(base, ""); err == nil {
		t.Fatal("missing relay accepted")
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatal("missing configuration created an identity directory")
	}
	for _, relay := range []string{"http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid?token=secret"} {
		if err := prepareProviderRelay(base, relay); err == nil {
			t.Fatal("unsafe relay accepted")
		}
	}
	const relay = "https://relay.example.invalid"
	if err := prepareProviderRelay(base, relay); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(profile, "identity.key")); !os.IsNotExist(err) {
		t.Fatal("settings implicitly created identity")
	}
	if err := prepareProviderRelay(base, ""); err != nil {
		t.Fatal("saved setting was not reusable", err)
	}
	if err := pairingCommand("share", "", profile, "", "ssh", "127.0.0.1:22", ""); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(profile, "config.json"))
	if err != nil || c.Relay != relay || c.Logging != nil {
		t.Fatal("local settings or telemetry default incorrect", err)
	}
	before, _ := os.ReadFile(filepath.Join(profile, "identity.key"))
	if err := prepareProviderRelay(base, "https://other.example.invalid"); err == nil {
		t.Fatal("existing relay silently replaced")
	}
	after, _ := os.ReadFile(filepath.Join(profile, "identity.key"))
	if string(before) != string(after) {
		t.Fatal("identity changed")
	}
	if err := os.WriteFile(filepath.Join(profile, "config.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareProviderRelay(base, relay); err == nil {
		t.Fatal("corrupt profile was silently replaced")
	}
}

func TestProviderStartupWaitsForServiceButNotRevocation(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "temporary outage", true: "revoked"}[revoked], func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if revoked {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"code":"TUNNEL_DEVICE_REVOKED"}`))
					return
				}
				if calls == 1 {
					w.WriteHeader(502)
					_, _ = w.Write([]byte("private gateway diagnostics must not be printed"))
					return
				}
				var body struct {
					Registration struct {
						ID string `json:"id"`
					} `json:"registration"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id": body.Registration.ID})
			}))
			defer server.Close()
			dir := t.TempDir()
			if err := initialize("startup-test", dir, server.URL); err != nil {
				t.Fatal(err)
			}
			c, err := load(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = registerProviderUntilAvailable(ctx, c)
			if revoked {
				if err == nil || !strings.Contains(err.Error(), "revoked") || calls != 1 {
					t.Fatalf("revocation: calls=%d err=%v", calls, err)
				}
			} else if err != nil || calls != 2 {
				t.Fatalf("outage recovery: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestEnrollmentErrorDoesNotPrintUntrustedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"code":"secret injected diagnostic"}`))
	}))
	defer server.Close()
	err := enrollmentRequest(server.URL, struct{}{}, &struct{}{})
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatal(err)
	}
}

func TestSSHAccessRequiresLocalDecisionAndKeepsRejection(t *testing.T) {
	base := t.TempDir()
	profile := filepath.Join(base, "public-host")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ssh.NewPublicKey(pub)
	public := string(ssh.MarshalAuthorizedKey(key))
	for _, invalid := range []string{"private key", public + public, "command=\"whoami\" " + public} {
		if _, err = receiveSSHAccess(profile, "caller", "device-key", invalid); err == nil {
			t.Fatal("invalid public key accepted")
		}
	}
	a, err := receiveSSHAccess(profile, "caller", "device-key", public)
	if err != nil || a.Status != "pending" || a.User != "" {
		t.Fatalf("initial request: %+v %v", a, err)
	}
	b, err := receiveSSHAccess(profile, "caller", "device-key", public)
	if err != nil || a.ID != b.ID {
		t.Fatal("retry must preserve request identity")
	}
	changedDevice, _ := receiveSSHAccess(profile, "caller", "other-device-key", public)
	if changedDevice.ID == a.ID {
		t.Fatal("approval must bind the authenticated device key")
	}
	if r := decideSSHAccess(context.Background(), base, a.ID, "unused", "SHA256:wrong", true); r.Code != "PUBLIC_KEY_MISMATCH" {
		t.Fatal(r)
	}
	if r := decideSSHAccess(context.Background(), base, a.ID, "", "", true); r.Code != "LOCAL_USER_REQUIRED" {
		t.Fatal(r)
	}
	if r := decideSSHAccess(context.Background(), base, a.ID, "", "", false); !r.OK {
		t.Fatal(r)
	}
	b, _ = receiveSSHAccess(profile, "caller", "device-key", public)
	if b.Status != "rejected" {
		t.Fatal("remote retry reopened a locally rejected request")
	}
	if r := decideSSHAccess(context.Background(), base, a.ID, "unused", "", true); r.Code != "ACCESS_REQUEST_CLOSED" {
		t.Fatal(r)
	}
	changedDevice.CreatedAt = time.Now().Add(-11 * time.Minute).Unix()
	file, _ := accessPath(profile, changedDevice.ID)
	if err = privateJSON(file, changedDevice); err != nil {
		t.Fatal(err)
	}
	if r := decideSSHAccess(context.Background(), base, changedDevice.ID, "unused", "", true); r.Code != "ACCESS_REQUEST_CLOSED" {
		t.Fatal(r)
	}
	for _, view := range listSSHAccess(profile) {
		if view.PublicKey != "" || view.HostKey != "" {
			t.Fatal("status leaked full key data")
		}
	}
}

func TestSSHGrantAllowsMultipleDevicesAndFailureIsVisible(t *testing.T) {
	dir := t.TempDir()
	if err := initialize("grant-test", dir, "http://127.0.0.1:9000"); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	old, err := readConnectionKey(filepath.Join(dir, "connection-key-ssh.txt"))
	if err != nil || old.SSHGrant != "" {
		t.Fatal("legacy code gained SSH authority")
	}
	// Deliberately invalid local account: unit tests never write to the test
	// runner's real authorized_keys. Real success is checked in the Podman flow.
	c.sshAccount = "nonexistent-account-for-grant-test"
	if err = issueSSHGrant(c, "nonexistent-account-for-grant-test"); err != nil {
		t.Fatal(err)
	}
	key, err := readConnectionKey(filepath.Join(dir, "connection-key-ssh.txt"))
	if err != nil || !validGrantToken(key.SSHGrant) {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshKey, _ := ssh.NewPublicKey(pub)
	a, err := receiveSSHAccess(dir, "first", "device-one", string(ssh.MarshalAuthorizedKey(sshKey)))
	if err != nil {
		t.Fatal(err)
	}
	bad, err := redeemSSHGrant(c, a, strings.Repeat("x", 43))
	if err != nil || bad.Status != "denied" {
		t.Fatalf("bad code accepted %+v %v", bad, err)
	}
	var grant sshGrant
	grantFile := filepath.Join(dir, "ssh-grant.json")
	if err = readJSON(grantFile, &grant); err != nil {
		t.Fatal(err)
	}
	grant.User = "different-account"
	grant.Expires = time.Now().Add(time.Minute).Unix()
	if err = privateJSON(grantFile, grant); err != nil {
		t.Fatal(err)
	}
	bad, err = redeemSSHGrant(c, a, key.SSHGrant)
	if err != nil || bad.Code != "LOCAL_ACCOUNT_NOT_AUTHORIZED" {
		t.Fatal("mutable profile changed fixed local account", bad, err)
	}
	grant.User = c.sshAccount
	grant.Expires = time.Now().Add(time.Minute).Unix()
	if err = privateJSON(grantFile, grant); err != nil {
		t.Fatal(err)
	}
	first, err := redeemSSHGrant(c, a, key.SSHGrant)
	if err != nil || first.Status != "configuring" {
		t.Fatal(first, err)
	}
	b, err := receiveSSHAccess(dir, "second", "device-two", string(ssh.MarshalAuthorizedKey(sshKey)))
	if err != nil {
		t.Fatal(err)
	}
	bad, err = redeemSSHGrant(c, b, key.SSHGrant)
	if err != nil || bad.Status != "configuring" {
		t.Fatal(bad, err)
	}
	file, _ := accessPath(dir, a.ID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var status sshAccess
		secondFile, _ := accessPath(dir, b.ID)
		var second sshAccess
		if readJSON(file, &status) == nil && status.Status == "setup-failed" && readJSON(secondFile, &second) == nil && second.Status == "setup-failed" {
			if status.Code == "" {
				t.Fatal(status)
			}
			if err = readJSON(grantFile, &grant); err != nil || grant.User != "nonexistent-account-for-grant-test" {
				t.Fatal(grant, err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("installation failure was not recorded")
}

func TestLegacyAccessRequestOmitsEmptyGrant(t *testing.T) {
	payload, err := json.Marshal(sshAccessRequest{PublicKey: "ssh-ed25519 test"})
	if err != nil {
		t.Fatal(err)
	}
	// agent.2 rejects unknown fields, so omitting the optional field is required.
	var legacy struct {
		PublicKey string `json:"publicKey"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&legacy); err != nil {
		t.Fatal("new client broke the previous provider", err)
	}
	payload, _ = json.Marshal(sshAccessRequest{PublicKey: "ssh-ed25519 test", Grant: "nonempty"})
	var current sshAccessRequest
	if json.Unmarshal(payload, &current) != nil || current.Grant != "nonempty" {
		t.Fatal("new authorization omitted")
	}
}

func TestProviderRegistrationHonorsCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(503)
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := initialize("deadline-test", dir, server.URL); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = registerProviderUntilAvailable(ctx, c)
	if err == nil || time.Since(started) > 200*time.Millisecond {
		t.Fatalf("registration exceeded caller budget: %v %s", err, time.Since(started))
	}
}

func TestRecoveryLockHonorsWaitingCallerDeadline(t *testing.T) {
	r := &enrollmentRecovery{}
	if err := r.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.lock(ctx); err == nil {
		r.unlock()
		t.Fatal("concurrent recovery ignored deadline")
	}
}

func TestPairingStatusPreservesRetryabilityAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		code  string
		retry bool
	}{
		{"DATA_CHANNEL_UNAVAILABLE", true}, {"TARGET_OFFLINE", true},
		{"TARGET_BUSY", true}, {"PAIRING_TRANSPORT_INTERRUPTED", true},
		{"TARGET_DENIED", false}, {"SERVICE_DENIED", false}, {"private-peer-text", false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			g := newGUI(t.TempDir(), "unused")
			g.state.Running, g.state.Role = true, "connect"
			line := "relay could not pair service: " + tc.code
			g.processLine(line, g.generation)
			p := g.state.Problem
			if p == nil || p.Retryable != tc.retry || strings.Contains(p.Message, "private-peer-text") {
				t.Fatalf("missing or incorrect structured pairing problem: %+v", p)
			}
			if tc.code == "DATA_CHANNEL_UNAVAILABLE" && (!strings.Contains(p.Message, "数据通道") || strings.Contains(p.Message, "拒绝")) {
				t.Fatalf("data capacity mislabeled as authorization: %+v", p)
			}
			serialized := describeConnectionError(errors.New(line))
			if serialized.Code != p.Code || serialized.Retryable != tc.retry || strings.Contains(serialized.Message, "private-peer-text") {
				t.Fatalf("CLI and GUI pairing classifications differ: %+v / %+v", serialized, p)
			}
			g.processLine("tunnel-ready", g.generation)
			if tc.retry && (g.state.Problem != nil || !agentStateResult("status", g.state).OK) {
				t.Fatal("recovered tunnel kept stale retryable error")
			}
			if !tc.retry && g.state.Problem == nil {
				t.Fatal("readiness erased policy rejection")
			}
		})
	}
}
