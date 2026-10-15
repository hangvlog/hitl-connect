package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSystemSSHUpgradeRequiresConfirmedDrain(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		active, locked, descriptor, interrupt bool
		stateStatus                           int
		drain                                 string
		wantErr                               bool
	}{
		{"missing-live-service", true, false, false, false, 200, `{"ok":true}`, true},
		{"missing-live-panel", false, true, false, false, 200, `{"ok":true}`, true},
		{"unreachable-live-service", true, false, true, false, 503, `{"ok":true}`, true},
		{"negative-drain", true, false, true, false, 200, `{"ok":false}`, true},
		{"confirmed-drain", true, false, true, false, 200, `{"ok":true}`, false},
		{"already-stopped", false, false, false, false, 200, `{"ok":true}`, false},
		{"explicit-interruption", true, false, false, true, 200, `{"ok":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.locked {
				release, acquired, err := tryProfileLock(root, ".panel.lock")
				if err != nil || !acquired {
					t.Fatal(err)
				}
				defer release()
			}
			quit, drained := false, false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/state":
					w.WriteHeader(tc.stateStatus)
					_, _ = w.Write([]byte(`{"running":true}`))
				case "/api/drain":
					drained = true
					_, _ = w.Write([]byte(tc.drain))
				case "/api/quit":
					quit = true
					_, _ = w.Write([]byte(`{"ok":true}`))
				}
			}))
			defer server.Close()
			if tc.descriptor {
				if err := privateJSON(filepath.Join(root, "gui-session.json"), guiDescriptor{URL: server.URL, Token: strings.Repeat("a", 64)}); err != nil {
					t.Fatal(err)
				}
			}
			err := quiesceSystemSSHProvider(context.Background(), root, tc.interrupt, tc.active)
			if (err != nil) != tc.wantErr {
				t.Errorf("error=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && quit {
				t.Error("quit sent without a confirmed drain")
			}
			if tc.name == "confirmed-drain" && (!quit || !drained) {
				t.Error("missing drain/quit")
			}
		})
	}
}

func TestSystemSSHKeysRestrictCurrentGrantAndAccount(t *testing.T) {
	p := t.TempDir()
	if err := os.Mkdir(filepath.Join(p, "ssh-access"), 0700); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	public := string(ssh.MarshalAuthorizedKey(key))
	policy := hostAuthorization{User: "allowed"}
	grant := sshGrant{Hash: "current", User: "allowed"}
	if err := privateJSON(filepath.Join(p, "ssh-grant.json"), grant); err != nil {
		t.Fatal(err)
	}
	a := sshAccess{ID: strings.Repeat("a", 64), Status: "approved", GrantHash: "current", User: "allowed", PublicKey: public, Fingerprint: ssh.FingerprintSHA256(key)}
	path, _ := accessPath(p, a.ID)
	save := func() {
		t.Helper()
		if err := privateJSON(path, a); err != nil {
			t.Fatal(err)
		}
	}
	save()
	data, err := systemSSHKeys(p, policy, nil)
	if err != nil || !strings.Contains(string(data), "restrict "+public) {
		t.Fatal("active key not constrained", err, string(data))
	}
	for _, status := range []string{"revoked", "denied", "pending", "setup-failed", "configuring"} {
		a.Status = status
		save()
		data, err = systemSSHKeys(p, policy, nil)
		if err != nil || strings.Contains(string(data), public) {
			t.Fatal("unapproved key present", status, err)
		}
	}
	data, err = systemSSHKeys(p, policy, &a)
	if err != nil || !strings.Contains(string(data), public) {
		t.Fatal("current installation rejected", err)
	}
	a.Status = "approved"
	a.User = "another"
	save()
	if _, err = systemSSHKeys(p, policy, nil); err == nil {
		t.Fatal("another account accepted")
	}
	a.User = "allowed"
	a.PublicKey = "command=\"whoami\" " + public
	save()
	if _, err = systemSSHKeys(p, policy, nil); err == nil {
		t.Fatal("key option injection accepted")
	}
	a.PublicKey = public
	a.GrantHash = "old"
	save()
	data, err = systemSSHKeys(p, policy, nil)
	if err != nil || strings.Contains(string(data), public) {
		t.Fatal("old grant retained", err)
	}
	a.GrantHash = "current"
	save()
	grant.Disabled = true
	if err = privateJSON(filepath.Join(p, "ssh-grant.json"), grant); err != nil {
		t.Fatal(err)
	}
	data, err = systemSSHKeys(p, policy, &a)
	if err == nil || strings.Contains(string(data), public) {
		t.Fatal("disabled grant retained", err)
	}
}
