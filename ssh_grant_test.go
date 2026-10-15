package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostTrustFixture(t *testing.T, signers ...ssh.Signer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{NoClientAuth: true}
	for _, signer := range signers {
		config.AddHostKey(signer)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _, _, _ = ssh.NewServerConn(conn, config)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestSavedSSHTrustWithMultipleHostKeyAlgorithms(t *testing.T) {
	_, edPrivate, _ := ed25519.GenerateKey(rand.Reader)
	ed, _ := ssh.NewSignerFromKey(edPrivate)
	ecPrivate, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec, _ := ssh.NewSignerFromKey(ecPrivate)
	address := hostTrustFixture(t, ec, ed)
	base := t.TempDir()
	file := filepath.Join(base, "gui-known-hosts")
	original := []byte(knownhosts.Line([]string{address}, ed.PublicKey()) + "\n")
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := trustPairedSSHHost(base, address, string(ssh.MarshalAuthorizedKey(ec.PublicKey()))); err != nil {
		t.Fatalf("same server's other algorithm falsely rejected original trust: %v", err)
	}
	data, _ := os.ReadFile(file)
	if !bytes.Equal(original, data) {
		t.Fatal("existing trust was replaced or extended")
	}
	key, err := probeSSHForSavedHost(address, file)
	if err != nil || !bytes.Equal(key.Marshal(), ed.PublicKey().Marshal()) {
		t.Fatalf("diagnostic did not select the saved host key: %v", err)
	}
}

func TestSavedSSHTrustRejectsRealChangeAndMissingOriginal(t *testing.T) {
	_, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	old, _ := ssh.NewSignerFromKey(oldPrivate)
	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	replacement, _ := ssh.NewSignerFromKey(newPrivate)
	ecPrivate, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec, _ := ssh.NewSignerFromKey(ecPrivate)
	for _, scenario := range []struct {
		name    string
		keys    []ssh.Signer
		offered ssh.PublicKey
	}{
		{"different-ed25519", []ssh.Signer{replacement}, replacement.PublicKey()},
		{"original-removed", []ssh.Signer{ec}, ec.PublicKey()},
		{"fallback-key-changed", []ssh.Signer{ec, replacement}, ec.PublicKey()},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			address := hostTrustFixture(t, scenario.keys...)
			base := t.TempDir()
			file := filepath.Join(base, "gui-known-hosts")
			original := []byte(knownhosts.Line([]string{address}, old.PublicKey()) + "\n")
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := trustPairedSSHHost(base, address, string(ssh.MarshalAuthorizedKey(scenario.offered))); err == nil {
				t.Fatal("changed/unavailable original key was accepted")
			}
			data, _ := os.ReadFile(file)
			if !bytes.Equal(data, original) {
				t.Fatal("failure modified trust")
			}
		})
	}
}

func TestConnectionCodeDoesNotExpireWithElapsedTime(t *testing.T) {
	dir := grantTestDirectory(t)
	if err := initialize("long-lived-test", dir, "http://127.0.0.1:9000"); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	c.sshAccount = "nonexistent-account-for-grant-test"
	if err = issueSSHGrant(c, c.sshAccount); err != nil {
		t.Fatal(err)
	}
	key, err := readConnectionKey(filepath.Join(dir, "connection-key-ssh.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var grant sshGrant
	file := filepath.Join(dir, "ssh-grant.json")
	if err = readJSON(file, &grant); err != nil {
		t.Fatal(err)
	}
	// An old version's deadline must not defeat the user's new no-expiry policy.
	grant.Expires = time.Now().Add(-365 * 24 * time.Hour).Unix()
	if err = privateJSON(file, grant); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keypub, _ := ssh.NewPublicKey(pub)
	a, err := receiveSSHAccess(dir, "caller", "device", string(ssh.MarshalAuthorizedKey(keypub)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := redeemSSHGrant(c, a, key.SSHGrant)
	if err != nil || result.Status == "denied" {
		t.Fatalf("time alone invalidated the connection code: %+v %v", result, err)
	}
	path, _ := accessPath(dir, a.ID)
	for i := 0; i < 100; i++ {
		if _, active := grantInstallations.Load(path); !active {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("setup did not finish")
}

func TestConnectionCodeSurvivesRestartAndCanBeDisabled(t *testing.T) {
	dir := grantTestDirectory(t)
	if err := initialize("persist-test", dir, "http://127.0.0.1:9000"); err != nil {
		t.Fatal(err)
	}
	c, err := load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	c.sshAccount = "nonexistent-account-for-grant-test"
	if err = ensureSSHGrant(c, c.sshAccount); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "connection-key-ssh.txt")
	old, err := readConnectionKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
		t.Fatal(err)
	}
	if err = ensureSSHGrant(c, c.sshAccount); err != nil {
		t.Fatal(err)
	}
	same, err := readConnectionKey(keyFile)
	if err != nil || old != same {
		t.Fatal("restart replaced the code", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshKey, _ := ssh.NewPublicKey(pub)
	a, err := receiveSSHAccess(dir, "bound-device", "device-key", string(ssh.MarshalAuthorizedKey(sshKey)))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := accessPath(dir, a.ID)
	a.Status = "approved"
	a.User = c.sshAccount
	if err = privateJSON(path, a); err != nil {
		t.Fatal(err)
	}
	var grant sshGrant
	grantFile := filepath.Join(dir, "ssh-grant.json")
	if err = readJSON(grantFile, &grant); err != nil || grant.Expires != 0 {
		t.Fatal("code has deadline", err)
	}
	grant.Request = a.ID
	if err = privateJSON(grantFile, grant); err != nil {
		t.Fatal(err)
	}
	if err = disableSSHGrant(dir); err != nil {
		t.Fatal(err)
	}
	revoked, err := redeemSSHGrant(c, a, old.SSHGrant)
	if err != nil || revoked.Code != "CONNECTION_CODE_DISABLED" {
		t.Fatal(revoked, err)
	}
	if sshPeerAllowed(dir, a.Peer, a.DeviceKey) {
		t.Fatal("disabled device can still open SSH")
	}
	if sshPeerAllowed(dir, "unrelated-device", "other-key") {
		t.Fatal("new device can bypass code revocation with an existing SSH key")
	}
	if !sshPeerAllowed(t.TempDir(), "legacy-device", "other-key") {
		t.Fatal("legacy tunnel-only profile no longer allows manual SSH")
	}
	if err = ensureSSHGrant(c, c.sshAccount); err != nil {
		t.Fatal(err)
	}
	if err = readJSON(grantFile, &grant); err != nil || !grant.Disabled {
		t.Fatal("restart re-enabled a disabled code")
	}
	if err = issueSSHGrant(c, c.sshAccount); err != nil {
		t.Fatal(err)
	}
	next, err := readConnectionKey(keyFile)
	if err != nil || next.SSHGrant == old.SSHGrant {
		t.Fatal("explicit replacement did not replace code")
	}
	denied, err := redeemSSHGrant(c, a, old.SSHGrant)
	if err != nil || denied.Code != "CONNECTION_CODE_INVALID_OR_REPLACED" {
		t.Fatal("old code still works", denied, err)
	}
}

func TestMultipleGrantDevicesRevocationAndLateInstallation(t *testing.T) {
	for _, action := range []string{"disable", "replace"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			if err := initialize("multi-grant", dir, "http://127.0.0.1:9000"); err != nil {
				t.Fatal(err)
			}
			c, err := load(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = share(c, "ssh", "127.0.0.1:22"); err != nil {
				t.Fatal(err)
			}
			c.sshAccount = "fixture-account"
			if err = ensureSSHGrant(c, c.sshAccount); err != nil {
				t.Fatal(err)
			}
			var grant sshGrant
			grantFile := filepath.Join(dir, "ssh-grant.json")
			if err = readJSON(grantFile, &grant); err != nil {
				t.Fatal(err)
			}
			var devices []sshAccess
			for i, peer := range []string{"legacy", "new-device", "installing-device"} {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				key, _ := ssh.NewPublicKey(pub)
				a, e := receiveSSHAccess(dir, peer, peer+"-key", string(ssh.MarshalAuthorizedKey(key)))
				if e != nil {
					t.Fatal(e)
				}
				a.Status, a.User, a.GrantHash = "approved", c.sshAccount, grant.Hash
				if i == 0 {
					a.GrantHash = ""
					grant.Request = a.ID
				}
				if i == 2 {
					a.Status = "configuring"
				}
				path, _ := accessPath(dir, a.ID)
				if e = privateJSON(path, a); e != nil {
					t.Fatal(e)
				}
				devices = append(devices, a)
			}
			if err = privateJSON(grantFile, grant); err != nil {
				t.Fatal(err)
			}
			if err = ensureSSHGrant(c, c.sshAccount); err != nil {
				t.Fatal(err)
			}
			for _, a := range devices[:2] {
				if !sshPeerAllowed(dir, a.Peer, a.DeviceKey) {
					t.Fatal("restart lost authorized device", a.Peer)
				}
			}
			if action == "disable" {
				err = disableSSHGrant(dir)
			} else {
				err = issueSSHGrant(c, c.sshAccount)
			}
			if err != nil {
				t.Fatal(err)
			}
			finishGrantInstallation(dir, devices[2], grant, agentResult{OK: true})
			for _, a := range devices {
				if sshPeerAllowed(dir, a.Peer, a.DeviceKey) {
					t.Fatal("revoked device still allowed", a.Peer)
				}
				path, _ := accessPath(dir, a.ID)
				var current sshAccess
				if readJSON(path, &current) != nil || current.Status != "revoked" {
					t.Fatal("late install restored authority", current)
				}
			}
			if err = ensureSSHGrant(c, c.sshAccount); err != nil {
				t.Fatal(err)
			}
			if sshPeerAllowed(dir, "fresh", "new-identity") {
				t.Fatal("unknown identity bypassed revocation")
			}
			if action == "replace" {
				var next sshGrant
				if err = readJSON(grantFile, &next); err != nil {
					t.Fatal(err)
				}
				// The same request can redeem the new code while an old install completes.
				a := devices[2]
				a.Status, a.Code, a.GrantHash = "configuring", "", next.Hash
				path, _ := accessPath(dir, a.ID)
				if err = privateJSON(path, a); err != nil {
					t.Fatal(err)
				}
				finishGrantInstallation(dir, devices[2], grant, agentResult{OK: true})
				var current sshAccess
				if readJSON(path, &current) != nil || current.Status != "configuring" {
					t.Fatal("old generation approved a new request")
				}
				finishGrantInstallation(dir, a, next, agentResult{OK: true})
				if !sshPeerAllowed(dir, a.Peer, a.DeviceKey) {
					t.Fatal("new generation could not authorize")
				}
				// A partial tombstone write must still fail closed on disabled generation.
				next.Disabled = true
				if err = privateJSON(grantFile, next); err != nil {
					t.Fatal(err)
				}
				if sshPeerAllowed(dir, a.Peer, a.DeviceKey) {
					t.Fatal("disabled grant accepted approved record")
				}
			}
		})
	}
}
