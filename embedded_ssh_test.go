package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func embeddedFixture(t *testing.T) (*embeddedSSH, ssh.Signer, string, string) {
	t.Helper()
	profile := t.TempDir()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(private)
	a, err := receiveSSHAccess(profile, "peer-one", "device-one", string(ssh.MarshalAuthorizedKey(key.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	account, sid := "account", "S-1-5-21-123-456-789-1001"
	if runtime.GOOS == "windows" {
		u, e := user.Current()
		if e != nil {
			t.Fatal(e)
		}
		account, sid = u.Username, u.Uid
	}
	g := sshGrant{Hash: "current-grant", User: account}
	if err = privateJSON(filepath.Join(profile, "ssh-grant.json"), g); err != nil {
		t.Fatal(err)
	}
	a.Status, a.User, a.GrantHash = "approved", account, g.Hash
	file, _ := accessPath(profile, a.ID)
	if err = privateJSON(file, a); err != nil {
		t.Fatal(err)
	}
	return &embeddedSSH{policy: hostAuthorization{Profile: profile, User: account, SID: sid, Privilege: "standard"}, signers: []ssh.Signer{key}}, key, a.Peer, a.DeviceKey
}
func TestEmbeddedBindsAccountDeviceKeyAndGrant(t *testing.T) {
	e, key, peer, device := embeddedFixture(t)
	if !e.allows(peer, device, e.policy.User, key.PublicKey()) {
		t.Fatal("approved rejected")
	}
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherPrivate)
	for _, tt := range []struct {
		peer, device, user string
		key                ssh.PublicKey
	}{{"fresh-peer", device, e.policy.User, key.PublicKey()}, {peer, "different-device", e.policy.User, key.PublicKey()}, {peer, device, "hitl-wrong-account", key.PublicKey()}, {peer, device, e.policy.User, other.PublicKey()}} {
		if e.allows(tt.peer, tt.device, tt.user, tt.key) {
			t.Fatal("identity boundary bypass")
		}
	}
	if err := disableSSHGrant(e.policy.Profile); err != nil {
		t.Fatal(err)
	}
	if e.allows(peer, device, e.policy.User, key.PublicKey()) {
		t.Fatal("disabled code accepted")
	}
}
func TestEmbeddedSSHProtocolAndAudit(t *testing.T) {
	e, key, peer, device := embeddedFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err == nil {
			defer raw.Close()
			e.serve(context.Background(), raw, peer, device)
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(&sshFrameConn{Conn: raw}, listener.Addr().String(), &ssh.ClientConfig{User: e.policy.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	if string(conn.ServerVersion()) != "SSH-2.0-HITL_Connect" {
		t.Fatal("missing product identity")
	}
	if channel, _, err := client.OpenChannel("direct-tcpip", nil); err == nil {
		channel.Close()
		t.Fatal("forwarding accepted")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("unsupported PTY accepted")
	}
	session.Close()
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not terminate")
	}
	data, err := os.ReadFile(filepath.Join(e.policy.Profile, "ssh-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var record map[string]any
		if json.Unmarshal(line, &record) != nil || record["product"] != "HITL Connect" {
			t.Fatal("invalid audit")
		}
	}
	if !strings.Contains(string(data), "authenticated") || !strings.Contains(string(data), "disconnected") {
		t.Fatal("missing lifecycle audit")
	}
	if strings.Contains(string(data), "current-grant") || strings.Contains(string(data), string(ssh.MarshalAuthorizedKey(key.PublicKey()))) {
		t.Fatal("secret/public-key material in audit")
	}
}
func TestEmbeddedWorkerNeverUsesSystemOrWrongPrivilege(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	if !validWorkerIdentity(sid, sid, "standard", false) || !validWorkerIdentity(sid, sid, "administrator", true) {
		t.Fatal("valid account denied")
	}
	for _, tt := range []struct {
		actual, expected, privilege string
		elevated                    bool
	}{{"S-1-5-18", sid, "administrator", true}, {"S-1-5-18", "S-1-5-18", "administrator", true}, {sid, sid, "standard", true}, {sid, sid, "administrator", false}, {sid, sid, "", false}} {
		if validWorkerIdentity(tt.actual, tt.expected, tt.privilege, tt.elevated) {
			t.Fatal("worker boundary bypass")
		}
	}
}
func TestEmbeddedHostKeyNeverReplaced(t *testing.T) {
	p := t.TempDir()
	if err := createEmbeddedHostKey(p); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(p, "ssh-host-ed25519.key"))
	if err := createEmbeddedHostKey(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(p, "ssh-host-ed25519.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("host key rotated")
	}
}
