package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The SSH endpoint exists only inside authenticated HITL TLS streams. There is
// no TCP listener and no system sshd, authorized_keys or firewall mutation.
type embeddedSSH struct {
	policy  hostAuthorization
	signers []ssh.Signer
	auditMu sync.Mutex
}

func embeddedPolicy(profile string) (hostAuthorization, bool) {
	a, e := readHostAuthorization(profile)
	return a, e == nil && a.Engine == "embedded"
}
func loadEmbeddedSSH(profile string) (*embeddedSSH, error) {
	a, ok := embeddedPolicy(profile)
	if !ok {
		return nil, errors.New("EMBEDDED_AUTHORIZATION_REQUIRED")
	}
	e := &embeddedSSH{policy: a}
	for _, name := range []string{"ssh-host-ed25519.key", "ssh-host-ecdsa.key", "ssh-host-rsa.key"} {
		data, err := os.ReadFile(filepath.Join(profile, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, errors.New("EMBEDDED_HOST_KEY_INVALID")
		}
		e.signers = append(e.signers, signer)
	}
	if len(e.signers) == 0 {
		return nil, errors.New("EMBEDDED_HOST_KEY_MISSING")
	}
	return e, nil
}
func createEmbeddedHostKey(profile string) error {
	path := filepath.Join(profile, "ssh-host-ed25519.key")
	if _, e := os.Stat(path); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(key, "HITL Connect")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(pem.EncodeToMemory(block))
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	return err
}

// Minimal append-only local audit. No commands, file contents, credentials or
// connection codes. Administrators can alter local logs; this is not a remote
// tamper-proof ledger. Refuse new sessions when the audit cannot be written.
func (e *embeddedSSH) audit(event, peer, fingerprint, session, operation string, exit int) error {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	record := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "product": "HITL Connect", "event": event, "peer": peer, "keyFingerprint": fingerprint, "session": session, "accountSid": e.policy.SID, "privilege": e.policy.Privilege, "operation": operation, "exitCode": exit}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(e.policy.Profile, "ssh-audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (e *embeddedSSH) allows(peer, device, user string, key ssh.PublicKey) bool {
	// Locally approved account SID, device TLS key, SSH key and current grant.
	if !embeddedLoginUser(e.policy, user) || !sshPeerAllowed(e.policy.Profile, peer, device) {
		return false
	}
	var grant sshGrant
	if readJSON(filepath.Join(e.policy.Profile, "ssh-grant.json"), &grant) != nil || grant.Disabled || grant.User != e.policy.User {
		return false
	}
	digest := sha256.Sum256([]byte(peer + "\n" + device + "\n" + string(ssh.MarshalAuthorizedKey(key))))
	path, _ := accessPath(e.policy.Profile, hex.EncodeToString(digest[:]))
	var a sshAccess
	if readJSON(path, &a) != nil || a.Status != "approved" || a.Peer != peer || a.DeviceKey != device || a.User != e.policy.User || !accessUsesGrant(a, grant) {
		return false
	}
	approved, err := plainSSHKey([]byte(a.PublicKey))
	return err == nil && bytes.Equal(approved.Marshal(), key.Marshal())
}

// Adapt the existing encrypted HITL data/FIN framing to an SSH byte stream.
type sshFrameConn struct {
	net.Conn
	pending []byte
	writeMu sync.Mutex
}

func (c *sshFrameConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		kind, data, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		if kind == 2 {
			return 0, io.EOF
		}
		if kind != 1 {
			return 0, errors.New("unexpected SSH frame")
		}
		c.pending = data
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *sshFrameConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxChunk)
		if err := writeFrame(c.Conn, 1, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (e *embeddedSSH) serve(ctx context.Context, raw net.Conn, peer, device string) error {
	session := rand.Text()
	config := &ssh.ServerConfig{ServerVersion: "SSH-2.0-HITL_Connect", MaxAuthTries: 3, PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := ssh.FingerprintSHA256(key)
		if !e.allows(peer, device, meta.User(), key) {
			_ = e.audit("authentication-denied", peer, fp, session, "", -1)
			return nil, errors.New("device or account not authorized")
		}
		if err := e.audit("key-authorized", peer, fp, session, "", 0); err != nil {
			return nil, errors.New("AUDIT_UNAVAILABLE")
		}
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}}
	for _, s := range e.signers {
		config.AddHostKey(s)
	}
	conn := &sshFrameConn{Conn: raw}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return err
	}
	defer server.Close()
	if err = e.audit("authenticated", peer, server.Permissions.Extensions["fingerprint"], session, "", 0); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- server.Wait(); cancel() }()
	go func() { <-sessionCtx.Done(); _ = server.Close() }()
	go ssh.DiscardRequests(requests)
	// Bound the number of concurrent account workers per SSH connection.
	slots := make(chan struct{}, 4)
	var workers sync.WaitGroup
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "HITL Connect supports exec, shell and sftp sessions")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = ch.Reject(ssh.ResourceShortage, "session limit")
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			<-slots
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			e.session(sessionCtx, channel, reqs, peer, server.Permissions.Extensions["fingerprint"], session)
		}()
	}
	cancel()
	workers.Wait()
	_ = e.audit("disconnected", peer, server.Permissions.Extensions["fingerprint"], session, "", 0)
	return <-ended
}
func (e *embeddedSSH) session(ctx context.Context, ch ssh.Channel, requests <-chan *ssh.Request, peer, fp, session string) {
	defer ch.Close()
	for req := range requests {
		operation, command := "", ""
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if ssh.Unmarshal(req.Payload, &p) == nil && len(p.Command) > 0 && len(p.Command) <= 32768 {
				operation, command = "exec", p.Command
			}
		case "shell":
			if len(req.Payload) == 0 {
				operation = "shell"
			}
		case "subsystem":
			var p struct{ Name string }
			if ssh.Unmarshal(req.Payload, &p) == nil && p.Name == "sftp" {
				operation = "sftp"
			}
		}
		if operation == "" {
			_ = req.Reply(false, nil)
			continue
		}
		if err := e.audit("session-start", peer, fp, session, operation, -1); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		// Remaining requests (including environment/forwarding/PTY) cannot mutate
		// the fixed account worker's environment or executable selection.
		workerCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			for request := range requests {
				_ = request.Reply(false, nil)
			}
			cancel()
		}()
		go func() { <-workerCtx.Done(); _ = ch.Close() }()
		exit, err := runEmbeddedWorker(workerCtx, e.policy, operation, command, ch)
		if err != nil {
			fmt.Fprintln(ch.Stderr(), err.Error())
		}
		_ = e.audit("session-end", peer, fp, session, operation, exit)
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exit)}))
		_ = ch.CloseWrite()
		return
	}
}
