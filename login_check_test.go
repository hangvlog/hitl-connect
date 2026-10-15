package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func loginFixture(t *testing.T, public ssh.PublicKey, output string, status uint32, signers ...ssh.Signer) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var connections, authentications atomic.Int32
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		authentications.Add(1)
		if !bytes.Equal(key.Marshal(), public.Marshal()) {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	for _, s := range signers {
		config.AddHostKey(s)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					ch, reqs, err := incoming.Accept()
					if err != nil {
						return
					}
					for r := range reqs {
						if r.Type != "exec" {
							r.Reply(false, nil)
							continue
						}
						var cmd struct{ Command string }
						ssh.Unmarshal(r.Payload, &cmd)
						if cmd.Command != "whoami" {
							r.Reply(false, nil)
							return
						}
						r.Reply(true, nil)
						// Require client EOF, as the Windows account worker does.
						io.Copy(io.Discard, ch)
						io.WriteString(ch, output)
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						ch.Close()
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), &connections, &authentications
}
func loginSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManagedLoginSingleConnectionAndTrust(t *testing.T) {
	for _, scenario := range []string{"valid", "multiple-algorithms", "hashed-host", "changed", "revoked", "revoked-only", "malformed", "wrong-user-key", "nonzero", "invalid-identity"} {
		t.Run(scenario, func(t *testing.T) {
			base := t.TempDir()
			file, key, err := accessKey(base, "")
			if err != nil {
				t.Fatal(err)
			}
			host := loginSigner(t)
			pin := host.PublicKey()
			serverKeys := []ssh.Signer{host}
			output, status := "fixture\\tester\r\n", uint32(0)
			switch scenario {
			case "multiple-algorithms":
				ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				s, _ := ssh.NewSignerFromKey(ec)
				serverKeys = append([]ssh.Signer{s}, serverKeys...)
			case "changed":
				pin = loginSigner(t).PublicKey()
			case "wrong-user-key":
				key = loginSigner(t).PublicKey()
			case "nonzero":
				status = 7
			case "invalid-identity":
				output = "first\nsecond\n"
			}
			address, connections, auth := loginFixture(t, key, output, status, serverKeys...)
			hostName := address
			if scenario == "hashed-host" {
				hostName = knownhosts.HashHostname(knownhosts.Normalize(address))
			}
			trust := knownhosts.Line([]string{hostName}, pin) + "\n"
			if scenario == "revoked" {
				trust += "@revoked " + knownhosts.Line([]string{address}, pin) + "\n"
			}
			if scenario == "revoked-only" {
				trust = "@revoked " + knownhosts.Line([]string{address}, pin) + "\n"
			}
			if scenario == "malformed" {
				trust = "broken trust\n"
			}
			knownFile := filepath.Join(base, "gui-known-hosts")
			os.WriteFile(knownFile, []byte(trust), 0600)
			g := newGUI(base, "unused")
			g.state.Role, g.state.Running, g.address = "connect", true, address
			if err := g.diagnose(guiRequest{User: "tester", KeyPath: file}); err != nil {
				t.Fatal(err)
			}
			success := scenario == "valid" || scenario == "multiple-algorithms" || scenario == "hashed-host"
			if success {
				if g.state.LoginIdentity != "fixture\\tester" || g.state.NativeSSHExitCode == nil || *g.state.NativeSSHExitCode != 0 || g.state.LoginCheckEngine != "embedded" {
					t.Fatalf("login failed: %+v", g.state)
				}
				if connections.Load() != 1 {
					t.Fatalf("expected one connection, got %d", connections.Load())
				}
			} else if g.state.LoginIdentity != "" {
				t.Fatal("failure reported success")
			}
			if scenario == "changed" || scenario == "revoked" || scenario == "revoked-only" || scenario == "malformed" {
				if auth.Load() != 0 || g.state.CanTrust {
					t.Fatalf("unsafe trust handling: auth=%d canTrust=%v", auth.Load(), g.state.CanTrust)
				}
			}
			if scenario == "nonzero" && (g.state.NativeSSHExitCode == nil || *g.state.NativeSSHExitCode != 7) {
				t.Fatal("lost remote exit code")
			}
			after, _ := os.ReadFile(knownFile)
			if string(after) != trust {
				t.Fatal("trust modified")
			}
		})
	}
}

func TestLoginCheckCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err = runLoginCheck(ctx, listener.Addr().String(), "tester", loginSigner(t), nil, ssh.FixedHostKey(loginSigner(t).PublicKey()))
	if err == nil {
		t.Fatal("hung server accepted")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection leaked after cancellation")
	}
}

func TestLoginCheckBoundedOutput(t *testing.T) {
	b := &loginOutput{limit: 4096}
	n, err := io.Copy(b, strings.NewReader(strings.Repeat("x", 65536)))
	if err != nil || n != 65536 || len(b.data) != 4096 {
		t.Fatal("output was not bounded and drained")
	}
}
