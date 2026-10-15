package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Win32 OpenSSH with stdin connected to NUL can leave the channel input open.
// The embedded account worker waits for that EOF before completing cmd.Run.
// Exercise the native client against a server with the same EOF requirement.
func TestNativeLoginCheckClosesInput(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("native SSH client unavailable")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
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
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(18 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil { // The preliminary host-key probe intentionally aborts.
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						_ = request.Reply(true, nil)
						_, _ = io.WriteString(channel, "fixture\\tester\r\n")
						_, _ = io.Copy(io.Discard, channel)
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = channel.Close()
						return
					}
				}
			}()
		}
	}()
	base := t.TempDir()
	address := listener.Addr().String()
	if err := os.WriteFile(filepath.Join(base, "gui-known-hosts"), []byte(knownhosts.Line([]string{address}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	g := newGUI(base, "unused")
	g.state.Role, g.state.Running, g.address = "connect", true, address
	if err := g.diagnose(guiRequest{User: "tester"}); err != nil {
		t.Fatal(err)
	}
	if g.state.NativeSSHExitCode == nil || *g.state.NativeSSHExitCode != 0 || !strings.EqualFold(g.state.LoginIdentity, "fixture\\tester") {
		t.Fatalf("native login did not finish after returning identity: exit=%v steps=%+v", g.state.NativeSSHExitCode, g.state.Steps)
	}
}
