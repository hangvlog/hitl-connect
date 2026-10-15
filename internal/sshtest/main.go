// An isolated SSH protocol fixture. It never executes OS commands.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	publicFile := flag.String("public-key", "", "only accepted client public key")
	flag.Parse()
	data, err := os.ReadFile(*publicFile)
	if err != nil {
		panic(err)
	}
	authorized, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		panic(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "fixture" || !bytes.Equal(key.Marshal(), authorized.Marshal()) {
			return nil, fmt.Errorf("denied")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"port": listener.Addr().(*net.TCPAddr).Port, "hostKey": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))})
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			server, channels, requests, err := ssh.NewServerConn(conn, config)
			if err != nil {
				return
			}
			defer server.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				if channel.ChannelType() != "session" {
					channel.Reject(ssh.UnknownChannelType, "session only")
					continue
				}
				ch, requests, err := channel.Accept()
				if err != nil {
					continue
				}
				go func() {
					defer ch.Close()
					for request := range requests {
						var command struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || (command.Command != "probe" && command.Command != "whoami") {
							request.Reply(false, nil)
							continue
						}
						request.Reply(true, nil)
						ch.Write([]byte("hitl-tunnel-ssh-ok\n"))
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						return
					}
				}()
			}
		}()
	}
}
