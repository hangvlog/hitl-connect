package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/coder/websocket"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

func acceptSession(ctx context.Context, c *Config, ws *websocket.Conn, paired Paired, service Service) {
	defer ws.CloseNow()
	metrics := &sessionMetrics{}
	finish := sessionReporter(c, paired, "accept")
	stage := "tls"
	var result error
	defer func() { finish(stage, result, metrics) }()
	if !slices.Contains(service.Allow, paired.Peer) && service.PairingCA == "" {
		result = errors.New("peer denied")
		fmt.Fprintln(os.Stderr, "peer denied for service")
		return
	}
	mode := ""
	encrypted, err := secureWithMode(ctx, c, ws, paired, true, &mode)
	if err != nil {
		result = err
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer encrypted.Close()
	stage = "authorization"
	if mode == sshAccessMode {
		handleSSHAccess(c, encrypted, paired, service)
		return
	}
	if paired.Service == "ssh" {
		if !sshDeviceAllowed(c, encrypted, paired.Peer) {
			result = errors.New("SSH authorization rejected")
			fmt.Fprintln(os.Stderr, "SSH device not authorized or connection code disabled")
			return
		}
		done := make(chan struct{})
		defer close(done)
		go watchSSHDevice(c, encrypted, paired.Peer, done)
	}
	if paired.Service == "ssh" && c.embedded != nil {
		stage = "service-ready"
		if result = serviceReady(encrypted, paired, true, true); result != nil {
			return
		}
		if c.runtime != nil {
			c.runtime.ready()
		}
		stage = "stream"
		certs := encrypted.ConnectionState().PeerCertificates
		digest := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
		fmt.Printf("connected peer=%s service=ssh engine=HITL-Connect\n", paired.Peer)
		result = c.embedded.serve(ctx, &measuredConn{Conn: encrypted, metrics: metrics}, paired.Peer, hex.EncodeToString(digest[:]))
		return
	}
	address, err := loopback(service.Target)
	if err != nil {
		result = err
		return
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	stage = "local-service"
	localCtx, cancel := context.WithDeadline(ctx, stageDeadline(paired, 2*time.Second))
	defer cancel()
	conn, err := dialer.DialContext(localCtx, "tcp", address)
	if err != nil {
		result = &pairingFailure{code: "LOCAL_SERVICE_UNAVAILABLE", cause: err}
		_ = serviceReady(encrypted, paired, true, false)
		fmt.Fprintln(os.Stderr, "local service unavailable")
		return
	}
	tcp := conn.(*net.TCPConn)
	defer tcp.Close()
	fmt.Printf("connected peer=%s service=%s\n", paired.Peer, paired.Service)
	if result = serviceReady(encrypted, paired, true, true); result != nil {
		return
	}
	if c.runtime != nil {
		c.runtime.ready()
	}
	stage = "stream"
	result = pipeMeasured(ctx, tcp, encrypted, metrics)
}
func serve(ctx context.Context, c *Config) error {
	a, authErr := readHostAuthorization(filepath.Dir(c.path))
	if authErr != nil && !os.IsNotExist(authErr) {
		return authErr
	}
	if authErr == nil && a.Engine == "embedded" && c.embedded == nil {
		var err error
		c.embedded, err = loadEmbeddedSSH(filepath.Dir(c.path))
		if err != nil {
			return err
		}
		c.sshAccount = a.User
	}
	if len(c.Services) == 0 {
		return errors.New("no local services configured")
	}
	if c.Protocol == "v3" {
		return serveV3(ctx, c)
	}
	var workers sync.WaitGroup
	slots := make(chan struct{}, 16)
	for name, service := range c.Services {
		workers.Add(1)
		go func() {
			defer workers.Done()
			backoff := time.Second
			for ctx.Err() == nil {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				ws, paired, err := connect(ctx, c, Hello{Role: "accept", Service: name})
				if err != nil {
					<-slots
					if ctx.Err() != nil {
						return
					}
					fmt.Fprintf(os.Stderr, "%v; reconnecting in %s\n", err, backoff)
					select {
					case <-time.After(backoff):
					case <-ctx.Done():
						return
					}
					if backoff < 8*time.Second {
						backoff *= 2
					}
					continue
				}
				backoff = time.Second
				workers.Add(1)
				go func() { defer workers.Done(); defer func() { <-slots }(); acceptSession(ctx, c, ws, paired, service) }()
			}
		}()
	}
	fmt.Printf("serving device=%s services=%d\n", c.ID, len(c.Services))
	workers.Wait()
	return nil
}
func forward(ctx context.Context, c *Config, peerID, service, bind string) error {
	peer, ok := c.Peers[peerID]
	if !ok || !identifier.MatchString(service) || !slices.Contains(peer.Services, service) {
		return errors.New("target service has not been trusted")
	}
	address, err := loopback(bind)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	fmt.Printf("listening=%s peer=%s service=%s\nLocal listener ready; remote service and SSH login are verified when a connection is made.\n", listener.Addr(), peerID, service)
	var workers sync.WaitGroup
	defer workers.Wait()
	slots := make(chan struct{}, 8)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Admission is part of the existing 25-second establishment budget.
		// Keep one bounded waiter here instead of dropping the ninth connection
		// or spawning unbounded goroutines under load. Wait at most 15 seconds,
		// retaining 10 seconds of the setup budget for pairing, TLS and readiness.
		dialCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		select {
		case slots <- struct{}{}:
		default:
			started, trace := time.Now(), newTransportTrace()
			reportLifecycle(c, trace, "dial", "waiting", "admission", nil, 0, map[string]any{"activeLimit": cap(slots)})
			waitCtx, stopWait := context.WithTimeout(dialCtx, 15*time.Second)
			err := waitForwardSlot(waitCtx, slots)
			stopWait()
			if err != nil {
				reportLifecycle(c, trace, "dial", "rejected", "admission", err, time.Since(started), map[string]any{"activeLimit": cap(slots)})
				fmt.Fprintln(os.Stderr, "local-capacity-timeout: active connections retained; new connection was not forwarded")
				cancel()
				conn.Close()
				continue
			}
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			ws, paired, err := connect(dialCtx, c, Hello{Role: "dial", Target: peerID, Service: service})
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "tunnel connection failed: %v\n", err)
				return
			}
			defer ws.CloseNow()
			metrics := &sessionMetrics{}
			finish := sessionReporter(c, paired, "dial")
			stage := "tls"
			var result error
			defer func() { finish(stage, result, metrics) }()
			encrypted, err := secure(ctx, c, ws, paired, false)
			if err != nil {
				result = err
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer encrypted.Close()
			stage = "service-ready"
			if result = serviceReady(encrypted, paired, false, true); result != nil {
				return
			}
			if c.runtime != nil {
				c.runtime.ready()
			}
			fmt.Println("tunnel-ready")
			stage = "stream"
			result = pipeMeasured(ctx, conn.(*net.TCPConn), encrypted, metrics)
		}()
	}
}

var errLocalCapacity = errors.New("LOCAL_CAPACITY_TIMEOUT")

func waitForwardSlot(ctx context.Context, slots chan struct{}) error {
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errLocalCapacity
		}
		return ctx.Err()
	}
}
