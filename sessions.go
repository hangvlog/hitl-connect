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
	if paired.stopHealthy != nil {
		defer paired.stopHealthy()
	}
	metrics := &sessionMetrics{}
	finish := sessionReporter(c, paired, "accept")
	stage := "tls"
	var result error
	// A rejected, interrupted or completed peer session is not a provider outage.
	// Only provider registration/control/accept failures consume its retry budget.
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
		stopHealthy := budgetFor(c, "ssh").online()
		defer stopHealthy()
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
	stopHealthy := budgetFor(c, "ssh").online()
	defer stopHealthy()
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
	if c.Protocol == "v3" && c.runtime == nil {
		c.runtime = newProviderRuntime()
	}
	if c.embedded != nil && c.embedded.jobs == nil {
		c.embedded.jobs = newJobManager(ctx, filepath.Join(c.embedded.policy.Profile, "jobs"), c.runtime,
			func(jobCtx context.Context, command string, streams workerIO) (int, error) {
				return runEmbeddedWorker(jobCtx, c.embedded.policy, "exec", command, streams)
			})
	}
	if len(c.Services) == 0 {
		return errors.New("no local services configured")
	}
	if c.Protocol == "v3" {
		return serveV3(ctx, c)
	}
	var workers sync.WaitGroup
	slots := make(chan struct{}, c.capacity().ProviderConnections)
	for name, service := range c.Services {
		workers.Add(1)
		go func() {
			defer workers.Done()

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
					wait := retryMinimum()
					fmt.Fprintf(os.Stderr, "%v; reconnecting with saved backoff\n", err)
					if err := budgetFor(c, "ssh").wait(ctx, wait); err != nil {
						if isReconnectStopped(err) {
							fmt.Fprintln(os.Stderr, err)
						}
						return
					}
					continue
				}

				workers.Add(1)
				go func() { defer workers.Done(); defer func() { <-slots }(); acceptSession(ctx, c, ws, paired, service) }()
			}
		}()
	}
	fmt.Printf("serving device=%s services=%d\n", c.ID, len(c.Services))
	workers.Wait()
	if err := budgetFor(c, "ssh").wait(ctx, 0); isReconnectStopped(err) {
		return err
	}
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
	limits := c.capacity()
	type pending struct {
		conn     net.Conn
		accepted time.Time
		timer    *time.Timer
	}
	queue := make(chan pending, limits.CallerQueue)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer close(queue)
	for i := 0; i < limits.CallerConnections; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for request := range queue {
				request.timer.Stop()
				if ctx.Err() != nil || time.Since(request.accepted) >= 15*time.Second {
					request.conn.Close()
					reportLifecycle(c, newTransportTrace(), "dial", "rejected", "admission", errLocalCapacity, time.Since(request.accepted), nil)
					continue
				}
				dialCtx, cancel := context.WithDeadline(ctx, request.accepted.Add(25*time.Second))
				forwardConnection(ctx, dialCtx, c, peerID, service, request.conn)
				cancel()
			}
		}()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		timer := time.AfterFunc(15*time.Second, func() { _ = conn.Close() })
		select {
		case queue <- pending{conn, time.Now(), timer}:
		default:
			timer.Stop()
			conn.Close()
			reportLifecycle(c, newTransportTrace(), "dial", "rejected", "admission", errLocalCapacity, 0, map[string]any{"queueLimit": limits.CallerQueue})
		}
	}
}

func forwardConnection(ctx, dialCtx context.Context, c *Config, peerID, service string, conn net.Conn) {
	defer conn.Close()
	ws, paired, err := connect(dialCtx, c, Hello{Role: "dial", Target: peerID, Service: service})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tunnel connection failed: %v\n", err)
		return
	}
	defer ws.CloseNow()
	metrics := &sessionMetrics{}
	finish := sessionReporter(c, paired, "dial")
	stage := "tls"
	var result error
	defer func() {
		if stage != "stream" {
			_ = budgetFor(c, "ssh").result(result, ctx)
		}
	}()
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
	stopHealthy := budgetFor(c, "ssh").online()
	defer stopHealthy()
	stage = "stream"
	result = pipeMeasured(ctx, conn.(*net.TCPConn), encrypted, metrics)
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
