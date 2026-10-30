package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"io"
	"net"
	"strings"
	"time"
)

func dialRelay(ctx context.Context, c *Config, hello Hello) (*websocket.Conn, Paired, error) {
	return dialRelayWithReady(ctx, c, hello, nil)
}
func dialRelayWithReady(ctx context.Context, c *Config, hello Hello, opened func()) (*websocket.Conn, Paired, error) {
	u, err := relayURL(c)
	if err != nil {
		if opened != nil {
			opened()
		}
		return nil, Paired{}, err
	}
	ws, err := openRelay(ctx, c, u)
	if opened != nil {
		opened()
	}
	if err != nil {
		return nil, Paired{}, err
	}
	idle := false
	stopHealthy := func() {}
	defer func() {
		stopHealthy()
		if idle && c.runtime != nil {
			c.runtime.pool(-1)
		}
	}()
	ws.SetReadLimit(65536)
	readCtx, cancelBudget, budgetErr := budgetFor(c, "ssh").attempt(ctx)
	if budgetErr != nil {
		ws.CloseNow()
		return nil, Paired{}, budgetErr
	}
	defer cancelBudget()
	bytes, _ := json.Marshal(hello)
	if err = ws.Write(readCtx, websocket.MessageText, bytes); err != nil {
		ws.CloseNow()
		return nil, Paired{}, pairingError(err)
	}
	for {
		kind, bytes, readErr := ws.Read(readCtx)
		var paired Paired
		if readErr != nil || kind != websocket.MessageText || len(bytes) > 1024 || json.Unmarshal(bytes, &paired) != nil {
			ws.CloseNow()
			return nil, Paired{}, pairingError(readErr)
		}
		if paired.State == "waiting" && hello.Role == "accept" {
			if !idle {
				stopHealthy = budgetFor(c, "ssh").online()
				idle = true
				if c.runtime != nil {
					c.runtime.pool(1)
				}
			}
			readCtx = ctx // Acknowledged idle slot is an online provider connection.
			continue
		}
		if paired.State != "paired" || (hello.Service != "" && paired.Service != hello.Service) || !identifier.MatchString(paired.Peer) || (hello.Role == "dial" && paired.Peer != hello.Target) {
			ws.CloseNow()
			return nil, Paired{}, errors.New("unexpected relay pairing")
		}
		if hello.Role == "accept" {
			if _, ok := c.Services[paired.Service]; !ok {
				ws.CloseNow()
				return nil, Paired{}, errors.New("unconfigured service")
			}
		}
		if c.Protocol == "v3" && hello.Role == "dial" && paired.RequestID != hello.RequestID {
			ws.CloseNow()
			return nil, Paired{}, errors.New("request binding failed")
		}
		if idle {
			paired.stopHealthy = stopHealthy
			stopHealthy = func() {}
		}
		return ws, paired, nil
	}
}
func secure(ctx context.Context, c *Config, ws *websocket.Conn, paired Paired, accepting bool) (*tls.Conn, error) {
	return secureWithMode(ctx, c, ws, paired, accepting, nil)
}

func secureWithMode(ctx context.Context, c *Config, ws *websocket.Conn, paired Paired, accepting bool, mode *string) (*tls.Conn, error) {
	conf, err := tlsConfig(c, paired.Peer, paired.Service, accepting)
	if err != nil {
		return nil, err
	}
	transport := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	var encrypted *tls.Conn
	if accepting {
		encrypted = tls.Server(transport, conf)
	} else {
		encrypted = tls.Client(transport, conf)
	}
	handshakeCtx, cancel := context.WithDeadline(ctx, stageDeadline(paired, 7*time.Second))
	defer cancel()
	if err = encrypted.HandshakeContext(handshakeCtx); err != nil {
		return nil, secureError("TLS handshake", err)
	}
	// Bind the requested service inside TLS so the relay cannot substitute services.
	encrypted.SetDeadline(stageDeadline(paired, 3*time.Second))
	if accepting {
		kind, payload, err := readFrame(encrypted)
		if err != nil {
			return nil, secureError("service binding", err)
		}
		binding := string(payload)
		if paired.Ready {
			suffix := "\nservice-ready-v1"
			if !strings.HasSuffix(binding, suffix) {
				return nil, errors.New("encrypted capability binding failed")
			}
			binding = strings.TrimSuffix(binding, suffix)
		}
		if mode != nil && paired.Service == "ssh" && binding == paired.Service+"\n"+sshAccessMode {
			*mode = sshAccessMode
		} else if binding != paired.Service {
			return nil, errors.New("encrypted service binding failed")
		}
		if kind != 3 {
			return nil, errors.New("encrypted service binding failed")
		}
		if err = writeFrame(encrypted, 3, payload); err != nil {
			return nil, secureError("service binding", err)
		}
	} else {
		binding := paired.Service
		if mode != nil && *mode != "" {
			binding += "\n" + *mode
		}
		if paired.Ready {
			binding += "\nservice-ready-v1"
		}
		if err = writeFrame(encrypted, 3, []byte(binding)); err != nil {
			return nil, secureError("service binding", err)
		}
		kind, payload, err := readFrame(encrypted)
		if err != nil {
			return nil, secureError("service binding", err)
		}
		if kind != 3 || string(payload) != binding {
			return nil, errors.New("encrypted service binding failed")
		}
	}
	encrypted.SetDeadline(time.Time{})
	return encrypted, nil
}
func writeFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > maxChunk {
		return errors.New("frame too large")
	}
	header := make([]byte, 5)
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	_, err := io.Copy(w, bytes.NewReader(append(header, payload...)))
	return err
}
func readFrame(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > maxChunk || header[0] < 1 || header[0] > 3 || (header[0] == 2 && size != 0) {
		return 0, nil, errors.New("invalid encrypted frame")
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(r, payload)
	return header[0], payload, err
}

// FIN is encrypted application framing, preserving TCP half-close in either direction.
func pipe(ctx context.Context, tcp *net.TCPConn, encrypted *tls.Conn) error {
	return pipeMeasured(ctx, tcp, encrypted, &sessionMetrics{})
}
func pipeMeasured(ctx context.Context, tcp *net.TCPConn, encrypted *tls.Conn, metrics *sessionMetrics) error {
	done := make(chan error, 2)
	go func() {
		writer := frameWriter{}
		buffer := writer.buffer[5:]
		for {
			n, err := tcp.Read(buffer)
			if n > 0 {
				started := time.Now()
				encrypted.SetWriteDeadline(started.Add(60 * time.Second))
				if sendErr := writer.write(encrypted, 1, buffer[:n]); sendErr != nil {
					done <- streamError("peer", "write", sendErr)
					return
				}
				metrics.wrote(n, true, started)
				encrypted.SetWriteDeadline(time.Time{})
			}
			if err == io.EOF {
				encrypted.SetWriteDeadline(time.Now().Add(60 * time.Second))
				done <- streamError("peer", "half-close", writer.write(encrypted, 2, nil))
				return
			}
			if err != nil {
				done <- streamError("local", "read", err)
				return
			}
		}
	}()
	go func() {
		reader := frameReader{}
		for {
			kind, payload, err := reader.read(encrypted)
			if err != nil {
				done <- streamError("peer", "read", err)
				return
			}
			if kind == 2 {
				done <- streamError("local", "half-close", tcp.CloseWrite())
				return
			}
			if kind != 1 {
				done <- errors.New("unexpected encrypted control frame")
				return
			}
			started := time.Now()
			tcp.SetWriteDeadline(started.Add(60 * time.Second))
			if err = writeFrameBytes(tcp, payload); err != nil {
				done <- streamError("local", "write", err)
				return
			}
			metrics.wrote(len(payload), false, started)
			tcp.SetWriteDeadline(time.Time{})
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return streamError("process", "cancel", ctx.Err())
		}
	}
	return nil
}

func stageDeadline(paired Paired, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if !paired.deadline.IsZero() && paired.deadline.Before(deadline) {
		return paired.deadline
	}
	return deadline
}
func serviceReady(encrypted *tls.Conn, paired Paired, accepting bool, available bool) error {
	if !paired.Ready {
		return nil
	}
	encrypted.SetDeadline(stageDeadline(paired, 2*time.Second))
	defer encrypted.SetDeadline(time.Time{})
	if accepting {
		code := "SERVICE_READY"
		if !available {
			code = "LOCAL_SERVICE_UNAVAILABLE"
		}
		return writeFrame(encrypted, 3, []byte(code))
	}
	kind, payload, err := readFrame(encrypted)
	if err != nil {
		return secureError("local service readiness", err)
	}
	if kind != 3 || string(payload) != "SERVICE_READY" {
		return &pairingFailure{code: "LOCAL_SERVICE_UNAVAILABLE"}
	}
	return nil
}
