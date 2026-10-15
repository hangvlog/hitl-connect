package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

type sessionMetrics struct{ sent, received, lastIO, writeWait atomic.Int64 }

func (m *sessionMetrics) wrote(n int, outbound bool, started time.Time) {
	if outbound {
		m.sent.Add(int64(n))
	} else {
		m.received.Add(int64(n))
	}
	m.lastIO.Store(time.Now().UnixMilli())
	wait := time.Since(started).Milliseconds()
	for old := m.writeWait.Load(); wait > old; old = m.writeWait.Load() {
		if m.writeWait.CompareAndSwap(old, wait) {
			break
		}
	}
}
func lifecycleCode(err error) string {
	if err == nil {
		return "OK"
	}
	var p *pairingFailure
	var r *relayFailure
	var secure *secureFailure
	var network net.Error
	switch {
	case errors.Is(err, errLocalCapacity):
		return "LOCAL_CAPACITY_TIMEOUT"
	case errors.As(err, &p):
		return p.code
	case errors.As(err, &r):
		if r.permanent {
			return "RELAY_REJECTED"
		}
		return "RELAY_UNAVAILABLE"
	case errors.Is(err, context.Canceled):
		return "CANCELED"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "TIMEOUT"
	case connectionReset(err):
		return "CONNECTION_RESET"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "TRANSPORT_TRUNCATED"
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return "TRANSPORT_CLOSED"
	case websocket.CloseStatus(err) != -1:
		return "WEBSOCKET_CLOSED"
	case errors.As(err, &secure):
		if secure.reason == "peer certificate verification rejected" {
			return "CERTIFICATE_REJECTED"
		}
		if secure.reason == "transport closed" || secure.reason == "transport interrupted" {
			return "TRANSPORT_CLOSED"
		}
		return "SECURE_TRANSPORT_FAILED"
	default:
		return "SESSION_FAILED"
	}
}

func connectionReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	// Go's Windows networking exposes Winsock errors, not the POSIX errno constants.
	return runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(10054)) || errors.Is(err, syscall.Errno(10053)) || errors.Is(err, syscall.Errno(64)))
}
func reportLifecycle(c *Config, trace, role, event, stage string, err error, elapsed time.Duration, fields map[string]any) {
	if c.Logging == nil || !c.Logging.Enabled || c.Logging.Level == "off" {
		return
	}
	record := transportRecord(trace, role, 1, elapsed, false, nil)
	record.Message = "tunnel " + event
	if err != nil {
		record.Level = "warn"
	}
	if c.Logging.Level == "error" || c.Logging.Level == "warn" && record.Level == "info" {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	fields["role"] = role
	fields["stage"] = stage
	fields["code"] = lifecycleCode(err)
	var relay *relayFailure
	if errors.As(err, &relay) {
		fields["transportStage"], fields["transportReason"], fields["httpStatus"] = relay.stage, relay.reason, relay.status
	}
	var stream *streamFailure
	if errors.As(err, &stream) {
		fields["observedSide"] = stream.side
		fields["operation"] = stream.operation
	}
	fields["elapsedMs"] = elapsed.Milliseconds()
	data, _ := json.Marshal(fields)
	if len(data) > 2048 {
		return
	}
	record.Detail = string(data)
	transportLogs.submitLocal(c.Logging.Endpoint, record, filepath.Join(filepath.Dir(c.path), "transport.log"))
}

// Fixed labels describe where I/O failed, not an inferred network root cause.
type streamFailure struct {
	side, operation string
	cause           error
}

func (e *streamFailure) Error() string { return "stream " + e.side + " " + e.operation + " failed" }
func (e *streamFailure) Unwrap() error { return e.cause }
func streamError(side, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &streamFailure{side: side, operation: operation, cause: err}
}
func sessionReporter(c *Config, paired Paired, role string) func(string, error, *sessionMetrics) {
	started := time.Now()
	reportLifecycle(c, paired.SessionID, role, "paired", "pairing", nil, 0, map[string]any{"requestId": paired.RequestID})
	return func(stage string, err error, m *sessionMetrics) {
		fields := map[string]any{"requestId": paired.RequestID}
		if m != nil {
			fields["sentBytes"] = m.sent.Load()
			fields["receivedBytes"] = m.received.Load()
			fields["maxWriteWaitMs"] = m.writeWait.Load()
			if last := m.lastIO.Load(); last > 0 {
				fields["lastIOMs"] = time.Now().UnixMilli() - last
			}
		}
		reportLifecycle(c, paired.SessionID, role, "closed", stage, err, time.Since(started), fields)
	}
}

// Called only by the asynchronous log worker. Three files, two MiB each.
func appendTransportLog(file string, record transportLogRecord) {
	if file == "" {
		return
	}
	if info, err := os.Stat(file); err == nil && info.Size() >= 2*1024*1024 {
		_ = os.Remove(file + ".2")
		_ = os.Rename(file+".1", file+".2")
		_ = os.Rename(file, file+".1")
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(record)
}

// Embedded SSH has no loopback TCP; observe only encrypted framing byte counts.
type measuredConn struct {
	net.Conn
	metrics *sessionMetrics
}

func (c *measuredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.metrics.received.Add(int64(n))
		c.metrics.lastIO.Store(time.Now().UnixMilli())
	}
	return n, err
}
func (c *measuredConn) Write(p []byte) (int, error) {
	started := time.Now()
	c.Conn.SetWriteDeadline(started.Add(60 * time.Second))
	n, err := c.Conn.Write(p)
	c.Conn.SetWriteDeadline(time.Time{})
	if n > 0 {
		c.metrics.wrote(n, true, started)
	}
	return n, err
}
