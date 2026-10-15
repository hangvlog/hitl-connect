package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Configured per existing profile; no credentials or device identifiers are
// sent. A bounded asynchronous queue isolates telemetry from tunnel traffic.
type transportLogSettings struct {
	Endpoint string `json:"endpoint"`
	Enabled  bool   `json:"enabled"`
	Level    string `json:"level,omitempty"`
}
type transportLogRecord struct {
	Level      string `json:"level"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	Message    string `json:"message"`
	Detail     string `json:"detail"`
	SessionID  string `json:"sessionId"`
	AppVersion string `json:"appVersion"`
	DeviceInfo string `json:"deviceInfo"`
	ClientTime int64  `json:"clientTime"`
}
type transportLogJob struct {
	endpoint string
	record   transportLogRecord
	local    string
}
type transportLogSink struct {
	once  sync.Once
	queue chan transportLogJob
}

var transportLogs = &transportLogSink{queue: make(chan transportLogJob, 32)}

func newTransportTrace() string { return "connect-" + rand.Text() }

func transportRecord(trace, role string, attempt int, elapsed time.Duration, retry bool, err error) transportLogRecord {
	detail := map[string]any{"role": role, "attempt": attempt, "elapsedMs": elapsed.Milliseconds(), "retry": retry}
	message, level := "relay connection recovered", "info"
	if err != nil {
		message, level = "relay connection failed", "warn"
		var pairing *pairingFailure
		var relay *relayFailure
		switch {
		case errors.As(err, &pairing):
			detail["stage"], detail["code"] = "pairing", pairing.code
		case errors.As(err, &relay):
			detail["stage"], detail["reason"], detail["httpStatus"] = relay.stage, relay.reason, relay.status
		default:
			detail["code"] = "CONNECTION_REJECTED"
		}
	}
	data, _ := json.Marshal(detail)
	version := strings.SplitN(guiVersion, "+", 2)[0]
	if len(version) > 32 {
		version = version[:32]
	}
	return transportLogRecord{level, "custom", "hitl-connect", message, string(data), trace, version, runtime.GOOS + "/" + runtime.GOARCH, time.Now().UnixMilli()}
}

func reportTransport(c *Config, trace, role string, attempt int, elapsed time.Duration, retry bool, err error) {
	if c.Logging == nil || !c.Logging.Enabled {
		return
	}
	record := transportRecord(trace, role, attempt, elapsed, retry, err)
	if c.Logging.Level == "off" || c.Logging.Level == "error" || c.Logging.Level == "warn" && record.Level == "info" {
		return
	}
	transportLogs.submitLocal(c.Logging.Endpoint, record, filepath.Join(filepath.Dir(c.path), "transport.log"))
}

func (s *transportLogSink) submit(endpoint string, record transportLogRecord) {
	s.submitLocal(endpoint, record, "")
}
func (s *transportLogSink) submitLocal(endpoint string, record transportLogRecord, local string) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/front/client-log/report" {
		return
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return
	}
	s.once.Do(func() { go s.run() })
	select {
	case s.queue <- transportLogJob{endpoint: endpoint, record: record, local: local}:
	default:
	}
}

func (s *transportLogSink) run() {
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Bounded aggregation state. Active tunnel I/O never waits for this worker.
	type repeated struct {
		at    time.Time
		count int
	}
	recent := map[string]repeated{}
	for job := range s.queue {
		if job.record.Level == "warn" && job.record.Message != "tunnel closed" {
			var detail map[string]any
			_ = json.Unmarshal([]byte(job.record.Detail), &detail)
			key := job.endpoint + job.local + job.record.Message + fmt.Sprint(detail["role"], detail["stage"], detail["code"])
			old := recent[key]
			if time.Since(old.at) < time.Minute {
				old.count++
				recent[key] = old
				continue
			}
			if old.count > 0 {
				detail["suppressedCount"] = old.count
				data, _ := json.Marshal(detail)
				job.record.Detail = string(data)
			}
			if len(recent) >= 128 {
				clear(recent)
			}
			recent[key] = repeated{at: time.Now()}
		}
		appendTransportLog(job.local, job.record)
		data, _ := json.Marshal(job.record)
		response, err := client.Post(job.endpoint, "application/json", bytes.NewReader(data))
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			response.Body.Close()
		}
		// No recursive logging or retry on report failure.
	}
}
