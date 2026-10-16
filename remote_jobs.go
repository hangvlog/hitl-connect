package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var jobID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

type jobRequest struct {
	Action         string `json:"action"`
	ID             string `json:"id"`
	Command        string `json:"command,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	Offset         int64  `json:"offset,omitempty"`
	Stream         string `json:"stream,omitempty"`
}
type jobRecord struct {
	ID         string     `json:"id"`
	Hash       string     `json:"requestHash"`
	State      string     `json:"state"`
	ExitCode   *int       `json:"exitCode,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}
type jobReply struct {
	OK         bool       `json:"ok"`
	Code       string     `json:"code"`
	Job        *jobRecord `json:"job,omitempty"`
	Data       []byte     `json:"data,omitempty"`
	NextOffset int64      `json:"nextOffset,omitempty"`
}
type workerIO interface {
	io.Reader
	io.Writer
	Stderr() io.ReadWriter
}
type jobStreams struct {
	io.Reader
	io.Writer
	err io.ReadWriter
}

func (s jobStreams) Stderr() io.ReadWriter { return s.err }

type boundedJobOutput struct {
	file      *os.File
	remaining int64
}

func (w *boundedJobOutput) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("JOB_OUTPUT_LIMIT")
	}
	n, err := w.file.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type jobRun struct {
	cancel context.CancelFunc
	record jobRecord
}
type jobManager struct {
	mu      sync.Mutex
	root    string
	ctx     context.Context
	active  map[string]*jobRun
	runtime *providerRuntime
	run     func(context.Context, string, workerIO) (int, error)
}

func newJobManager(ctx context.Context, root string, runtime *providerRuntime, run func(context.Context, string, workerIO) (int, error)) *jobManager {
	return &jobManager{root: root, ctx: ctx, runtime: runtime, active: map[string]*jobRun{}, run: run}
}

// Owner includes the authenticated device and SSH key. Request IDs are scoped
// to that owner and never used as arbitrary paths or automatically replayed.
func (m *jobManager) request(owner string, r jobRequest, authorized func() bool) jobReply {
	if !jobID.MatchString(r.ID) || r.Offset < 0 {
		return jobReply{Code: "INVALID_JOB_REQUEST"}
	}
	digest := sha256.Sum256([]byte(owner))
	directory := filepath.Join(m.root, hex.EncodeToString(digest[:]), r.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !authorized() {
		return jobReply{Code: "JOB_ACCESS_REVOKED"}
	}
	recordFile := filepath.Join(directory, "status.json")
	var record jobRecord
	err := readJSON(recordFile, &record)
	active := m.active[directory]
	if active != nil {
		record = active.record
		err = nil
	}
	if r.Action == "submit" {
		if len(r.Command) == 0 || len(r.Command) > 32768 || r.TimeoutSeconds < 1 || r.TimeoutSeconds > 86400 {
			return jobReply{Code: "INVALID_JOB_REQUEST"}
		}
		encoded, _ := json.Marshal(struct {
			Command string
			Timeout int
		}{r.Command, r.TimeoutSeconds})
		hash := sha256.Sum256(encoded)
		requestHash := hex.EncodeToString(hash[:])
		if err == nil {
			if record.Hash != requestHash {
				return jobReply{Code: "JOB_ID_CONFLICT"}
			}
			if active == nil && record.State == "running" {
				record.State = "interrupted"
				_ = privateJSON(recordFile, record)
			}
			return jobReply{OK: true, Code: "EXISTING", Job: &record}
		}
		if !os.IsNotExist(err) {
			return jobReply{Code: "JOB_STATE_UNAVAILABLE"}
		}
		entries, listErr := os.ReadDir(filepath.Dir(directory))
		if listErr != nil && !os.IsNotExist(listErr) {
			return jobReply{Code: "JOB_STORAGE_UNAVAILABLE"}
		}
		if len(entries) >= 256 {
			return jobReply{Code: "JOB_HISTORY_FULL"}
		}
		if len(m.active) >= 32 {
			return jobReply{Code: "JOB_CAPACITY_FULL"}
		}
		if m.runtime != nil && !m.runtime.begin() {
			return jobReply{Code: "PROVIDER_DRAINING"}
		}
		release := func() {
			if m.runtime != nil {
				m.runtime.end()
			}
		}
		if err = os.MkdirAll(directory, 0700); err != nil {
			release()
			return jobReply{Code: "JOB_STORAGE_UNAVAILABLE"}
		}
		record = jobRecord{ID: r.ID, Hash: requestHash, State: "running", StartedAt: time.Now().UTC()}
		if err = privateJSON(recordFile, record); err != nil {
			release()
			return jobReply{Code: "JOB_STORAGE_UNAVAILABLE"}
		}
		ctx, cancel := context.WithTimeout(m.ctx, time.Duration(r.TimeoutSeconds)*time.Second)
		job := &jobRun{cancel: cancel, record: record}
		m.active[directory] = job
		go m.execute(ctx, job, directory, r.Command, authorized, release)
		copy := record
		return jobReply{OK: true, Code: "ACCEPTED", Job: &copy}
	}
	if err != nil {
		return jobReply{Code: "JOB_NOT_FOUND"}
	}
	if active == nil && record.State == "running" {
		record.State = "interrupted"
		_ = privateJSON(recordFile, record)
	}
	switch r.Action {
	case "status":
		return jobReply{OK: true, Code: "STATUS", Job: &record}
	case "cancel":
		if active != nil {
			active.cancel()
		}
		return jobReply{OK: true, Code: "CANCEL_REQUESTED", Job: &record}
	case "logs":
		if r.Stream != "stdout" && r.Stream != "stderr" {
			return jobReply{Code: "INVALID_JOB_STREAM"}
		}
		f, e := os.Open(filepath.Join(directory, r.Stream+".log"))
		if e != nil {
			return jobReply{Code: "JOB_LOG_UNAVAILABLE"}
		}
		defer f.Close()
		if _, e = f.Seek(r.Offset, io.SeekStart); e != nil {
			return jobReply{Code: "INVALID_JOB_OFFSET"}
		}
		data, e := io.ReadAll(io.LimitReader(f, 65536))
		if e != nil {
			return jobReply{Code: "JOB_LOG_UNAVAILABLE"}
		}
		return jobReply{OK: true, Code: "LOGS", Job: &record, Data: data, NextOffset: r.Offset + int64(len(data))}
	default:
		return jobReply{Code: "INVALID_JOB_ACTION"}
	}
}
func (m *jobManager) execute(ctx context.Context, job *jobRun, directory, command string, authorized func() bool, release func()) {
	defer release()
	defer job.cancel()
	stdout, e1 := os.OpenFile(filepath.Join(directory, "stdout.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	stderr, e2 := os.OpenFile(filepath.Join(directory, "stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	exit, err := 1, errors.New("JOB_LOG_UNAVAILABLE")
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !authorized() {
					job.cancel()
					return
				}
			}
		}
	}()
	if e1 == nil && e2 == nil {
		out := &boundedJobOutput{stdout, 64 << 20}
		er := &boundedJobOutput{stderr, 64 << 20}
		exit, err = m.run(ctx, command, jobStreams{Reader: bytes.NewReader(nil), Writer: out, err: struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(nil), er}})
	}
	if stdout != nil {
		stdout.Close()
	}
	if stderr != nil {
		stderr.Close()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record := job.record
	record.State = "completed"
	record.ExitCode = &exit
	if err != nil || exit != 0 {
		record.State = "failed"
	}
	if ctx.Err() != nil {
		record.State = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			record.State = "timed_out"
		}
	}
	now := time.Now().UTC()
	record.FinishedAt = &now
	// Keep in-memory terminal evidence when disk writes fail; never run again.
	if privateJSON(filepath.Join(directory, "status.json"), record) != nil {
		job.record = record
		return
	}
	delete(m.active, directory)
}
