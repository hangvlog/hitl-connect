package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// Established before UAC or filesystem setup. The child can report even when
// creating the installation directory fails. No elevated writes to caller paths.
type installResultReceiver struct {
	URL, Token string
	reports    chan installerReport
	server     *http.Server
	once       sync.Once
}

func newInstallResultReceiver() (*installResultReceiver, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &installResultReceiver{URL: "http://" + listener.Addr().String() + "/install-result", Token: hex.EncodeToString(token), reports: make(chan installerReport, 1)}
	r.server = &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/install-result" {
			http.NotFound(w, req)
			return
		}
		if subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+r.Token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var result installerReport
		d := json.NewDecoder(http.MaxBytesReader(w, req.Body, 8192))
		d.DisallowUnknownFields()
		if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Schema != "hitl-connect.install.v1" || !regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`).MatchString(result.Stage) || !regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(result.Code) || result.Message == "" || len(result.Message) > 4096 {
			http.Error(w, "invalid report", 400)
			return
		}
		accepted := false
		r.once.Do(func() { r.reports <- result; accepted = true })
		if accepted {
			w.WriteHeader(204)
		} else {
			http.Error(w, "already reported", 409)
		}
	})}
	go func() { _ = r.server.Serve(listener) }()
	return r, nil
}
func (r *installResultReceiver) Close() { _ = r.server.Close() }
func (r *installResultReceiver) Result() *installerReport {
	select {
	case report := <-r.reports:
		return &report
	default:
		return nil
	}
}
func sendInstallReport(endpoint, token string, report installerReport) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "/install-result" || u.RawQuery != "" || u.Fragment != "" || len(token) != 64 {
		return errors.New("INSTALL_REPORT_ENDPOINT_INVALID")
	}
	if _, err = hex.DecodeString(token); err != nil {
		return errors.New("INSTALL_REPORT_TOKEN_INVALID")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	// Explicit loopback-only transport; never use environment proxies or redirects.
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		return errors.New("INSTALL_REPORT_REJECTED")
	}
	return nil
}
