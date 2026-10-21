package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

func openRelay(ctx context.Context, c *Config, endpoint string) (*websocket.Conn, error) {
	// Keep room for a second attempt within the existing 15-second caller
	// budget. The provider also benefits from quicker recovery of a stalled dial.
	timeout := 4 * time.Second
	if c.Protocol == "v3" {
		timeout = 8 * time.Second
		if len(c.Services) > 0 {
			timeout = 10 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stage atomic.Value
	stage.Store("websocket")
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { stage.Store("dns") },
		ConnectStart:      func(string, string) { stage.Store("tcp") },
		TLSHandshakeStart: func() { stage.Store("tls") },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				stage.Store("websocket")
			}
		},
	}
	ws, response, err := websocket.Dial(httptrace.WithClientTrace(ctx, trace), endpoint, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.Token}, "X-Connect-Local-Ips": {strings.Join(localAddresses(), ",")}}, CompressionMode: websocket.CompressionDisabled,
	})
	if err == nil {
		return ws, nil
	}
	failure := &relayFailure{stage: stage.Load().(string), cause: err, reason: "transport interrupted"}
	if response != nil {
		failure.status = response.StatusCode
		failure.stage, failure.reason = "websocket", "HTTP response rejected"
	}
	var verification *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.As(err, &verification):
		failure.reason, failure.permanent = "certificate verification rejected", true
	case errors.Is(err, context.Canceled):
		failure.reason, failure.permanent = "operation canceled", true
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		failure.reason = "transport timed out"
	}
	return nil, failure
}
