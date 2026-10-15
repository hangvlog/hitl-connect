package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/coder/websocket"
)

// Preserve the cause for classification without displaying peer-controlled
// certificate names, WebSocket close reasons or transport URLs.
type secureFailure struct {
	stage, reason string
	retryable     bool
	cause         error
}

func (e *secureFailure) Error() string {
	return fmt.Sprintf("end-to-end %s failed: %s", e.stage, e.reason)
}
func (e *secureFailure) Unwrap() error { return e.cause }

func secureError(stage string, err error) error {
	e := &secureFailure{stage: stage, reason: "TLS or service verification rejected", cause: err}
	var verification *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &verification) || errors.As(err, &invalid) || errors.As(err, &authority) || errors.As(err, &hostname) {
		e.reason = "peer certificate verification rejected"
		return e
	}
	var closed websocket.CloseError
	if errors.As(err, &closed) {
		switch closed.Code {
		case websocket.StatusNormalClosure, websocket.StatusGoingAway, websocket.StatusAbnormalClosure,
			websocket.StatusInternalError, websocket.StatusServiceRestart, websocket.StatusTryAgainLater:
			e.reason, e.retryable = "transport closed", true
		default:
			e.reason = "relay policy or protocol rejected"
		}
		return e
	}
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		e.reason = "operation canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		e.reason, e.retryable = "transport timed out", true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrClosedPipe):
		e.reason, e.retryable = "transport interrupted", true
	}
	return e
}
