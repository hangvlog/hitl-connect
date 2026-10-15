package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/coder/websocket"
)

// Preserve only known protocol reasons. Gateway text and peer-controlled close
// reasons must not appear in diagnostics or turn a policy rejection into retry.
type pairingFailure struct {
	code      string
	retryable bool
	cause     error
}

func (e *pairingFailure) Error() string {
	return fmt.Sprintf("relay could not pair service: %s", e.code)
}
func (e *pairingFailure) Unwrap() error { return e.cause }

func pairingCode(code string) *pairingFailure {
	e := &pairingFailure{code: "PAIRING_PROTOCOL_REJECTED"}
	switch code {
	case "TARGET_OFFLINE", "TARGET_BUSY", "DATA_CHANNEL_UNAVAILABLE":
		e.code, e.retryable = code, true
	case "TARGET_DENIED", "TARGET_DENIED_OR_BUSY", "SERVICE_DENIED", "INVALID_HELLO", "ALREADY_WAITING", "NOT_PAIRED", "HELLO_TIMEOUT", "PAIRING_FAILED", "STALE_GENERATION", "OWNER_ACTIVE", "DUPLICATE_REQUEST", "POOL_FULL", "CONTROL_UNAVAILABLE", "CAPACITY_RESERVED":
		e.code = code
	}
	return e
}

// Subprocess/API serialization loses the Go error type. Recover only the
// allowlisted code, never a peer-controlled reason or an inferred permission.
func pairingFromText(text string) *pairingFailure {
	_, reason, ok := strings.Cut(text, "relay could not pair service:")
	if !ok {
		return nil
	}
	code := strings.Fields(reason)
	if len(code) == 0 {
		return pairingCode("")
	}
	if code[0] == "PAIRING_TRANSPORT_INTERRUPTED" {
		return &pairingFailure{code: code[0], retryable: true}
	}
	return pairingCode(code[0])
}

func pairingError(err error) error {
	e := &pairingFailure{code: "PAIRING_PROTOCOL_REJECTED", cause: err}
	var closed websocket.CloseError
	if errors.As(err, &closed) && closed.Code == websocket.StatusPolicyViolation {
		e = pairingCode(closed.Reason)
		e.cause = err
		return e
	}
	var transport *secureFailure
	if errors.As(secureError("pairing", err), &transport) && transport.retryable {
		e.code, e.retryable = "PAIRING_TRANSPORT_INTERRUPTED", true
	}
	return e
}
