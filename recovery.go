package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Only protocol codes we recognize are displayed. Never echo a gateway's body,
// a URL containing credentials, or an untrusted WebSocket close reason.
type relayFailure struct {
	status        int
	code          string
	stage, reason string
	permanent     bool
	cause         error
	retryAfter    time.Duration
}

func (e *relayFailure) Unwrap() error { return e.cause }

func (e *relayFailure) Error() string {
	detail := "relay request rejected"
	switch e.code {
	case "TUNNEL_INVITATION_UNAVAILABLE":
		detail = "provider registration or invitation unavailable; the provider must reconnect (SSH login has not started)"
	case "TUNNEL_DEVICE_REVOKED":
		detail = "device access was revoked; automatic registration cannot restore it"
	case "TUNNEL_DEVICE_EXISTS", "TUNNEL_CREDENTIAL_CONFLICT":
		detail = "existing registration conflicts with this identity; preserve the identity directory and check the relay"
	case "TUNNEL_DEVICE_CAPACITY":
		detail = "relay device capacity reached"
	case "TUNNEL_ENROLLMENT_PROOF_INVALID", "TUNNEL_PROVIDER_PROOF_INVALID":
		detail = "registration proof rejected; check certificate validity and system time"
	default:
		switch {
		case e.status == 0:
			detail = "relay unreachable; check network and HTTPS connectivity"
		case e.status == http.StatusUnauthorized:
			detail = "device registration not accepted by relay"
		case e.status == http.StatusTooManyRequests:
			detail = "relay capacity or request limit reached; wait before retrying"
		case e.status >= 500:
			detail = "relay service unavailable; wait for recovery (changing keys will not help)"
		}
	}
	if e.stage != "" {
		detail += "; " + e.stage + ": " + e.reason
	}
	return fmt.Sprintf("%s (HTTP %d)", detail, e.status)
}

func retryableEnrollment(err error) bool {
	var failure *relayFailure
	return errors.As(err, &failure) && (failure.status == 0 || failure.status >= 500 || failure.status == 429)
}

// Serialize recovery across concurrent connections without changing any saved
// credential. Manual serve/forward configurations do not opt into self enrollment.
type enrollmentRecovery struct {
	once sync.Once
	gate chan struct{}
}

func (r *enrollmentRecovery) lock(ctx context.Context) error {
	r.once.Do(func() { r.gate = make(chan struct{}, 1) })
	select {
	case r.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *enrollmentRecovery) unlock() { <-r.gate }

func connect(ctx context.Context, c *Config, hello Hello) (wsResult *websocket.Conn, pairedResult Paired, result error) {
	defer func() { result = budgetFor(c, "ssh").result(result, ctx) }()
	// Retry only before a pair exists: no TLS, SSH or application bytes have
	// been sent. Live sessions and commands are never replayed. The caller's
	// deadline bounds the total wait, including the relay's 5-second windows.
	trace, started := newTransportTrace(), time.Now()
	maxAttempts := 3
	if c.Protocol == "v3" {
		maxAttempts = 2
		if hello.Role == "dial" && hello.RequestID == "" {
			hello.RequestID = trace
		}
	}
	for attempt := 1; ; attempt++ {
		ws, paired, err := connectOnce(ctx, c, hello)
		var failure *pairingFailure
		var relay *relayFailure
		retryable := errors.As(err, &failure) && failure.retryable || errors.As(err, &relay) && !relay.permanent && (relay.status == 0 || relay.status == 429 || relay.status >= 500)
		retry := hello.Role == "dial" && attempt < maxAttempts && retryable && ctx.Err() == nil
		if err != nil || attempt > 1 {
			reportTransport(c, trace, hello.Role, attempt, time.Since(started), retry, err)
		}
		if !retry {
			if err == nil {
				if paired.RequestID == "" {
					paired.RequestID = trace
				}
				if deadline, ok := ctx.Deadline(); ok && hello.Role == "dial" {
					paired.deadline = deadline
				}
			}
			return ws, paired, err
		}
		select {
		case <-ctx.Done():
			return nil, Paired{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func connectOnce(ctx context.Context, c *Config, hello Hello) (*websocket.Conn, Paired, error) {
	ws, paired, err := dialRelay(ctx, c, hello)
	var failure *relayFailure
	if c.recovery == nil || !errors.As(err, &failure) || failure.status != http.StatusUnauthorized || ctx.Err() != nil {
		return ws, paired, err
	}
	if err = c.recovery.lock(ctx); err != nil {
		return nil, Paired{}, err
	}
	if ctx.Err() != nil {
		c.recovery.unlock()
		return nil, Paired{}, ctx.Err()
	}
	if hello.Role == "accept" || hello.Role == "control" {
		err = registerProvider(ctx, c)
	} else {
		err = restoreCaller(ctx, c, hello.Target, hello.Service)
	}
	c.recovery.unlock()
	if err != nil {
		return nil, Paired{}, fmt.Errorf("registration recovery failed: %w", err)
	}
	fmt.Fprintln(os.Stderr, "relay registration restored with existing identity")
	return dialRelay(ctx, c, hello)
}

// The existing service certificate plus proof of its private key is sufficient
// to restore a lost caller registration. No invitation seed or new identity is
// needed. The server still enforces CA, expiry, scope and revocation checks.
func restoreCaller(ctx context.Context, c *Config, provider, service string) (result error) {
	parent := ctx
	budget := budgetFor(c, "ssh")
	limited, cancel, err := budget.attempt(ctx)
	if err != nil {
		return err
	}
	ctx = limited
	defer cancel()
	defer func() { result = budget.result(result, parent) }()
	peer, ok := c.Peers[provider]
	if !ok || peer.ClientCertificates[service] == "" {
		return errors.New("no saved service enrollment; use the original manual registration procedure")
	}
	endpoint, err := enrollmentURL(c.Relay)
	if err != nil {
		return err
	}
	var public pairingPublic
	if err = enrollmentRequestContext(ctx, endpoint, map[string]string{"provider": provider, "service": service}, &public); err != nil {
		return err
	}
	trusted, err := peerCert(provider, peer.Certificate)
	if err != nil {
		return err
	}
	current, err := peerCert(provider, public.Certificate)
	if err != nil || !bytes.Equal(trusted.Raw, current.Raw) {
		return errors.New("provider identity changed; refusing automatic recovery")
	}
	ca, err := parseCA(public.CA)
	if err != nil {
		return err
	}
	issued, err := os.ReadFile(localPath(c, peer.ClientCertificates[service]))
	if err != nil {
		return err
	}
	leaf, err := peerCert(c.ID, string(issued))
	if err != nil || leaf.CheckSignatureFrom(ca) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return errors.New("saved service certificate expired or authority changed; automatic recovery stopped")
	}
	return registerCaller(ctx, c, provider, service, string(issued))
}

func registerCaller(ctx context.Context, c *Config, provider, service, issued string) error {
	local, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return err
	}
	signer, ok := local.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("invalid device signing key")
	}
	leaf, err := peerCert(c.ID, issued)
	if err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return errors.New("saved service certificate does not match the device private key")
	}
	tokenHash := sha256.Sum256([]byte(c.Token))
	hash := hex.EncodeToString(tokenHash[:])
	message, _ := json.Marshal([]string{"hitl-connect-enroll-v1", provider, service, c.ID, hash, issued})
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	endpoint, err := enrollmentURL(c.Relay)
	if err != nil {
		return err
	}
	var registered struct {
		ID string `json:"id"`
	}
	err = enrollmentRequestContext(ctx, endpoint, map[string]any{"provider": provider, "service": service,
		"registration": map[string]string{"id": c.ID, "tokenSha256": hash, "certificate": issued,
			"signature": base64.StdEncoding.EncodeToString(signature)}}, &registered)
	if err != nil {
		return err
	}
	if registered.ID != c.ID {
		return errors.New("unexpected enrollment response")
	}
	return nil
}

func registerProviderUntilAvailable(ctx context.Context, c *Config) error {

	budget := budgetFor(c, "ssh")
	for {
		err := registerProvider(ctx, c)
		if err == nil || !retryableEnrollment(err) {
			return err
		}
		wait := retryMinimum()
		fmt.Fprintf(os.Stderr, "%v; retrying with saved backoff\n", err)
		if err := budget.wait(ctx, wait); err != nil {
			return err
		}
	}
}
