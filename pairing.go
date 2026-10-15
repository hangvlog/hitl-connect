package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// The shared invitation authorizes client certificates for ONE provider service.
// Each device keeps its own private key; the relay receives public certificates only.
type connectionKey struct {
	Relay       string `json:"r"`
	Provider    string `json:"p"`
	Service     string `json:"s"`
	Fingerprint string `json:"f"`
	Seed        string `json:"k"`
	SSHGrant    string `json:"a,omitempty"`
}
type pairingPublic struct {
	Certificate string `json:"certificate"`
	CA          string `json:"caCertificate"`
	ExpiresAt   string `json:"expiresAt"`
}

func certificatePEM(cert []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
}
func parseCA(text string) (*x509.Certificate, error) {
	b, rest := pem.Decode([]byte(text))
	if b == nil || b.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid pairing authority")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || !c.IsCA || c.CheckSignatureFrom(c) != nil || time.Now().Before(c.NotBefore) || !time.Now().Before(c.NotAfter) {
		return nil, errors.New("invalid or expired pairing authority")
	}
	return c, nil
}
func pairingAuthority(service Service) (*x509.Certificate, ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(service.PairingSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("invalid connection key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	ca, err := parseCA(service.PairingCA)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := ca.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		return nil, nil, errors.New("connection key does not match authority")
	}
	return ca, key, nil
}
func invitedTLSConfig(c *Config, peerID string, service Service) (*tls.Config, error) {
	ca, _, err := pairingAuthority(service)
	if err != nil {
		return nil, err
	}
	local, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return nil, errors.New("cannot load device private identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{local},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) < 1 || state.PeerCertificates[0].IsCA {
				return errors.New("invalid invited device certificate")
			}
			return state.PeerCertificates[0].VerifyHostname(peerID)
		}}, nil
}
func exportRegistration(c *Config, output string) error {
	services := []string{}
	allow := []map[string]string{}
	invitations := []map[string]string{}
	for id, service := range c.Services {
		services = append(services, id)
		if service.PairingCA != "" {
			cert, err := os.ReadFile(localPath(c, c.Certificate))
			if err != nil {
				return err
			}
			invitations = append(invitations, map[string]string{"service": id, "caCertificate": service.PairingCA, "certificate": string(cert)})
		}
	}
	slices.Sort(services)
	for id, peer := range c.Peers {
		for _, service := range peer.Services {
			allow = append(allow, map[string]string{"device": id, "service": service})
		}
	}
	digest := sha256.Sum256([]byte(c.Token))
	entry := map[string]any{"id": c.ID, "tokenSha256": hex.EncodeToString(digest[:]), "expiresAt": c.ExpiresAt, "services": services, "allow": allow}
	if len(invitations) != 0 {
		entry["pairing"] = invitations
	}
	return privateJSON(output, entry)
}
func share(c *Config, name, target string) error {
	if name == "" {
		name = "ssh"
	}
	if target == "" {
		target = "127.0.0.1:22"
	}
	if !identifier.MatchString(name) {
		return errors.New("invalid service name")
	}
	address, err := loopback(target)
	if err != nil {
		return err
	}
	service := c.Services[name]
	if service.Target != "" && service.Target != address {
		return errors.New("service already targets a different address")
	}
	service.Target = address
	if service.Allow == nil {
		service.Allow = []string{}
	}
	if service.PairingCA == "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
		expires, _ := time.Parse(time.RFC3339, c.ExpiresAt)
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "hitl-connect invitation"},
			NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true,
			MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return err
		}
		service.PairingCA = certificatePEM(der)
		service.PairingSeed = base64.RawURLEncoding.EncodeToString(key.Seed())
	}
	c.Services[name] = service
	if err := privateJSON(c.path, c); err != nil {
		return err
	}
	public, err := os.ReadFile(localPath(c, c.Certificate))
	if err != nil {
		return err
	}
	cert, err := peerCert(c.ID, string(public))
	if err != nil {
		return err
	}
	pin := sha256.Sum256(cert.Raw)
	invitation := connectionKey{Relay: c.Relay, Provider: c.ID, Service: name, Fingerprint: hex.EncodeToString(pin[:]), Seed: service.PairingSeed}
	// Share is also called during provider startup. Preserve the locally issued
	// SSH authorization token instead of silently replacing it on every launch.
	if old, e := readConnectionKey(localPath(c, "connection-key-"+name+".txt")); e == nil && old.Provider == invitation.Provider && old.Service == invitation.Service && old.Fingerprint == invitation.Fingerprint && old.Seed == invitation.Seed && old.Relay == invitation.Relay {
		invitation.SSHGrant = old.SSHGrant
	}
	encoded, err := json.Marshal(invitation)
	if err != nil {
		return err
	}
	keyPath := localPath(c, "connection-key-"+name+".txt")
	// A text key is deliberately separate from public registration.json.
	if err = privateText(keyPath, "hitl1."+base64.RawURLEncoding.EncodeToString(encoded)+"\n"); err != nil {
		return err
	}
	registration := localPath(c, "registration.json")
	if err = exportRegistration(c, registration); err != nil {
		return err
	}
	fmt.Printf("connectionKeyFile=%s\nregistration=%s\n", keyPath, registration)
	return nil
}
func privateText(path, text string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hitl-connect-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = io.WriteString(f, text)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func readConnectionKey(file string) (connectionKey, error) {
	var text string
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return connectionKey{}, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil {
			return connectionKey{}, err
		}
		text = string(b)
	} else {
		fmt.Fprintln(os.Stderr, "Paste connection key:")
		line, _, err := bufio.NewReaderSize(os.Stdin, 4097).ReadLine()
		if err != nil {
			return connectionKey{}, err
		}
		text = string(line)
	}
	return parseConnectionKey(text)
}
func parseConnectionKey(text string) (connectionKey, error) {
	text = strings.TrimSpace(text)
	if len(text) > 4096 || !strings.HasPrefix(text, "hitl1.") {
		return connectionKey{}, errors.New("invalid connection key")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, "hitl1."))
	if err != nil {
		return connectionKey{}, errors.New("invalid connection key")
	}
	var key connectionKey
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&key) != nil || !identifier.MatchString(key.Provider) || !identifier.MatchString(key.Service) {
		return key, errors.New("invalid connection key")
	}
	seed, err := base64.RawURLEncoding.DecodeString(key.Seed)
	if err != nil || len(seed) != 32 {
		return key, errors.New("invalid connection key")
	}
	pin, err := hex.DecodeString(key.Fingerprint)
	if err != nil || len(pin) != 32 {
		return key, errors.New("invalid connection key")
	}
	if key.SSHGrant != "" && (!validGrantToken(key.SSHGrant) || key.Service != "ssh") {
		return key, errors.New("invalid SSH authorization code")
	}
	_, err = relayURL(&Config{Relay: key.Relay})
	return key, err
}
func enrollmentURL(relay string) (string, error) {
	u, err := relayBaseURL(&Config{Relay: relay})
	if err != nil {
		return "", err
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/enroll"
	return u.String(), nil
}
func enrollmentRequest(endpoint string, value any, result any) error {
	return enrollmentRequestContext(context.Background(), endpoint, value, result)
}
func enrollmentRequestContext(ctx context.Context, endpoint string, value any, result any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return &relayFailure{cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return &relayFailure{cause: err}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&failure)
		return &relayFailure{status: res.StatusCode, code: failure.Code}
	}
	return json.NewDecoder(io.LimitReader(res.Body, 32768)).Decode(result)
}
func join(c *Config, invitation connectionKey) error {
	if c.Relay != invitation.Relay || c.ID == invitation.Provider {
		return errors.New("use a separate identity directory for this provider and relay")
	}
	endpoint, err := enrollmentURL(c.Relay)
	if err != nil {
		return err
	}
	request := map[string]any{"provider": invitation.Provider, "service": invitation.Service}
	var public pairingPublic
	if err = enrollmentRequest(endpoint, request, &public); err != nil {
		return err
	}
	providerCert, err := peerCert(invitation.Provider, public.Certificate)
	if err != nil {
		return err
	}
	pin := sha256.Sum256(providerCert.Raw)
	if hex.EncodeToString(pin[:]) != invitation.Fingerprint {
		return errors.New("provider certificate does not match connection key")
	}
	ca, authority, err := pairingAuthority(Service{PairingCA: public.CA, PairingSeed: invitation.Seed})
	if err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, public.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return errors.New("provider registration expired")
	}
	localExpiry, _ := time.Parse(time.RFC3339, c.ExpiresAt)
	if localExpiry.Before(expires) {
		expires = localExpiry
	}
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	if providerCert.NotAfter.Before(expires) {
		expires = providerCert.NotAfter
	}
	local, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return err
	}
	signer, ok := local.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("invalid device signing key")
	}
	issuedPath := localPath(c, "joined-"+invitation.Provider+"-"+invitation.Service+".crt")
	issued, readErr := os.ReadFile(issuedPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if os.IsNotExist(readErr) {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return err
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: c.ID}, DNSNames: []string{c.ID},
			NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, signer.Public(), authority)
		if err != nil {
			return err
		}
		issued = []byte(certificatePEM(der))
		if err = privateText(issuedPath, string(issued)); err != nil {
			return err
		}
	}
	leaf, err := peerCert(c.ID, string(issued))
	if err != nil || leaf.CheckSignatureFrom(ca) != nil {
		return errors.New("existing enrollment uses a different key; use a new identity directory")
	}
	tokenHash := sha256.Sum256([]byte(c.Token))
	hash := hex.EncodeToString(tokenHash[:])
	message, _ := json.Marshal([]string{"hitl-connect-enroll-v1", invitation.Provider, invitation.Service, c.ID, hash, string(issued)})
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	request["registration"] = map[string]string{"id": c.ID, "tokenSha256": hash, "certificate": string(issued), "signature": base64.StdEncoding.EncodeToString(signature)}
	var registered struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err = enrollmentRequest(endpoint, request, &registered); err != nil {
		return err
	}
	if registered.ID != c.ID {
		return errors.New("unexpected enrollment response")
	}
	if previous, ok := c.Peers[invitation.Provider]; ok && previous.Certificate != public.Certificate {
		return errors.New("provider identity changed; remove old trust explicitly")
	}
	peer := c.Peers[invitation.Provider]
	peer.Certificate = public.Certificate
	if !slices.Contains(peer.Services, invitation.Service) {
		peer.Services = append(peer.Services, invitation.Service)
	}
	if peer.ClientCertificates == nil {
		peer.ClientCertificates = map[string]string{}
	}
	peer.ClientCertificates[invitation.Service] = filepath.Base(issuedPath)
	c.Peers[invitation.Provider] = peer
	if err = privateJSON(c.path, c); err != nil {
		return err
	}
	if invitation.SSHGrant != "" {
		if err = privateText(localPath(c, "ssh-grant.txt"), invitation.SSHGrant); err != nil {
			return err
		}
	}
	fmt.Printf("joined=%s service=%s\nconfiguration=%s\nRun connect with this config, then use SSH on 127.0.0.1:2222.\n", invitation.Provider, invitation.Service, c.path)
	return nil
}
func pairingCommand(command, config, dir, relay, service, target, keyFile string) error {
	var invitation connectionKey
	var err error
	if command == "join" {
		invitation, err = readConnectionKey(keyFile)
		if err != nil {
			return err
		}
		relay = invitation.Relay
	}
	if dir != "" {
		config = filepath.Join(dir, "config.json")
	}
	if _, err = os.Stat(config); os.IsNotExist(err) {
		if dir == "" {
			return errors.New("first use requires --dir for the private device identity")
		}
		if relay == "" {
			relay, err = localProviderRelay(dir)
			if err != nil {
				return err
			}
		}
		if err = initialize("", dir, relay); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	c, err := load(config)
	if err != nil {
		return err
	}
	if command == "share" {
		return share(c, service, target)
	}
	return join(c, invitation)
}

func registerProvider(ctx context.Context, c *Config) error {
	file := localPath(c, "registration.json")
	if err := exportRegistration(c, file); err != nil {
		return err
	}
	var registration struct {
		ID          string              `json:"id"`
		TokenSha256 string              `json:"tokenSha256"`
		ExpiresAt   string              `json:"expiresAt"`
		Services    []string            `json:"services"`
		Allow       []map[string]string `json:"allow"`
		Pairing     []struct {
			Service     string `json:"service"`
			CA          string `json:"caCertificate"`
			Certificate string `json:"certificate"`
		} `json:"pairing"`
	}
	if err := readJSON(file, &registration); err != nil {
		return err
	}
	// Self-service registration grants only this device's own services, never
	// caller-selected access to any other device or administrator privileges.
	registration.Allow = []map[string]string{}
	local, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return err
	}
	certificate, err := os.ReadFile(localPath(c, c.Certificate))
	if err != nil {
		return err
	}
	signer, ok := local.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("invalid device signing key")
	}
	version := time.Now().UnixMilli()
	invitations := [][3]string{}
	for _, item := range registration.Pairing {
		invitations = append(invitations, [3]string{item.Service, item.CA, item.Certificate})
	}
	message, _ := json.Marshal([]any{"hitl-connect-provider-v1", version, c.ID, registration.TokenSha256, registration.ExpiresAt,
		string(certificate), registration.Services, invitations})
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	endpoint, err := enrollmentURL(c.Relay)
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if err = enrollmentRequestContext(ctx, endpoint+"/provider", map[string]any{"certificate": string(certificate), "version": version,
		"registration": registration, "signature": base64.StdEncoding.EncodeToString(signature)}, &result); err != nil {
		return err
	}
	if result.ID != c.ID {
		return errors.New("unexpected registration response")
	}
	return nil
}

func quickStart(ctx context.Context, command, config, dir, relay, service, target, keyFile, peerID, bind, account string) error {
	if dir == "" && config == "config.json" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		role := "client"
		if command == "host" {
			role = "provider"
		}
		dir = filepath.Join(base, "hitl-connect", role)
	}
	if dir != "" {
		config = filepath.Join(dir, "config.json")
	}
	if command == "host" {
		if target == "" {
			target = "127.0.0.1:22"
		}
		if service == "" {
			service = "ssh"
		}
		address, err := loopback(target)
		if err != nil {
			return err
		}
		if account == "" && service == "ssh" {
			saved, e := savedHostAccount(filepath.Dir(config))
			if e == nil {
				account, address = saved.User, saved.Address
				target = address
			} else if !os.IsNotExist(e) {
				return e
			}
		}
		if account != "" {
			if service != "ssh" {
				return errors.New("SSH_SERVICE_REQUIRED")
			}
			saved, e := readHostAuthorization(filepath.Dir(config))
			if e == nil && saved.Engine == "embedded" && (saved.User != account || saved.Address != address) {
				return errors.New("HOST_SCOPE_FIXED")
			}
			if runtime.GOOS == "windows" && e != nil {
				return errors.New("HOST_SETUP_REQUIRED: use agent allow or install-host to authorize embedded SSH")
			}
			if e != nil || saved.User != account || saved.Address != address {
				address, err = prepareAllowedSSH(ctx, account, address)
				if err != nil {
					return err
				}
				if err = saveHostAuthorization(filepath.Dir(config), account, address); err != nil {
					return err
				}
			}
			target = address
		}
		_, embedded := embeddedPolicy(filepath.Dir(config))
		if !embedded {
			probe, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return fmt.Errorf("local service %s is not running; start the SSH server or specify --target", address)
			}
			probe.Close()
		}
		if err = pairingCommand("share", config, dir, relay, service, target, ""); err != nil {
			return err
		}
		c, err := load(config)
		if err != nil {
			return err
		}
		if embedded {
			c.embedded, err = loadEmbeddedSSH(filepath.Dir(config))
			if err != nil {
				return err
			}
		}
		if err = registerProviderUntilAvailable(ctx, c); err != nil {
			return err
		}
		if account != "" {
			c.sshAccount = account
			if err = ensureSSHGrant(c, account); err != nil {
				return err
			}
		}
		key, err := os.ReadFile(localPath(c, "connection-key-"+service+".txt"))
		if err != nil {
			return err
		}
		fmt.Printf("Ready. Paste this connection key on the other computer (keep it private):\n%s", key)
		c.recovery = &enrollmentRecovery{}
		return serve(ctx, c)
	}
	_, statErr := os.Stat(config)
	if os.IsNotExist(statErr) || keyFile != "" {
		if err := pairingCommand("join", config, dir, "", "", "", keyFile); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	}
	c, err := load(config)
	if err != nil {
		return err
	}
	// A failed first enrollment leaves an identity for safe retry, not a working connection.
	if len(c.Peers) == 0 {
		if err = pairingCommand("join", config, "", "", "", "", keyFile); err != nil {
			return err
		}
		c, err = load(config)
		if err != nil {
			return err
		}
	}
	if peerID == "" && len(c.Peers) == 1 {
		for id := range c.Peers {
			peerID = id
		}
	}
	if service == "" && len(c.Peers[peerID].Services) == 1 {
		service = c.Peers[peerID].Services[0]
	}
	c.recovery = &enrollmentRecovery{}
	return forward(ctx, c, peerID, service, bind)
}
