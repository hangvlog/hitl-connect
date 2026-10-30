// hitl-connect exposes explicit loopback TCP services through an opaque relay.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

const maxChunk = 32768

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

type Identity struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
}
type Peer struct {
	Certificate        string            `json:"certificate"`
	Services           []string          `json:"services"`
	ClientCertificates map[string]string `json:"clientCertificates,omitempty"`
}
type Service struct {
	Target      string   `json:"target"`
	Allow       []string `json:"allow"`
	PairingCA   string   `json:"pairingCa,omitempty"`
	PairingSeed string   `json:"pairingSeed,omitempty"`
}
type Config struct {
	ID           string             `json:"id"`
	Relay        string             `json:"relay"`
	Token        string             `json:"token"`
	ExpiresAt    string             `json:"expiresAt"`
	Certificate  string             `json:"certificateFile"`
	Key          string             `json:"keyFile"`
	Peers        map[string]Peer    `json:"peers"`
	Services     map[string]Service `json:"services"`
	path         string
	runtime      *providerRuntime
	recovery     *enrollmentRecovery
	embedded     *embeddedSSH
	sshAccount   string                // fixed by local allow action; never read from mutable profile JSON
	Logging      *transportLogSettings `json:"logging,omitempty"`
	Protocol     string                `json:"protocol,omitempty"`
	IdleChannels int                   `json:"idleChannels,omitempty"`
	Capacity     capacitySettings      `json:"capacity,omitempty"`
}
type Hello struct {
	Role       string `json:"role"`
	Target     string `json:"target,omitempty"`
	Service    string `json:"service,omitempty"`
	InstanceID string `json:"instanceId,omitempty"`
	Generation string `json:"generation,omitempty"`
	RequestID  string `json:"requestId,omitempty"`
}
type Paired struct {
	State       string `json:"state"`
	Peer        string `json:"peer"`
	Service     string `json:"service"`
	SessionID   string `json:"sessionId"`
	RequestID   string `json:"requestId,omitempty"`
	Ready       bool   `json:"ready,omitempty"`
	deadline    time.Time
	stopHealthy func() // v2 waiting-slot uptime transfers to the paired session
}

func privateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".hitl-connect-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.DisallowUnknownFields()
	if err = d.Decode(value); err != nil {
		return errors.New("invalid configuration JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("unexpected trailing configuration")
	}
	return nil
}
func load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c := &Config{path: abs}
	if err = readJSON(abs, c); err != nil {
		return nil, err
	}
	if !identifier.MatchString(c.ID) || len(c.Token) != 64 {
		return nil, errors.New("invalid device identity or token")
	}
	if _, err = hex.DecodeString(c.Token); err != nil {
		return nil, errors.New("invalid device token")
	}
	expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return nil, errors.New("device enrollment expired")
	}
	if c.Protocol != "" && c.Protocol != "v2" && c.Protocol != "v3" {
		return nil, errors.New("unsupported protocol")
	}
	if c.IdleChannels < 0 || c.IdleChannels > 16 {
		return nil, errors.New("idleChannels must be 1-16 or omitted")
	}
	if err = c.validateCapacity(); err != nil {
		return nil, err
	}
	if c.Peers == nil {
		c.Peers = map[string]Peer{}
	}
	if c.Services == nil {
		c.Services = map[string]Service{}
	}
	if _, err = relayURL(c); err != nil {
		return nil, err
	}
	for id, peer := range c.Peers {
		if !identifier.MatchString(id) {
			return nil, errors.New("invalid peer name")
		}
		if _, err = peerCert(id, peer.Certificate); err != nil {
			return nil, err
		}
		for _, service := range peer.Services {
			if !identifier.MatchString(service) {
				return nil, errors.New("invalid service name")
			}
		}
	}
	for id, service := range c.Services {
		if !identifier.MatchString(id) || (len(service.Allow) == 0 && service.PairingCA == "") {
			return nil, errors.New("service needs a name and explicit peers")
		}
		if service.PairingCA != "" {
			if _, _, err := pairingAuthority(service); err != nil {
				return nil, err
			}
		}
		if _, err = loopback(service.Target); err != nil {
			return nil, err
		}
		for _, peer := range service.Allow {
			if _, ok := c.Peers[peer]; !ok {
				return nil, errors.New("service authorizes an untrusted peer")
			}
		}
	}
	return c, nil
}
func loopback(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("address must be loopback-host:port")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("only explicit loopback addresses are supported")
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid TCP port")
	}
	return net.JoinHostPort(host, fmt.Sprint(n)), nil
}
func relayBaseURL(c *Config) (*url.URL, error) {
	u, err := url.Parse(c.Relay)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid relay URL")
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("relay requires HTTPS; plaintext is limited to loopback tests")
		}
		u.Scheme = "ws"
	default:
		return nil, errors.New("relay requires HTTPS")
	}
	return u, nil
}
func relayURL(c *Config) (string, error) {
	u, err := relayBaseURL(c)
	if err != nil {
		return "", err
	}
	// Gateways may expose enrollment and WebSocket traffic under different paths.
	// This path convention does not embed any deployment hostname.
	if strings.TrimRight(u.Path, "/") == "/hitl/device-tunnel" {
		u.Path = "/hitl/local-http-relay/connect/hitl-connect/" + protocolVersion(c) + "/session"
		return u.String(), nil
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/connect/" + protocolVersion(c) + "/session"
	return u.String(), nil
}
func peerCert(id, text string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid peer certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.VerifyHostname(id) != nil {
		return nil, errors.New("peer certificate does not match device")
	}
	return cert, nil
}
func localPath(c *Config, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(c.path), path)
}
func tlsConfig(c *Config, peerID, service string, accepting bool) (*tls.Config, error) {
	peer, ok := c.Peers[peerID]
	if accepting && !slices.Contains(c.Services[service].Allow, peerID) && c.Services[service].PairingCA != "" {
		return invitedTLSConfig(c, peerID, c.Services[service])
	}
	if !ok {
		return nil, errors.New("peer is not trusted")
	}
	cert, err := peerCert(peerID, peer.Certificate)
	if err != nil {
		return nil, err
	}
	certificateFile := c.Certificate
	if !accepting && peer.ClientCertificates[service] != "" {
		certificateFile = peer.ClientCertificates[service]
	}
	local, err := tls.LoadX509KeyPair(localPath(c, certificateFile), localPath(c, c.Key))
	if err != nil {
		return nil, errors.New("cannot load device private identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	pin := sha256.Sum256(cert.Raw)
	t := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{local}, RootCAs: pool, ServerName: peerID,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].Raw) != pin {
				return errors.New("peer certificate pin mismatch")
			}
			return state.PeerCertificates[0].VerifyHostname(peerID)
		}}
	if accepting {
		t.ClientAuth = tls.RequireAndVerifyClientCert
		t.ClientCAs = pool
	}
	return t, nil
}
func protocolVersion(c *Config) string {
	if c.Protocol == "v3" {
		return "v3"
	}
	return "v2"
}
func initialize(id, dir, relay string) error {
	if id == "" {
		randomID := make([]byte, 16)
		if _, err := rand.Read(randomID); err != nil {
			return err
		}
		id = "dev-" + hex.EncodeToString(randomID)
	}
	if !identifier.MatchString(id) {
		return errors.New("device name must use lowercase letters, digits and hyphens")
	}
	if _, err := relayURL(&Config{ID: id, Relay: relay}); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "config.json")
	for _, name := range []string{"config.json", "identity.crt", "identity.key", "identity.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("device identity already exists or cannot be checked; use a new directory")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id}, DNSNames: []string{id},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeIdentity := func(name string, data []byte) error {
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		return errors.Join(writeErr, closeErr)
	}
	if err = writeIdentity("identity.crt", cert); err != nil {
		return err
	}
	if err = writeIdentity("identity.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})); err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return err
	}
	c := &Config{ID: id, Relay: relay, Token: hex.EncodeToString(token), ExpiresAt: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Certificate: "identity.crt", Key: "identity.key", Peers: map[string]Peer{}, Services: map[string]Service{}}
	if _, err = relayURL(c); err != nil {
		return err
	}
	if err = privateJSON(path, c); err != nil {
		return err
	}
	if err = privateJSON(filepath.Join(dir, "identity.json"), Identity{ID: id, Certificate: string(cert)}); err != nil {
		return err
	}
	fmt.Printf("created=%s\ndevice=%s\npublicIdentity=%s\n", path, id, filepath.Join(dir, "identity.json"))
	return nil
}
func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "http" {
		return httpCommand(ctx, args[1:])
	}
	if len(args) > 0 && (args[0] == "install-system-ssh" || args[0] == "system-ssh-service") {
		return runSystemSSHServiceCommand(ctx, args)
	}
	if len(args) > 0 && args[0] == "system-ssh-host" {
		return runSystemSSHHost(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "ssh-account-worker" {
		return embeddedWorkerCommand(args[1:])
	}
	if len(args) > 0 && (args[0] == "install-host" || args[0] == "host-service") {
		return runManagedCommand(ctx, args)
	}
	if len(args) > 0 && args[0] == "agent" {
		return runAgent(ctx, args[1:])
	}
	if len(args) == 0 && runtime.GOOS == "windows" {
		return runGUI(ctx, "", "", false)
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Println("HITL Connect: remote access and TCP port mapping\nGUI: gui (Windows: double-click the executable)\nAutomation: agent help (JSON setup, control and login checks)\nQuick start: host (provide HITL Connect), connect (paste connection key)\nAdvanced: share, join, init, trust, expose, export-registration, check, serve, forward\nRun hitl-connect <command> --help for flags. Device private keys stay on the device.")
		return nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configPath := flags.String("config", "config.json", "private device configuration")
	id := flags.String("id", "", "device ID (default: random opaque ID; avoid personal or business names)")
	dir := flags.String("dir", "", "new identity directory")
	relay := flags.String("relay", "", "HTTPS relay base URL")
	identityPath := flags.String("identity", "", "peer's independently verified public identity.json")
	service := flags.String("service", "", "explicit service name")
	target := flags.String("target", "", "loopback target host:port")
	allow := flags.String("allow", "", "comma-separated trusted peer names")
	peerID := flags.String("peer", "", "destination device")
	bind := flags.String("listen", "127.0.0.1:2222", "local loopback listener")
	output := flags.String("output", "", "registration output file; contains token hash only")
	keyFile := flags.String("key-file", "", "private connection key file; join prompts if omitted")
	uiBind := flags.String("ui-address", "127.0.0.1:0", "local GUI address (loopback only)")
	allowUser := flags.String("allow-user", "", "locally authorize one caller for this account")
	hostLog := flags.String("host-log", "", "private provider output file")
	noOpen := flags.Bool("no-open", false, "do not open the GUI browser automatically")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "gui" {
		return runGUI(ctx, *dir, *uiBind, *noOpen)
	}
	if args[0] == "host" || args[0] == "connect" {
		if *allowUser != "" && args[0] != "host" {
			return errors.New("LOCAL_HOST_ACTION_REQUIRED")
		}
		if *hostLog != "" {
			if args[0] != "host" || *allowUser == "" {
				return errors.New("LOCAL_HOST_ACTION_REQUIRED")
			}
			log, err := os.OpenFile(*hostLog, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return err
			}
			defer log.Close()
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = log, log
			defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		}
		err := quickStart(ctx, args[0], *configPath, *dir, *relay, *service, *target, *keyFile, *peerID, *bind, *allowUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, "allow-error="+err.Error())
		}
		return err
	}
	if args[0] == "share" || args[0] == "join" {
		return pairingCommand(args[0], *configPath, *dir, *relay, *service, *target, *keyFile)
	}
	if args[0] == "init" {
		if *dir == "" {
			return errors.New("--dir is required")
		}
		return initialize(*id, *dir, *relay)
	}
	c, err := load(*configPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "trust":
		var identity Identity
		if err = readJSON(*identityPath, &identity); err != nil {
			return err
		}
		if _, err = peerCert(identity.ID, identity.Certificate); err != nil {
			return err
		}
		if previous, ok := c.Peers[identity.ID]; ok && previous.Certificate != identity.Certificate {
			return errors.New("peer identity changed; remove old trust explicitly before replacing")
		}
		peer := c.Peers[identity.ID]
		peer.Certificate = identity.Certificate
		if *service != "" {
			if !identifier.MatchString(*service) {
				return errors.New("invalid service")
			}
			if !slices.Contains(peer.Services, *service) {
				peer.Services = append(peer.Services, *service)
			}
		}
		if peer.Services == nil {
			peer.Services = []string{}
		}
		c.Peers[identity.ID] = peer
		return privateJSON(c.path, c)
	case "expose":
		address, err := loopback(*target)
		if err != nil {
			return err
		}
		if !identifier.MatchString(*service) {
			return errors.New("invalid service name")
		}
		peers := strings.Split(*allow, ",")
		for _, id := range peers {
			if _, ok := c.Peers[id]; !ok {
				return errors.New("--allow must name trusted peers")
			}
		}
		c.Services[*service] = Service{Target: address, Allow: peers}
		return privateJSON(c.path, c)
	case "export-registration":
		if *output == "" {
			return errors.New("--output is required")
		}
		return exportRegistration(c, *output)
	case "check":
		if _, err = tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key)); err != nil {
			return errors.New("invalid local private identity")
		}
		fmt.Printf("configuration OK device=%s services=%d trustedPeers=%d\n", c.ID, len(c.Services), len(c.Peers))
		return nil
	case "serve":
		return serve(ctx, c)
	case "forward":
		return forward(ctx, c, *peerID, *service, *bind)
	case "connect":
		if *peerID == "" && len(c.Peers) == 1 {
			for id := range c.Peers {
				*peerID = id
			}
		}
		if *service == "" && len(c.Peers[*peerID].Services) == 1 {
			*service = c.Peers[*peerID].Services[0]
		}
		return forward(ctx, c, *peerID, *service, *bind)
	default:
		return errors.New("unknown command")
	}
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		var status *agentExit
		if errors.As(err, &status) {
			os.Exit(status.code)
		}
		fmt.Fprintln(os.Stderr, err)
		if len(os.Args) == 1 || os.Args[1] == "gui" {
			showGUIError(err.Error())
		}
		os.Exit(1)
	}
}
