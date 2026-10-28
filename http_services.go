package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type httpPublication struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Token   string `json:"token"`
	Enabled bool   `json:"enabled"`
}
type httpPublications struct {
	Services []httpPublication `json:"services"`
}

var httpPublicationStates sync.Map

func readHTTPPublications(config string) (httpPublications, error) {
	var p httpPublications
	err := readJSON(filepath.Join(filepath.Dir(config), "http-services.private.json"), &p)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	seen := map[string]bool{}
	for _, s := range p.Services {
		if !identifier.MatchString(s.Name) || seen[s.Name] || len(s.Token) != 64 {
			return p, errors.New("invalid HTTP service configuration")
		}
		if _, err = hex.DecodeString(s.Token); err != nil {
			return p, err
		}
		if _, err = loopback(s.Target); err != nil {
			return p, err
		}
		seen[s.Name] = true
	}
	if len(p.Services) > 16 {
		return p, errors.New("too many HTTP services")
	}
	return p, nil
}
func saveHTTPPublication(config, name, target string, enabled bool) (httpPublication, error) {
	release, acquired, lockErr := tryProfileLock(filepath.Dir(config), ".http-services-config.lock")
	if lockErr != nil {
		return httpPublication{}, lockErr
	}
	if !acquired {
		return httpPublication{}, errors.New("HTTP service settings are being updated")
	}
	defer release()
	p, err := readHTTPPublications(config)
	if err != nil {
		return httpPublication{}, err
	}
	if enabled {
		target, err = loopback(target)
		if err != nil {
			return httpPublication{}, err
		}
	}
	if name == "" && enabled {
		_, name, _ = net.SplitHostPort(target)
	}
	if !identifier.MatchString(name) {
		return httpPublication{}, errors.New("invalid service name")
	}
	index := -1
	for i, s := range p.Services {
		if s.Name == name {
			index = i
		}
	}
	var s httpPublication
	if index >= 0 {
		s = p.Services[index]
	} else {
		if !enabled {
			return s, errors.New("service not found")
		}
		if len(p.Services) >= 16 {
			return s, errors.New("too many HTTP services")
		}
		token := make([]byte, 32)
		if _, err = rand.Read(token); err != nil {
			return s, err
		}
		s = httpPublication{Name: name, Token: hex.EncodeToString(token)}
	}
	s.Enabled = enabled
	if enabled {
		s.Target = target
	}
	if index >= 0 {
		p.Services[index] = s
	} else {
		p.Services = append(p.Services, s)
	}
	err = privateJSON(filepath.Join(filepath.Dir(config), "http-services.private.json"), p)
	return s, err
}
func httpServiceURL(c *Config, name string) (string, error) {
	u, err := relayBaseURL(c)
	if err != nil {
		return "", err
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	base := strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(base, "/device-tunnel") {
		base = strings.TrimSuffix(base, "/device-tunnel")
	}
	u.Path = base + "/services/" + c.ID + "/" + name + "/"
	return u.String(), nil
}
func httpRelayURL(c *Config) (string, error) {
	u, err := relayBaseURL(c)
	if err != nil {
		return "", err
	}
	if strings.TrimRight(u.Path, "/") == "/hitl/device-tunnel" {
		u.Path = "/hitl/local-http-relay/connect/hitl-connect/http-v1/session"
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + "/connect/http-v1/session"
	}
	return u.String(), nil
}

// Configuration changes restart only this HTTP owner; SSH streams keep their own lifetime.
func runHTTPPublications(ctx context.Context, config string) error {
	absolute, err := filepath.Abs(config)
	if err != nil {
		return err
	}
	config = absolute
	release, acquired, err := tryProfileLock(filepath.Dir(config), ".http-services.lock")
	if err != nil {
		return err
	}
	if !acquired {
		return errors.New("HTTP publisher already running")
	}
	defer release()
	backoff := reconnectBackoff{}
	var budget *reconnectBudget
	for ctx.Err() == nil {
		wait := time.Second // Local configuration polling makes no relay requests.
		c, err := load(config)
		p, e := readHTTPPublications(config)
		if err == nil && e == nil && len(p.Services) > 0 {
			budget = budgetFor(c, "http")
			_, cancelAttempt, attemptErr := budget.attempt(ctx)
			if attemptErr != nil {
				return attemptErr
			}
			// Budget bounds retries/handshakes, not an already acknowledged stream.
			cancelAttempt()
			child, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			before, _ := json.Marshal(p)
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-child.Done():
						return
					case <-ticker.C:
						p, e := readHTTPPublications(config)
						b, _ := json.Marshal(p)
						if e != nil || string(b) != string(before) {
							cancel()
							return
						}
					}
				}
			}()
			var online time.Time
			err = serveHTTPPublicationsReady(child, c, p, func() { online = time.Now() })
			configurationChanged := child.Err() != nil && ctx.Err() == nil
			cancel()
			<-done
			if ctx.Err() == nil && !configurationChanged {
				if stopped := budget.failure(); stopped != nil {
					return stopped
				}
				if !online.IsZero() && time.Since(online) >= reconnectStable {
					backoff = reconnectBackoff{}
				}
				wait = backoff.next()
				var failure *relayFailure
				if errors.As(err, &failure) {
					wait = max(wait, failure.retryAfter)
					if failure.permanent || (failure.status >= 400 && failure.status < 500 && failure.status != 429 && failure.status != 401) {
						return err
					}
				}
				fmt.Fprintf(os.Stderr, "HTTP publication disconnected; reconnecting in %s without replay\n", wait)
			}
		}
		if budget != nil {
			if err := budget.wait(ctx, wait); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		} else if waitReconnect(ctx, wait) != nil {
			return nil
		}
	}
	return nil
}
func serveHTTPPublications(ctx context.Context, c *Config, p httpPublications) error {
	return serveHTTPPublicationsReady(ctx, c, p, func() {})
}
func serveHTTPPublicationsReady(ctx context.Context, c *Config, p httpPublications, ready func()) error {
	httpPublicationStates.Store(c.path, false)
	defer httpPublicationStates.Store(c.path, false)
	endpoint, err := httpRelayURL(c)
	if err != nil {
		return err
	}
	local, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(localPath(c, c.Certificate))
	if err != nil {
		return err
	}
	sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })
	services := []map[string]any{}
	pairs := [][]any{}
	targets := map[string]string{}
	for _, s := range p.Services {
		if !s.Enabled {
			continue
		}
		hash := sha256.Sum256([]byte(s.Token))
		digest := hex.EncodeToString(hash[:])
		_, portText, _ := net.SplitHostPort(s.Target)
		port, _ := strconv.Atoi(portText)
		services = append(services, map[string]any{"name": s.Name, "tokenSha256": digest, "localPort": port})
		pairs = append(pairs, []any{s.Name, digest, port})
		targets[s.Name] = s.Target
	}
	version := time.Now().UnixMilli()
	message, _ := json.Marshal([]any{"hitl-http-publish-v2", c.ID, version, pairs})
	digest := sha256.Sum256(message)
	signature, err := local.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	ws, err := openRelay(ctx, c, endpoint)
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	handshakeCtx, cancelHandshake, budgetErr := budgetFor(c, "http").attempt(ctx)
	if budgetErr != nil {
		return budgetErr
	}
	defer cancelHandshake()
	handshakeCtx, cancelHandshakeTimeout := context.WithTimeout(handshakeCtx, 10*time.Second)
	defer cancelHandshakeTimeout()
	hello, _ := json.Marshal(map[string]any{"role": "http-control", "certificate": string(cert), "signature": base64.StdEncoding.EncodeToString(signature), "publication": map[string]any{"format": 2, "version": version, "services": services}})
	if err = ws.Write(handshakeCtx, websocket.MessageText, hello); err != nil {
		return err
	}
	kind, b, err := ws.Read(handshakeCtx)
	if err != nil {
		return err
	}
	var ack struct {
		State string `json:"state"`
	}
	if kind != websocket.MessageText || json.Unmarshal(b, &ack) != nil || ack.State != "published" {
		return errors.New("HTTP publication rejected")
	}
	fmt.Println("HTTP services published")
	httpPublicationStates.Store(c.path, true)
	stopHealthy := budgetFor(c, "http").online()
	defer stopHealthy()
	ready()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	defer workers.Wait()
	slots := make(chan struct{}, 8)
	for {
		kind, b, err = ws.Read(child)
		if err != nil {
			cancel()
			return err
		}
		var request struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
			Nonce     string `json:"nonce"`
			Service   string `json:"service"`
		}
		if kind != websocket.MessageText || json.Unmarshal(b, &request) != nil || request.Type != "request" || targets[request.Service] == "" {
			cancel()
			return errors.New("HTTP control protocol invalid")
		}
		select {
		case slots <- struct{}{}:
		default:
			cancel()
			return errors.New("HTTP local capacity exceeded")
		}
		workers.Add(1)
		go func(target, id, nonce string) {
			defer workers.Done()
			defer func() { <-slots }()
			_ = serveHTTPRequest(child, c, endpoint, target, id, nonce)
		}(targets[request.Service], request.RequestID, request.Nonce)
	}
}
func serveHTTPRequest(ctx context.Context, c *Config, endpoint, target, id, nonce string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	ws, err := openRelay(ctx, c, endpoint)
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	b, _ := json.Marshal(map[string]string{"role": "http-data", "requestId": id, "nonce": nonce})
	if err = ws.Write(ctx, websocket.MessageText, b); err != nil {
		return err
	}
	kind, b, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	var ack struct {
		State string `json:"state"`
	}
	if kind != websocket.MessageText || json.Unmarshal(b, &ack) != nil || ack.State != "ready" {
		return errors.New("HTTP request rejected")
	}
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	defer req.Body.Close()
	req.RequestURI = ""
	req.URL.Scheme = "http"
	req.URL.Host = target
	req.Host = target
	req.Header.Del("X-Hitl-Service-Token")
	req.Header.Del("Cookie")
	req.Header.Del("Proxy-Authorization")
	req.Close = true
	// Read after request EOF to observe caller cancellation while local work/SSE is active.
	finishedBody := make(chan struct{})
	var once sync.Once
	req.Body = &httpObservedBody{ReadCloser: req.Body, done: func() { once.Do(func() { close(finishedBody) }) }}
	if req.ContentLength == 0 {
		once.Do(func() { close(finishedBody) })
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-finishedBody:
		}
		var b [1]byte
		_, _ = conn.Read(b[:])
		cancel()
	}()
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 60 * time.Second}
	defer transport.CloseIdleConnections()
	req = req.WithContext(ctx)
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		response = &http.Response{StatusCode: 502, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"code":"SERVICE_LOCAL_UNAVAILABLE"}`)), ContentLength: -1, Close: true}
	}
	defer response.Body.Close()
	response.Header.Del("Set-Cookie")
	response.Close = true
	return response.Write(conn)
}

type httpObservedBody struct {
	io.ReadCloser
	done func()
}

func (b *httpObservedBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if e == io.EOF {
		b.done()
	}
	return n, e
}
func httpCommand(ctx context.Context, args []string) error {
	action := "help"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	if action == "help" || action == "--help" {
		fmt.Println("HTTP service publishing: http publish --config <provider-config> --port 8000 [--name model-api] --output <private-credentials>; http list --config ...; http disable --config ... --name ...; http run --config ...; http resume --config ... (manual reset after two-hour stop)\nExisting providers reuse their saved identity. GUI providers run publications automatically. CLI-only providers run http run alongside host. Never put tokens in arguments.")
		return nil
	}
	f := flag.NewFlagSet("http "+action, flag.ContinueOnError)
	config := f.String("config", "", "existing provider config.json")
	port := f.Int("port", 0, "loopback HTTP port")
	name := f.String("name", "", "service name (default port)")
	output := f.String("output", "", "private API credentials file")
	challenge := f.String("challenge", "", "Chat All account claim challenge JSON")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *config == "" {
		return errors.New("existing --config required")
	}
	c, err := load(*config)
	if err != nil {
		return err
	}
	if action == "run" {
		return runHTTPPublications(ctx, *config)
	}
	if action == "resume" {
		if err := budgetFor(c, "http").manualReset(); err != nil {
			return err
		}
		return runHTTPPublications(ctx, *config)
	}
	if action == "claim-proof" {
		return httpClaimProof(c, *challenge, *output)
	}
	if action == "publish" {
		if *port < 1 || *port > 65535 || *output == "" {
			return errors.New("publish requires --port 1-65535 and --output private file")
		}
		// Never let credentials overwrite identity/configuration or unrelated existing files.
		absolute, err := filepath.Abs(*output)
		if err != nil {
			return err
		}
		if filepath.Dir(absolute) == filepath.Dir(c.path) {
			return errors.New("credentials output must be outside the provider identity directory")
		}
		if _, err := os.Lstat(absolute); !os.IsNotExist(err) {
			return errors.New("credentials output already exists or cannot be inspected")
		}
		s, err := saveHTTPPublication(*config, *name, net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)), true)
		if err != nil {
			return err
		}
		u, _ := httpServiceURL(c, s.Name)
		if err = privateJSON(*output, map[string]string{"url": u, "header": "X-Hitl-Service-Token", "token": s.Token}); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"configured": true, "name": s.Name, "url": u, "credentialsFile": *output, "onlineVerified": false})
	}
	if action == "disable" {
		_, err := saveHTTPPublication(*config, *name, "", false)
		return err
	}
	if action == "list" {
		p, err := readHTTPPublications(*config)
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for _, s := range p.Services {
			u, _ := httpServiceURL(c, s.Name)
			items = append(items, map[string]any{"name": s.Name, "target": s.Target, "enabled": s.Enabled, "url": u})
		}
		return json.NewEncoder(os.Stdout).Encode(items)
	}
	return errors.New("unknown HTTP service action")
}

func (g *guiSession) httpAction(w http.ResponseWriter, r *http.Request, request guiRequest) {
	config := filepath.Join(g.base, "public-host", "config.json")
	c, err := load(config)
	fail := func(err error) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	if err != nil {
		fail(errors.New("请先配置本机提供端身份"))
		return
	}
	if r.URL.Path == "/api/http-publish" {
		if request.HTTPPort < 1 || request.HTTPPort > 65535 {
			fail(errors.New("端口必须在 1 到 65535 之间"))
			return
		}
		_, err = saveHTTPPublication(config, request.ServiceName, net.JoinHostPort("127.0.0.1", strconv.Itoa(request.HTTPPort)), true)
	} else if r.URL.Path == "/api/http-disable" {
		_, err = saveHTTPPublication(config, request.ServiceName, "", false)
	} else if r.URL.Path == "/api/http-resume" {
		err = budgetFor(c, "http").manualReset()
	}
	if err != nil {
		fail(err)
		return
	}
	p, err := readHTTPPublications(config)
	if err != nil {
		fail(err)
		return
	}
	items := []map[string]any{}
	connected, _ := httpPublicationStates.Load(c.path)
	for _, s := range p.Services {
		u, _ := httpServiceURL(c, s.Name)
		if r.URL.Path == "/api/http-credentials" && s.Name == request.ServiceName {
			_ = json.NewEncoder(w).Encode(map[string]string{"url": u, "header": "X-Hitl-Service-Token", "token": s.Token})
			return
		}
		items = append(items, map[string]any{"name": s.Name, "target": s.Target, "enabled": s.Enabled, "url": u})
	}
	if r.URL.Path == "/api/http-credentials" {
		fail(errors.New("服务不存在"))
		return
	}
	b := budgetFor(c, "http")
	b.mu.Lock()
	retryErr := b.checkLocked(time.Now())
	b.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "connected": connected == true, "reconnectStopped": isReconnectStopped(retryErr)})
}
