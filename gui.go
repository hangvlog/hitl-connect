package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed gui-assets/*
var guiAssets embed.FS

var guiVersion = "development"

type guiStep struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type guiState struct {
	ProtocolVersion    int                   `json:"protocolVersion,omitempty"`
	ControlState       string                `json:"controlState,omitempty"`
	ControlSeenAt      string                `json:"controlSeenAt,omitempty"`
	ActiveSessions     int                   `json:"activeSessions"`
	IdleChannels       int                   `json:"idleChannels"`
	ServiceReadyAt     string                `json:"serviceReadyAt,omitempty"`
	Privilege          string                `json:"privilege,omitempty"`
	SSHEngine          string                `json:"sshEngine,omitempty"`
	Installation       *installerReport      `json:"installation,omitempty"`
	Version            string                `json:"version"`
	Configured         bool                  `json:"configured"`
	Problem            *connectionProblem    `json:"problem,omitempty"`
	LoginCheckEngine   string                `json:"loginCheckEngine,omitempty"`
	NativeSSHExitCode  *int                  `json:"nativeSshExitCode,omitempty"`
	Managed            bool                  `json:"managed"`
	ManagedUnavailable bool                  `json:"managedUnavailable,omitempty"`
	Service            *managedServiceStatus `json:"service,omitempty"`
	Running            bool                  `json:"running"`
	Role               string                `json:"role"`
	Address            string                `json:"address"`
	Steps              []guiStep             `json:"steps"`
	Events             []string              `json:"events"`
	HasInvitation      bool                  `json:"hasInvitation"`
	Fingerprint        string                `json:"fingerprint"`
	CanTrust           bool                  `json:"canTrust"`
	LoginIdentity      string                `json:"loginIdentity"`
	SavedCaller        bool                  `json:"savedCaller"`
	SavedProvider      bool                  `json:"savedProvider"`
	CheckedAt          string                `json:"checkedAt"`
	LocalUser          string                `json:"localUser"`
	Access             []sshAccess           `json:"access"`
	AuthorizedUser     string                `json:"authorizedUser,omitempty"`
	GrantExpires       int64                 `json:"grantExpires,omitempty"`
	GrantDisabled      bool                  `json:"grantDisabled,omitempty"`
	GrantedDevices     int                   `json:"grantedDevices"`
	GrantUsed          bool                  `json:"grantUsed,omitempty"`
	AccessStatus       string                `json:"accessStatus,omitempty"`
	AccessRequest      string                `json:"accessRequest,omitempty"`
}
type guiRequest struct {
	Relay         string `json:"relay,omitempty"`
	Privilege     string `json:"privilege,omitempty"`
	Role          string `json:"role"`
	ConnectionKey string `json:"connectionKey"`
	Target        string `json:"target"`
	Listen        string `json:"listen"`
	User          string `json:"user"`
	KeyPath       string `json:"keyPath"`
	Fingerprint   string `json:"fingerprint"`
	RequestID     string `json:"requestId"`
	AllowSSH      bool   `json:"allowSSH"`
	ManualSSH     bool   `json:"manualSSH"`
}
type guiSession struct {
	runtime                  *providerRuntime
	mu                       sync.Mutex
	op                       sync.Mutex
	base, exe, origin, token string
	state                    guiState
	child                    *exec.Cmd
	cancel                   context.CancelFunc
	done                     chan struct{}
	invitation, address      string
	candidate                ssh.PublicKey
	generation               uint64
	shutdown                 context.CancelFunc
	autoSSH                  bool
	sshIdentity              string
	accessEpoch              uint64
}
type guiDescriptor struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func newGUI(base, exe string) *guiSession {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	g := &guiSession{base: base, exe: exe, token: hex.EncodeToString(b)}
	g.reset("host")
	g.restorePlanDisplay()
	if servicePolicy != nil {
		g.state.Managed = true
		g.state.LocalUser = servicePolicy.User
	}
	return g
}
func (g *guiSession) reset(role string) {
	g.state = guiState{Version: guiVersion, Managed: servicePolicy != nil, Role: role, Events: []string{}, Steps: []guiStep{
		{"local", "本机准备", "pending", "启动时检查 HITL Connect 服务或映射端口"},
		{"relay", "云端中继", "pending", "尚未连接"},
		{"tunnel", "HITL Connect 通道", "pending", "尚未验证"},
		{"login", "账号登录", "pending", "需要实际登录成功，才会显示通过"},
	}}
	_, a := os.Stat(filepath.Join(g.base, "public-connect", "config.json"))
	_, b := os.Stat(filepath.Join(g.base, "public-host", "config.json"))
	g.state.SavedCaller, g.state.SavedProvider = a == nil, b == nil
	g.state.LocalUser = localSSHUser()
	g.invitation, g.candidate = "", nil
}
func (g *guiSession) step(id, status, detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stepLocked(id, status, detail)
}
func (g *guiSession) stepLocked(id, status, detail string) {
	if id == "login" && (status == "pending" || status == "working") {
		g.state.NativeSSHExitCode = nil
		g.state.LoginCheckEngine = ""
	}
	if id == "login" && status != "passed" {
		g.state.LoginIdentity = ""
	}
	if id != "login" && (status == "failed" || status == "working" || status == "pending") {
		g.state.LoginIdentity = ""
		g.state.CanTrust = false
		g.candidate = nil
		g.stepLocked("login", "pending", "连接状态已变化，需重新验证账号登录")
	}
	for i := range g.state.Steps {
		if g.state.Steps[i].ID == id {
			g.state.Steps[i].Status = status
			g.state.Steps[i].Detail = detail
		}
	}
	g.state.CheckedAt = time.Now().Format(time.RFC3339)
}
func (g *guiSession) event(message string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.eventLocked(message)
}
func (g *guiSession) eventLocked(message string) {
	line := time.Now().Format("15:04:05") + "  " + message
	g.state.Events = append(g.state.Events, line)
	if len(g.state.Events) > 40 {
		g.state.Events = g.state.Events[len(g.state.Events)-40:]
	}
}
func (g *guiSession) handler() http.Handler {
	assets, _ := fs.Sub(guiAssets, "gui-assets")
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Host != strings.TrimPrefix(g.origin, "http://") {
			http.Error(w, "invalid host", 403)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" && r.URL.Path != "/brand.svg" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", 405)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+g.token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != g.origin {
			http.Error(w, "invalid origin", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if (r.Method == http.MethodGet && r.URL.Path == "/api/state" || r.Method == http.MethodPost && r.Header.Get("Origin") == g.origin) && g.forwardManaged(w, r) {
			return
		}
		if r.URL.Path == "/api/state" && r.Method == http.MethodGet {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.runtime != nil {
				g.runtime.project(&g.state)
			}
			if g.state.Role == "host" {
				g.state.Access = listSSHAccess(filepath.Join(g.base, "public-host"))
				g.refreshHostGrant()
			}
			_ = json.NewEncoder(w).Encode(g.state)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Origin") != g.origin {
			http.Error(w, "same-origin POST required", 403)
			return
		}
		if !g.op.TryLock() {
			http.Error(w, "another action is running", 409)
			return
		}
		defer g.op.Unlock()
		var request guiRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid request", 400)
			return
		}
		if err := validateManagedAction(servicePolicy, strings.TrimPrefix(r.URL.Path, "/api/"), request); err != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		var err error
		switch r.URL.Path {
		case "/api/disable-code":
			err = g.disableGrant()
		case "/api/renew":
			err = g.renewGrant()
		case "/api/allow":
			request.Role, request.AllowSSH = "host", true
			err = g.ensureConnection(request)
		case "/api/start":
			err = g.ensureConnection(request)
		case "/api/drain":
			err = g.drainProvider(r.Context())
		case "/api/stop":
			g.rememberStopped()
			g.stop()
		case "/api/diagnose":
			err = g.diagnoseConnection(request)
		case "/api/trust":
			err = g.trust(request.Fingerprint)
		case "/api/request-access":
			var again bool
			again, err = g.checkSSHAccess(request.KeyPath)
			if err != nil {
				g.connectionError(err)
			} else if again {
				g.launchAccessMonitor(request.KeyPath)
			}
		case "/api/approve", "/api/reject":
			result := decideSSHAccess(r.Context(), g.base, request.RequestID, request.User, request.Fingerprint, r.URL.Path == "/api/approve")
			_ = json.NewEncoder(w).Encode(result)
			return
		case "/api/invitation":
			g.mu.Lock()
			key := g.invitation
			if g.state.AuthorizedUser != "" {
				g.refreshHostGrant()
				if g.state.GrantDisabled {
					key = ""
				}
			}
			g.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"connectionKey": key})
			return
		case "/api/quit":
			g.rememberStopped()
			g.stop()
			if servicePolicy == nil || servicePolicy.Engine == "openssh" {
				go g.shutdown()
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			w.WriteHeader(400)
			var failure *installerError
			if errors.As(err, &failure) {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "installation": failure.Report})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
}

func runGUI(ctx context.Context, base, bind string, noOpen bool) error {
	if base == "" {
		home, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		base = filepath.Join(home, "hitl-connect")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	descriptor := filepath.Join(base, "gui-session.json")
	var previous guiDescriptor
	previousErr := readJSON(descriptor, &previous)
	previousURL, parseErr := url.Parse(previous.URL)
	if previousErr == nil && parseErr == nil && previousURL.Scheme == "http" && previousURL.Hostname() == "127.0.0.1" && previousURL.Port() != "" && previousURL.User == nil && previousURL.Path == "" && previousURL.RawQuery == "" && previousURL.Fragment == "" {
		req, requestErr := http.NewRequest("GET", previous.URL+"/api/state", nil)
		if requestErr != nil {
			return errors.New("invalid previous GUI address")
		}
		req.Header.Set("Authorization", "Bearer "+previous.Token)
		client := http.Client{Timeout: time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		if res, e := client.Do(req); e == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				if !noOpen {
					return openGUIBrowser(previous.URL + "/#" + previous.Token)
				}
				fmt.Println("GUI is already running; sessionFile=" + descriptor)
				return nil
			}
		}
	}
	release, acquired, lockErr := tryProfileLock(base, ".panel.lock")
	if lockErr != nil {
		return lockErr
	}
	if !acquired {
		return nil
	}
	defer release()
	if bind == "" {
		bind = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(bind)
	if err != nil || host != "127.0.0.1" {
		return errors.New("GUI must bind to 127.0.0.1")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	g := newGUI(base, exe)
	g.origin = "http://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.shutdown = cancel
	if err = privateJSON(descriptor, guiDescriptor{g.origin, g.token}); err != nil {
		listener.Close()
		return err
	}
	// A private local launcher lets tests open the same bootstrap URL without
	// printing its capability token in command output or sharing diagnostics.
	launchFile := filepath.Join(base, "gui-launch.html")
	if err = privateText(launchFile, `<!doctype html><meta http-equiv="refresh" content="0;url=`+g.origin+`/#`+g.token+`">`); err != nil {
		listener.Close()
		return err
	}
	defer func() {
		var current guiDescriptor
		if readJSON(descriptor, &current) == nil && current.Token == g.token {
			_ = os.Remove(launchFile)
			_ = os.Remove(descriptor)
		}
	}()
	server := &http.Server{Handler: g.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		g.op.Lock()
		g.stop()
		g.op.Unlock()
		deadline, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		_ = server.Shutdown(deadline)
		_ = server.Close()
	}()
	fmt.Printf("GUI=%s\nsessionFile=%s\n", g.origin, descriptor)
	if !noOpen {
		if err = openGUIBrowser(g.origin + "/#" + g.token); err != nil {
			fmt.Fprintln(os.Stderr, "Could not open browser; open the private gui-launch.html file.")
			showGUIError("无法打开默认浏览器，请手动打开：\n" + launchFile)
		}
	}
	if !noOpen || servicePolicy != nil {
		go g.resumeOnOpen()
	}
	err = server.Serve(listener)
	cancel()
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
