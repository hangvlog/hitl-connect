package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type agentExit struct{ code int }

type agentResponseError struct{ message string }

func (e *agentResponseError) Error() string { return e.message }

func (e *agentExit) Error() string { return "agent action did not complete" }

type agentResult struct {
	Schema            string           `json:"schemaVersion"`
	Action            string           `json:"action"`
	OK                bool             `json:"ok"`
	Code              string           `json:"code"`
	LoginVerified     bool             `json:"loginVerified"`
	Message           string           `json:"message,omitempty"`
	State             *guiState        `json:"state,omitempty"`
	Installation      *installerReport `json:"installation,omitempty"`
	Setup             json.RawMessage  `json:"setup,omitempty"`
	LoginIdentity     string           `json:"loginIdentity,omitempty"`
	NativeSSHExitCode *int             `json:"nativeSshExitCode,omitempty"`
	NextActions       []string         `json:"nextActions"`
}

func agentReply(result agentResult) error {
	result.Schema = "hitl-connect.agent.v1"
	if result.NextActions == nil {
		result.NextActions = []string{}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	if !result.OK {
		return &agentExit{2}
	}
	return nil
}

func agentSession(base string) (guiDescriptor, error) {
	var d guiDescriptor
	if managed, err := managedProfile(base); err != nil {
		return d, err
	} else if managed != "" {
		base = managed
	}
	if err := readJSON(filepath.Join(base, "gui-session.json"), &d); err != nil {
		return d, err
	}
	u, err := url.Parse(d.URL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(d.Token) != 64 {
		return d, errors.New("invalid local panel descriptor")
	}
	return d, nil
}

func agentCall(ctx context.Context, d guiDescriptor, action string, request *guiRequest, response any) error {
	method := http.MethodGet
	var body io.Reader
	if request != nil {
		method = http.MethodPost
		data, _ := json.Marshal(request)
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.URL+"/api/"+action, body)
	if err != nil {
		return errors.New("invalid local panel address")
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	req.Header.Set("Origin", d.URL)
	req.Header.Set("Content-Type", "application/json")
	timeout := 35 * time.Second
	if action == "drain" {
		timeout = 65 * time.Second
	}
	if action == "allow" {
		// Let the installer's 240-second timeout return its structured result.
		timeout = 255 * time.Second
	}
	client := http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("local panel unavailable or timed out; run status before retrying a mutation")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var failure struct {
			Error        string           `json:"error"`
			Installation *installerReport `json:"installation,omitempty"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&failure)
		if failure.Error == "" {
			failure.Error = fmt.Sprintf("local panel HTTP %d", res.StatusCode)
		}
		if failure.Installation != nil {
			return &installerError{*failure.Installation}
		}
		return &agentResponseError{failure.Error}
	}
	return json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(response)
}

func ensureAgentPanel(ctx context.Context, base string) (guiDescriptor, error) {
	if d, err := agentSession(base); err == nil {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		var state guiState
		err = agentCall(probe, d, "state", nil, &state)
		cancel()
		if err == nil {
			return d, nil
		}
	}
	if managed, err := managedProfile(base); err != nil {
		return guiDescriptor{}, err
	} else if managed != "" {
		return guiDescriptor{}, errors.New("HOST_SERVICE_UNAVAILABLE: Windows background service is not responding")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return guiDescriptor{}, err
	}
	release, acquired, err := tryProfileLock(base, ".panel-start.lock")
	if err != nil {
		return guiDescriptor{}, err
	}
	if !acquired {
		for i := 0; i < 50; i++ {
			select {
			case <-ctx.Done():
				return guiDescriptor{}, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			if d, e := agentSession(base); e == nil {
				var state guiState
				if agentCall(ctx, d, "state", nil, &state) == nil {
					return d, nil
				}
			}
		}
		return guiDescriptor{}, errors.New("PANEL_START_IN_PROGRESS")
	}
	defer release()
	exe, err := os.Executable()
	if err != nil {
		return guiDescriptor{}, err
	}
	cmd := exec.Command(exe, "gui", "--no-open", "--dir", base)
	detachAgentPanel(cmd)
	if err = cmd.Start(); err != nil {
		return guiDescriptor{}, errors.New("could not start local panel")
	}
	go func() { _ = cmd.Wait() }()
	for i := 0; i < 40; i++ {
		select {
		case <-ctx.Done():
			return guiDescriptor{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if d, err := agentSession(base); err == nil {
			var state guiState
			if agentCall(ctx, d, "state", nil, &state) == nil {
				return d, nil
			}
		}
	}
	return guiDescriptor{}, errors.New("local panel did not become ready")
}

func runAgent(ctx context.Context, args []string) error {
	action := "help"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	if action == "help" || action == "--help" {
		return agentReply(agentResult{Action: "help", OK: true, Code: "CAPABILITIES", Message: "JSON stdout. Exit 0=action/snapshot succeeded, 2=not ready or failed. Only loginVerified with nativeSshExitCode=0 and expected loginIdentity proves login. GUI and CLI share saved state. Temporary failures recover in background.", NextActions: []string{
			"Provider first use: agent allow --relay <https-relay-base> --user <local-account> --output <private-code-file> (accept Windows UAC once; installs background service)",
			"Caller first use: agent start --role connect --key-file <private-code-file> --wait",
			"Reconnect: agent start --wait (no code, account or key flags needed)",
			"Inspect: agent status; agent diagnose (structured code, problem.side, retryable, nextAction)",
			"Windows native setup availability: agent preflight (read-only, no panel, no installation or policy changes)",
			"Control: agent stop; agent disable-code; agent renew --output <private-code-file>",
			"Every command supports --dir <existing-profile>. Preserve it when upgrading. Codes remain valid until disabled or replaced; never delete identity to retry.",
		}})
	}
	fail := func(code, message string) error {
		return agentReply(agentResult{Action: action, Code: code, Message: message})
	}
	flags := flag.NewFlagSet("agent "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("dir", "", "shared GUI profile")
	role := flags.String("role", "", "host or connect")
	relay := flags.String("relay", "", "provider HTTPS relay base; saved only in the local profile")
	target := flags.String("target", "", "local SSH target")
	listen := flags.String("listen", "", "local mapped address")
	keyFile := flags.String("key-file", "", "invitation file; never put secrets in arguments")
	privilege := flags.String("privilege", "", "provider: standard or explicitly authorized administrator")
	user := flags.String("user", "", "remote or setup account")
	identity := flags.String("identity", "", "existing SSH private key path")
	fingerprint := flags.String("fingerprint", "", "independently verified host fingerprint")
	output := flags.String("output", "", "private output file")
	publicKey := flags.String("public-key", "", "approved public key for Windows setup")
	apply := flags.Bool("apply", false, "apply Windows setup after reviewing its plan")
	install := flags.Bool("install-server", false, "allow installing Windows OpenSSH capability")
	requestID := flags.String("request", "", "exact locally reviewed access request")
	wait := flags.Bool("wait", false, "wait for caller login or provider readiness (up to 300 seconds)")
	manual := flags.Bool("manual-ssh", false, "disable automatic SSH key exchange")
	flags.Bool("json", true, "always outputs JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return fail("INVALID_ARGUMENT", "Run agent help for supported commands and flags")
	}
	if action == "preflight" {
		return agentReply(nativeSetupPreflight(ctx))
	}
	if action == "prepare-ssh" {
		r := windowsSetup(ctx, *user, "", "", *apply, *install, true)
		r.Action = "prepare-ssh"
		return agentReply(r)
	}
	if action == "setup-ssh" {
		return runWindowsSetup(ctx, *user, *publicKey, *fingerprint, *apply, *install)
	}
	if !strings.Contains("|status|allow|renew|disable-code|start|diagnose|trust|invitation|stop|quit|request-access|approve|reject|", "|"+action+"|") {
		return fail("UNKNOWN_ACTION", "Run agent help")
	}
	if *base == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			return fail("PROFILE_UNAVAILABLE", "Cannot locate the user configuration directory")
		}
		*base = filepath.Join(config, "hitl-connect")
	}
	if action == "approve" || action == "reject" {
		return agentReply(decideSSHAccess(ctx, *base, *requestID, *user, *fingerprint, action == "approve"))
	}
	request := guiRequest{Relay: *relay, Privilege: *privilege, Role: *role, Target: *target, Listen: *listen, User: *user, KeyPath: *identity, Fingerprint: *fingerprint, ManualSSH: *manual}
	if action == "start" && *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil || len(data) > 4096 {
			return fail("INVITATION_FILE_INVALID", "Cannot read a bounded invitation file")
		}
		request.ConnectionKey = strings.TrimSpace(string(data))
	}
	if action == "invitation" && *output == "" {
		return fail("PRIVATE_OUTPUT_REQUIRED", "Use --output; connection codes are never printed to agent stdout")
	}
	if (action == "allow" || action == "renew") && *output != "" {
		if _, err := os.Stat(*output); !os.IsNotExist(err) {
			return fail("OUTPUT_EXISTS", "Choose a new private output file")
		}
	}
	d, err := agentSession(*base)
	if action == "start" || action == "allow" || action == "diagnose" {
		d, err = ensureAgentPanel(ctx, *base)
	}
	if err != nil {
		if result := managedAgentFailure(*base, action, err); result != nil {
			return agentReply(*result)
		}
		if strings.Contains(err.Error(), "HOST_SERVICE_") {
			return fail("HOST_SERVICE_UNAVAILABLE", err.Error())
		}
		return fail("PANEL_NOT_RUNNING", "Run agent start --wait using the existing profile")
	}
	if action != "status" {
		var result struct {
			ConnectionKey string `json:"connectionKey"`
		}
		if err = agentCall(ctx, d, action, &request, &result); err != nil {
			if offline := managedAgentFailure(*base, action, err); offline != nil {
				return agentReply(*offline)
			}
			problem := describeConnectionError(err)
			var failure *installerError
			if errors.As(err, &failure) {
				return agentReply(agentResult{Action: action, Code: problem.Code, Message: err.Error(), Installation: &failure.Report})
			}
			return fail(problem.Code, err.Error())
		}
		if action == "invitation" {
			if result.ConnectionKey == "" {
				return fail("INVITATION_NOT_READY", "Provider has no active invitation")
			}
			if _, err = os.Stat(*output); !os.IsNotExist(err) {
				return fail("OUTPUT_EXISTS", "Choose a new output path; existing files are not overwritten")
			}
			if err = privateText(*output, result.ConnectionKey+"\n"); err != nil {
				return fail("OUTPUT_FAILED", "Cannot save invitation to the specified private file")
			}
			return agentReply(agentResult{Action: action, OK: true, Code: "INVITATION_SAVED", Message: "Saved to the requested file; share only with an authorized caller"})
		}
		if action == "disable-code" {
			return agentReply(agentResult{Action: action, OK: true, Code: "CONNECTION_CODE_DISABLED", Message: "Connection code disabled; its device can no longer use this HITL SSH connection"})
		}
		if action == "quit" || action == "stop" {
			return agentReply(agentResult{Action: action, OK: true, Code: "STOPPED", Message: "Only this panel's processes stopped; identity preserved"})
		}
	}
	var state guiState
	if err = agentCall(ctx, d, "state", nil, &state); err != nil {
		if result := managedAgentFailure(*base, action, err); result != nil {
			return agentReply(*result)
		}
		return fail("PANEL_UNAVAILABLE", err.Error())
	}
	if *wait || ((action == "allow" || action == "renew") && *output != "") {
		for deadline := time.Now().Add(300 * time.Second); time.Now().Before(deadline); {
			snapshot := agentStateResult(action, state)
			ready := state.HasInvitation && state.Role == "host"
			if ready || snapshot.LoginVerified {
				break
			}
			terminal := !state.Running || state.GrantDisabled || (state.Problem != nil && !state.Problem.Retryable)
			for _, step := range state.Steps {
				if step.Status == "failed" && (state.Problem == nil || !state.Problem.Retryable) {
					terminal = true
				}
			}
			if terminal {
				return agentReply(snapshot)
			}
			select {
			case <-ctx.Done():
				return fail("WAIT_CANCELLED", "Use agent status to inspect the continuing process")
			case <-time.After(time.Second):
			}
			if err = agentCall(ctx, d, "state", nil, &state); err != nil {
				if result := managedAgentFailure(*base, action, err); result != nil {
					return agentReply(*result)
				}
				return fail("PANEL_UNAVAILABLE", err.Error())
			}
		}
		if !state.HasInvitation && !agentStateResult(action, state).LoginVerified {
			return fail("WAIT_TIMEOUT", "Connection continues in the background; inspect agent status")
		}
	}
	if (action == "allow" || action == "renew") && *output != "" {
		var code struct {
			ConnectionKey string `json:"connectionKey"`
		}
		if err = agentCall(ctx, d, "invitation", &guiRequest{}, &code); err != nil || code.ConnectionKey == "" {
			return fail("INVITATION_NOT_READY", "Use agent status to inspect the provider")
		}
		if err = privateText(*output, code.ConnectionKey+"\n"); err != nil {
			return fail("OUTPUT_FAILED", "Cannot save connection code to the private output path")
		}
		return agentReply(agentResult{Action: action, OK: true, Code: "CONNECTION_CODE_READY", State: &state, Message: "Connection code saved; caller can connect without another approval"})
	}
	return agentReply(agentStateResult(action, state))
}
