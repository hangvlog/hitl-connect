package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Run the report sender in a separate process, as the UAC installer does.
// It fails before creating its directory; no shared result file is available.
func TestInstallerEarlyFailureChild(t *testing.T) {
	endpoint := os.Getenv("HITL_TEST_INSTALL_REPORT_URL")
	if endpoint == "" {
		return
	}
	err := os.Mkdir(os.Getenv("HITL_TEST_INSTALL_DIRECTORY"), 0700)
	if err == nil {
		t.Fatal("expected blocked directory creation")
	}
	if e := sendInstallReport(endpoint, os.Getenv("HITL_TEST_INSTALL_REPORT_TOKEN"), installReport("protect-install-root", err)); e != nil {
		t.Fatal(e)
	}
	os.Exit(2)
}

func TestInstallerReportsBeforeDirectoryExists(t *testing.T) {
	r, err := newInstallResultReceiver()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	blocked := filepath.Join(t.TempDir(), "do-not-disclose")
	if err := os.WriteFile(blocked, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(blocked, "not-created")
	cmd := exec.Command(os.Args[0], "-test.run=^TestInstallerEarlyFailureChild$")
	cmd.Env = append(os.Environ(), "HITL_TEST_INSTALL_REPORT_URL="+r.URL, "HITL_TEST_INSTALL_REPORT_TOKEN="+r.Token, "HITL_TEST_INSTALL_DIRECTORY="+base)
	output, processErr := cmd.CombinedOutput()
	var failure *installerError
	if !errors.As(installerOutcome(r.Result(), processErr), &failure) {
		t.Fatalf("report lost: %v %s", processErr, output)
	}
	got := failure.Report
	if got.OK || got.Stage != "protect-install-root" || got.Code != "HOST_INSTALL_FAILED" || got.NativeCode == nil || *got.NativeCode == 0 || got.Message == "" || strings.Contains(got.Message, "do-not-disclose") {
		t.Fatalf("invalid report: %+v", got)
	}
	if _, err = os.Stat(base); err == nil {
		t.Fatal("result required a directory")
	}
	g := newGUI(t.TempDir(), "unused")
	if g.connectionError(failure) || g.state.Steps[0].Status != "failed" || g.state.Problem.Side != "local" {
		t.Fatal("install failure misclassified as login/network failure", g.state)
	}
	if g.state.Installation == nil || g.state.Installation.Stage != got.Stage {
		t.Fatal("GUI lost installation report")
	}
	// Network-looking installer failures must not be relabelled or auto-retried.
	if describeConnectionError(&installerError{installReport("prepare-ssh", context.DeadlineExceeded)}).Retryable {
		t.Fatal("installer timeout became a network retry")
	}
}

func TestInstallerReportAuthenticationAndValidation(t *testing.T) {
	r, err := newInstallResultReceiver()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	report := installReport("protect-install-root", errors.New("INSTALL_DIRECTORY_UNPROTECTED"))
	data, _ := json.Marshal(report)
	post := func(token string, body []byte) int {
		t.Helper()
		req, _ := http.NewRequest("POST", r.URL, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	if post(strings.Repeat("0", 64), data) != 401 {
		t.Fatal("accepted wrong token")
	}
	for _, invalid := range [][]byte{[]byte(`{}`), append(append([]byte{}, data...), []byte(`{}`)...), []byte(strings.Repeat(" ", 9000))} {
		if post(r.Token, invalid) != 400 {
			t.Fatal("accepted malformed/oversize report")
		}
	}
	if r.Result() != nil {
		t.Fatal("invalid report consumed result")
	}
	if err := sendInstallReport(r.URL, r.Token, report); err != nil {
		t.Fatal(err)
	}
	if r.Result() == nil {
		t.Fatal("valid report missing")
	}
	if post(r.Token, data) != 409 {
		t.Fatal("accepted second result")
	}
	for _, endpoint := range []string{"https://127.0.0.1:1/install-result", "http://localhost:1/install-result", "http://192.0.2.1:1/install-result", r.URL + "?target=x", strings.Replace(r.URL, "127.0.0.1", "user@127.0.0.1", 1)} {
		if err := sendInstallReport(endpoint, r.Token, report); err == nil || err.Error() != "INSTALL_REPORT_ENDPOINT_INVALID" {
			t.Fatal(endpoint, err)
		}
	}
}

func TestInstallerOutcomeNeverAssumesSuccess(t *testing.T) {
	success := installReport("verify-service", nil)
	for _, scenario := range []struct {
		report  *installerReport
		process error
		code    string
	}{
		{nil, nil, "HOST_INSTALL_RESULT_MISSING"},
		{nil, fmt.Errorf("process exited with code 2"), "HOST_INSTALL_PROCESS_FAILED"},
		{&success, fmt.Errorf("process exited with code 2"), "HOST_INSTALL_PROCESS_FAILED"},
	} {
		var failure *installerError
		if !errors.As(installerOutcome(scenario.report, scenario.process), &failure) || failure.Report.Code != scenario.code || failure.Report.Message == "" {
			t.Fatalf("outcome missing: %+v", failure)
		}
	}
	if err := installerOutcome(&success, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAgentPreservesInstallerFailure(t *testing.T) {
	report := installReport("protect-install-root", syscall.Errno(5))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "HOST_INSTALL_FAILED", "installation": report})
	}))
	defer server.Close()
	err := agentCall(context.Background(), guiDescriptor{URL: server.URL}, "allow", &guiRequest{}, nil)
	var failure *installerError
	if !errors.As(err, &failure) || failure.Report.Stage != report.Stage || failure.Report.NativeCode == nil || *failure.Report.NativeCode != 5 {
		t.Fatal("CLI discarded installation evidence", err)
	}
}

func TestGUIRecoversExistingProviderAccount(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "public-host"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := privateJSON(filepath.Join(base, "public-host", "ssh-grant.json"), sshGrant{User: "configured-user"}); err != nil {
		t.Fatal(err)
	}
	g := newGUI(base, "unused")
	if g.state.AuthorizedUser != "configured-user" {
		t.Fatalf("restart lost configured account: %q", g.state.AuthorizedUser)
	}
}

func TestConnectionPlanKeepsExplicitKeyAndEndpoint(t *testing.T) {
	base := t.TempDir()
	g := newGUI(base, "unused")
	want := guiRequest{Role: "connect", Listen: "127.0.0.1:22499", KeyPath: "/existing/private-key", User: "account"}
	if err := g.savePlan(want, true); err != nil {
		t.Fatal(err)
	}
	resumed := newGUI(base, "unused")
	got, err := resumed.resolveRequest(guiRequest{})
	if err != nil || got.Role != want.Role || got.Listen != want.Listen || got.KeyPath != want.KeyPath {
		t.Fatalf("resume forgot config: %+v %v", got, err)
	}
	if err := g.savePlan(guiRequest{Role: "connect", ConnectionKey: "secret-code", KeyPath: want.KeyPath}, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(base, "connection-plan.json"))
	if strings.Contains(string(raw), "secret-code") {
		t.Fatal("saved a secret in the plan")
	}
}

func TestTemporaryFailuresRetryButRevocationDoesNot(t *testing.T) {
	for _, err := range []error{&relayFailure{status: 401}, &relayFailure{status: 503}, errors.New("relay accepted this device but could not pair the service")} {
		if !describeConnectionError(err).Retryable {
			t.Fatal(err)
		}
	}
	for _, code := range []string{"CONNECTION_CODE_DISABLED", "LOCAL_ACCOUNT_NOT_AUTHORIZED", "CONNECTION_CODE_INVALID_OR_REPLACED", "provider identity changed"} {
		if describeConnectionError(errors.New(code)).Retryable {
			t.Fatal(code)
		}
	}
}

func TestHostConsentRestoresWithoutChangingGrant(t *testing.T) {
	if needsHostElevation() {
		t.Skip("requires elevated Windows test")
	}
	profile := t.TempDir()
	for _, name := range []string{"identity.key", "connection-key-ssh.txt"} {
		if err := os.WriteFile(filepath.Join(profile, name), []byte("preserve-original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Repeat the save against an existing protected policy, as an upgrade does.
	for i := 0; i < 2; i++ {
		if err := saveHostAuthorization(profile, localSSHUser(), "127.0.0.1:22"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"identity.key", "connection-key-ssh.txt"} {
		data, err := os.ReadFile(filepath.Join(profile, name))
		if err != nil || string(data) != "preserve-original" {
			t.Fatal("authorization changed identity/code", err)
		}
	}
	saved, err := savedHostAccount(profile)
	if err != nil || saved.User != localSSHUser() {
		t.Fatal(saved, err)
	}
	other := t.TempDir()
	data, _ := os.ReadFile(filepath.Join(profile, "host-authorization.json"))
	if err = os.WriteFile(filepath.Join(other, "host-authorization.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = savedHostAccount(other); err == nil {
		t.Fatal("copied consent authorized another profile")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(profile, ".host-authorization-*")); len(leftovers) != 0 {
		t.Fatal("temporary policy left behind", leftovers)
	}
}

func TestAuthorizationIsProtectedBeforeFirstWrite(t *testing.T) {
	if needsHostElevation() {
		t.Skip("requires elevated Windows test")
	}
	f, err := createAuthorizationFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("policy was written before checking protection", err)
	}
	if err = checkAuthorizationProtection(f); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("policy is not private: %v", info.Mode())
	}
}

func TestAuthorizationCommitFailureRetainsDataAndReportsOperation(t *testing.T) {
	if needsHostElevation() {
		t.Skip("requires elevated Windows test")
	}
	profile := t.TempDir()
	blocked := filepath.Join(profile, "host-authorization.json")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(blocked, "keep")
	if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	err := saveHostAuthorization(profile, localSSHUser(), "127.0.0.1:22")
	if err == nil {
		t.Fatal("expected commit to refuse replacing a nonempty directory")
	}
	r := installReport("save-authorization", err)
	if r.Code != "HOST_AUTHORIZATION_COMMIT_FAILED" || r.NativeCode == nil || r.OK {
		t.Fatalf("operation/native reason lost: %+v", r)
	}
	data, readErr := os.ReadFile(marker)
	if readErr != nil || string(data) != "original" {
		t.Fatal("failed commit changed existing data", readErr)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(profile, ".host-authorization-*")); len(leftovers) != 0 {
		t.Fatal("failed commit leaked temporary policy", leftovers)
	}
	for _, operation := range []string{"CREATE", "PROTECTION", "READBACK"} {
		report := installReport("save-authorization", fmt.Errorf("HOST_AUTHORIZATION_%s_FAILED: %w", operation, syscall.Errno(5)))
		if report.Code != "HOST_AUTHORIZATION_"+operation+"_FAILED" || report.NativeCode == nil || *report.NativeCode != 5 {
			t.Fatal("native Windows code lost", report)
		}
	}
}

func TestManagedServiceScopeCannotBeChangedByLocalAPI(t *testing.T) {
	p := &hostAuthorization{User: "allowed", Address: "127.0.0.1:22"}
	for _, r := range []guiRequest{{Role: "connect"}, {User: "administrator"}, {Target: "127.0.0.1:3389"}, {KeyPath: "C:/Windows/secret"}, {ConnectionKey: "a"}, {ManualSSH: true}, {Listen: "127.0.0.1:2222"}} {
		if validateManagedAction(p, "start", r) == nil {
			t.Fatalf("accepted changed scope: %+v", r)
		}
	}
	for _, action := range []string{"approve", "reject", "trust", "request-access"} {
		if validateManagedAction(p, action, guiRequest{}) == nil {
			t.Fatal(action)
		}
	}
	for _, action := range []string{"start", "allow", "stop", "diagnose", "invitation", "renew", "disable-code"} {
		if e := validateManagedAction(p, action, guiRequest{}); e != nil {
			t.Fatal(e)
		}
	}
}

func TestManagedPanelMissingSessionKeepsOfflineDiagnostics(t *testing.T) {
	base, managed := t.TempDir(), t.TempDir()
	if err := privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{managed}); err != nil {
		t.Fatal(err)
	}
	g := newGUI(base, "must-not-execute")
	g.origin = "http://127.0.0.1:32123"
	if err := privateJSON(filepath.Join(base, "connection-plan.json"), connectionPlan{Version: 1, Role: "host", Resume: true}); err != nil {
		t.Fatal(err)
	}
	g.resumeOnOpen()
	if g.state.Problem != nil || g.child != nil {
		t.Fatal("desktop tried to resume an offline managed provider")
	}
	request := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, g.origin+path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+g.token)
		r.Header.Set("Origin", g.origin)
		w := httptest.NewRecorder()
		g.handler().ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/state")
	var state guiState
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &state) != nil || !state.Managed || state.Running || state.Problem == nil || state.Problem.Retryable {
		t.Fatalf("offline panel did not render diagnostics: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), managed) || strings.Contains(w.Body.String(), "gui-session.json") {
		t.Fatal("raw session path leaked instead of service diagnosis")
	}
	if w = request("POST", "/api/allow"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline action fell back to installation: %d %s", w.Code, w.Body.String())
	}
	if w = request("POST", "/api/diagnose"); w.Code != http.StatusOK {
		t.Fatalf("read-only diagnosis unavailable: %d %s", w.Code, w.Body.String())
	}
	files, err := os.ReadDir(managed)
	if err != nil || len(files) != 0 {
		t.Fatal("offline requests changed managed profile", err)
	}
	// Once the existing service returns, use its live state again. Business
	// rejections from a responding service must not become offline diagnostics.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/state" {
			_ = json.NewEncoder(w).Encode(guiState{Managed: true, Running: true})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "HOST_SCOPE_FIXED"})
	}))
	defer upstream.Close()
	if err := privateJSON(filepath.Join(managed, "gui-session.json"), guiDescriptor{upstream.URL, strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/api/state")
	state = guiState{}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &state) != nil || !state.Running || state.ManagedUnavailable {
		t.Fatal("panel did not recover when existing service returned", w.Body.String())
	}
	if w = request("POST", "/api/allow"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "HOST_SCOPE_FIXED") {
		t.Fatal("business rejection misclassified as offline", w.Body.String())
	}
}
func TestProfileLockReleasedWithoutDeletingIdentity(t *testing.T) {
	base := t.TempDir()
	release, ok, e := tryProfileLock(base, ".test.lock")
	if e != nil || !ok {
		t.Fatal(e)
	}
	_, ok, e = tryProfileLock(base, ".test.lock")
	if e != nil || ok {
		t.Fatal("second holder accepted", e)
	}
	release()
	release, ok, e = tryProfileLock(base, ".test.lock")
	if e != nil || !ok {
		t.Fatal("lock not released", e)
	}
	release()
}

func TestFilesystemGenericRightsAreEquivalentToMappedRights(t *testing.T) {
	expected := fileACL{Owner: "admin", Group: "admin", Protected: true, Entries: []fileACE{
		{"system", 0, 3, 0x1f01ff}, {"admin", 0, 3, 0x1f01ff}, {"reader", 0, 3, 0xa0000000},
	}}
	mapped := expected
	mapped.Entries = []fileACE{{"reader", 0, 3, 0x1200a9}, {"admin", 0, 3, 0x1f01ff}, {"system", 0, 3, 0x1f01ff}}
	if !sameFileACL(mapped, expected) {
		t.Fatal("equivalent NTFS read/execute rights rejected after generic mapping/ACE canonicalization")
	}
}

func TestFilesystemACLStillRejectsBroaderAccess(t *testing.T) {
	expected := fileACL{Owner: "admin", Group: "admin", Protected: true, Entries: []fileACE{{"admin", 0, 3, 0x1f01ff}, {"reader", 0, 3, 0x1200a9}}}
	for _, change := range []func(*fileACL){
		func(a *fileACL) { a.Protected = false }, func(a *fileACL) { a.Owner = "reader" },
		func(a *fileACL) { a.Entries = append(a.Entries, fileACE{"everyone", 0, 3, 0x1f01ff}) },
		func(a *fileACL) { a.Entries[1].Mask |= 2 }, func(a *fileACL) { a.Entries[1].Mask |= 0x40000 },
		func(a *fileACL) { a.Entries[0].Flags = 0 }, func(a *fileACL) { a.Entries[0].Flags |= 0x10 },
		func(a *fileACL) { a.Entries[1].Type = 1 },
	} {
		actual := expected
		actual.Entries = append([]fileACE{}, expected.Entries...)
		change(&actual)
		if sameFileACL(actual, expected) {
			t.Fatalf("accepted changed authorization: %+v", actual)
		}
	}
	split := expected
	split.Entries = []fileACE{{"admin", 0, 3, 0x1f01ff}, {"reader", 0, 0, 0x1200a9}, {"reader", 0, 11, 0xa0000000}}
	if !sameFileACL(split, expected) {
		t.Fatal("equivalent effective/inherit-only ACE split rejected")
	}
}
