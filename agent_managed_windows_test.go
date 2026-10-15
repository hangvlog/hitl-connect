package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedAgentCommandChild(t *testing.T) {
	base := os.Getenv("HITL_TEST_AGENT_PROFILE")
	if base == "" {
		return
	}
	err := runAgent(context.Background(), []string{os.Getenv("HITL_TEST_AGENT_ACTION"), "--dir", base})
	var exit *agentExit
	if errors.As(err, &exit) {
		os.Exit(exit.code)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func runManagedAgentTest(t *testing.T, base, action string, wantExit int) agentResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestManagedAgentCommandChild$")
	cmd.Env = append(os.Environ(), "HITL_TEST_AGENT_PROFILE="+base, "HITL_TEST_AGENT_ACTION="+action)
	data, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	var result agentResult
	if code != wantExit || json.Unmarshal(data, &result) != nil {
		t.Fatalf("exit=%d output=%s", code, data)
	}
	if strings.Contains(string(data), base) || strings.Contains(string(data), strings.Repeat("a", 64)) {
		t.Fatal("profile path or local capability leaked")
	}
	return result
}

func TestManagedAgentMissingServiceReportsNativeDiagnosis(t *testing.T) {
	for _, stale := range []bool{false, true} {
		base := t.TempDir()
		sid, err := currentOwnerSID()
		if err != nil {
			t.Fatal(err)
		}
		managed, _, err := managedLocation(base, sid)
		if err != nil {
			t.Fatal(err)
		}
		if err = privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{managed}); err != nil {
			t.Fatal(err)
		}
		// Only a user-owned locator is written. No ProgramData directory or
		// Windows service is created, deleted, or started by this regression.
		locator, _ := os.ReadFile(filepath.Join(base, "managed-host.json"))
		if stale {
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			server.Close()
			// A stale desktop session must never be selected as a replacement
			// for the missing managed service session.
			if err = privateJSON(filepath.Join(base, "gui-session.json"), guiDescriptor{server.URL, strings.Repeat("a", 64)}); err != nil {
				t.Fatal(err)
			}
		}
		for _, action := range []string{"status", "diagnose", "start", "allow", "stop"} {
			result := runManagedAgentTest(t, base, action, 2)
			if result.Code != "HOST_SERVICE_NOT_REGISTERED" || result.OK || result.LoginVerified || result.State == nil || !result.State.ManagedUnavailable || result.State.Service == nil || result.State.Service.NativeCode == nil || *result.State.Service.NativeCode != 1060 {
				t.Fatalf("%s: %+v", action, result)
			}
			if len(result.NextActions) != 1 || strings.Contains(result.NextActions[0], "agent start") {
				t.Fatal("missing service suggested another start", result.NextActions)
			}
		}
		got, _ := os.ReadFile(filepath.Join(base, "managed-host.json"))
		if string(got) != string(locator) {
			t.Fatal("locator modified")
		}
		if _, err = os.Stat(managed); !os.IsNotExist(err) {
			t.Fatal("diagnosis created managed profile", err)
		}
	}
}

func TestManagedAgentLiveServiceAndRejectionsRemainAuthoritative(t *testing.T) {
	base, managed := t.TempDir(), t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/state" {
			_ = json.NewEncoder(w).Encode(guiState{Managed: true, Running: true, Role: "host", HasInvitation: true})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "HOST_SCOPE_FIXED"})
	}))
	defer server.Close()
	if err := privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{managed}); err != nil {
		t.Fatal(err)
	}
	if err := privateJSON(filepath.Join(managed, "gui-session.json"), guiDescriptor{server.URL, strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	result := runManagedAgentTest(t, base, "status", 0)
	if !result.OK || result.State == nil || !result.State.Running || result.State.ManagedUnavailable || result.LoginVerified {
		t.Fatal("live state replaced or login falsely verified", result)
	}
	result = runManagedAgentTest(t, base, "allow", 2)
	if result.State != nil || !strings.Contains(result.Message, "HOST_SCOPE_FIXED") {
		t.Fatal("service rejection replaced", result)
	}
	for _, cause := range []error{&agentResponseError{"denied"}, &installerError{installReport("test", errors.New("denied"))}} {
		if managedAgentFailure(base, "allow", cause) != nil {
			t.Fatal("authoritative failure replaced", cause)
		}
	}
	server.Close()
	result = runManagedAgentTest(t, base, "status", 2)
	if result.State == nil || !result.State.ManagedUnavailable {
		t.Fatal("stale managed session lost diagnostics", result)
	}
}

func TestManagedAgentPreservesUnmanagedAndInvalidLocators(t *testing.T) {
	base := t.TempDir()
	result := runManagedAgentTest(t, base, "status", 2)
	if result.Code != "PANEL_NOT_RUNNING" || result.State != nil {
		t.Fatal("unmanaged profile changed", result)
	}
	if err := privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{"relative-path"}); err != nil {
		t.Fatal(err)
	}
	result = runManagedAgentTest(t, base, "diagnose", 2)
	if result.Code != "MANAGED_PROFILE_INVALID" || result.State != nil || result.OK {
		t.Fatal("invalid locator became install/start advice", result)
	}
}
