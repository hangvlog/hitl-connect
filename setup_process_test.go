package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestSetupProtectionFailuresPreserveOnlySafeEvidence(t *testing.T) {
	for _, code := range []syscall.Errno{225, 226, 1260} {
		r := newSSHSetupReport()
		r.failure(code)
		if setupBool(r, "ok") || setupString(r, "code") != "SETUP_BLOCKED_BY_POLICY_OR_PROTECTION" || r["nativeCode"] != uint32(code) {
			t.Fatal(r)
		}
	}
	r := newSSHSetupReport()
	r.failure(context.DeadlineExceeded)
	if r["code"] != "SETUP_OUTCOME_UNKNOWN" {
		t.Fatal(r)
	}
}
func TestScopedSSHConfigPreservesExistingPolicy(t *testing.T) {
	original := []byte("Port 2202\r\n# Keep policies\r\nMatch Group administrators\r\n AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n")
	updated := scopedSSHConfig(original, "S-1-5-21-1", "Alice", "__PROGRAMDATA__/ssh/administrators_authorized_keys")
	if !bytes.Contains(updated, []byte("Match User alice\r\n")) || !bytes.HasPrefix(updated, []byte("Port 2202\r\n# Keep policies\r\n")) || !bytes.HasSuffix(updated, original[bytes.Index(original, []byte("Match Group")):]) {
		t.Fatal(string(updated))
	}
	if strings.Index(string(updated), "Match User") > strings.Index(string(updated), "Match Group") {
		t.Fatal("account rule must precede group fallback")
	}
	settings := sshEffectiveSettings([]byte("port 2202\r\nauthorizedkeysfile one two\r\n"))
	if settings["port"] != "2202" || settings["authorizedkeysfile"] != "one two" {
		t.Fatal(settings)
	}
}
func TestNativeSetupHasNoPowerShellExecution(t *testing.T) {
	// Protect every installer/grant entry, not only the first setup operation.
	for _, name := range []string{"agent_setup.go", "setup_process.go", "setup_native_windows.go", "setup_acl_windows.go", "managed_install_windows.go", "managed_launch_windows.go", "ssh_grant.go", "ssh_grant_install.go"} {
		b, e := os.ReadFile(name)
		if os.IsNotExist(e) {
			t.Skip("source not present in packaged native test")
		}
		if e != nil {
			t.Fatal(e)
		}
		for _, forbidden := range []string{"powershell.exe", "EncodedCommand", "ExecutionPolicy", "windowsSetupScript", "checkSetupPolicy", ".ps1"} {
			if bytes.Contains(b, []byte(forbidden)) {
				t.Fatalf("%s still depends on %s", name, forbidden)
			}
		}
	}
}
func TestSetupReportIsStructured(t *testing.T) {
	r := newSSHSetupReport()
	r.failure(syscall.Errno(5))
	data, e := json.Marshal(r)
	if e != nil || !bytes.Contains(data, []byte(`"powerShellRequired":false`)) || r["elevationRequired"] != true {
		t.Fatal(string(data), e)
	}
}
