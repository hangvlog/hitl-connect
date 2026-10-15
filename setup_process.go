package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type sshSetupInput struct {
	User, PublicKey, Fingerprint                           string
	Apply, InstallServer, PrepareOnly, ScopedAuthorization bool
}
type sshSetupReport map[string]any

func setupString(r sshSetupReport, key string) string { v, _ := r[key].(string); return v }
func setupBool(r sshSetupReport, key string) bool     { v, _ := r[key].(bool); return v }
func (r sshSetupReport) change(v string)              { r["changes"] = append(r["changes"].([]string), v) }
func (r sshSetupReport) fail(code, message string) error {
	r["ok"], r["code"], r["message"] = false, code, message
	return errors.New(code)
}
func newSSHSetupReport() sshSetupReport {
	return sshSetupReport{"ok": false, "code": "CHECKING", "message": "", "configurationReady": false, "loginVerified": false, "elevationRequired": false, "changes": []string{}, "backupDirectory": nil, "setupEngine": "windows-native", "powerShellRequired": false}
}
func (r sshSetupReport) failure(err error) {
	if err == nil {
		return
	}
	r["ok"] = false
	if setupString(r, "code") == "CHECKING" {
		r["code"], r["message"] = "WINDOWS_CHECK_FAILED", "Native Windows SSH setup failed; inspect the reported stage and native code"
		if regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(err.Error()) {
			r["code"] = err.Error()
		}
	}
	var code syscall.Errno
	if errors.As(err, &code) {
		r["nativeCode"] = uint32(code)
		if code == 5 {
			r["code"], r["message"], r["elevationRequired"] = "ELEVATION_REQUIRED", "Windows denied access to this operation", true
		}
		if code == 225 || code == 226 || code == 1260 {
			r["code"], r["message"] = "SETUP_BLOCKED_BY_POLICY_OR_PROTECTION", "Windows application control or endpoint protection blocked setup; preserve the report for administrator review"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		r["code"], r["message"] = "SETUP_OUTCOME_UNKNOWN", "Setup timed out or was cancelled; inspect system state before retrying"
	}
}
func nativeSetupPreflight(_ context.Context) agentResult {
	r := newSSHSetupReport()
	ok := runtime.GOOS == "windows"
	r["ok"], r["code"], r["message"] = ok, "NATIVE_SETUP_AVAILABLE", "Default provider uses HITL Connect embedded SSH and Windows native APIs; no system OpenSSH or PowerShell required. Legacy setup-ssh remains explicitly available. Execution policy is preserved"
	if !ok {
		r["code"], r["message"] = "WINDOWS_REQUIRED", "Run this check on the Windows provider"
	}
	data, _ := json.Marshal(r)
	return agentResult{Action: "preflight", OK: ok, Code: setupString(r, "code"), Message: setupString(r, "message"), Setup: data}
}
func sshEffectiveSettings(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) == 2 {
			out[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}
func scopedSSHConfig(original []byte, sid, user, current string) []byte {
	scoped := "__PROGRAMDATA__/ssh/hitl-" + sid + ".authorized_keys"
	block := "# HITL account-specific authorization " + sid + "\r\nMatch User " + strings.ToLower(user) + "\r\n    AuthorizedKeysFile " + scoped + " " + current + "\r\nMatch all\r\n"
	text := string(bytes.TrimPrefix(original, []byte{0xef, 0xbb, 0xbf}))
	index := regexp.MustCompile(`(?im)^[\t ]*Match[\t ]+`).FindStringIndex(text)
	if index != nil {
		return []byte(text[:index[0]] + block + text[index[0]:])
	}
	return []byte(strings.TrimRight(text, "\r\n") + "\r\n" + block)
}
func authorizedFingerprint(data []byte, fingerprint string) bool {
	// Check one line at a time; preserve comments and restricted existing keys.
	for _, line := range bytes.Split(data, []byte("\n")) {
		k, _, _, _, e := ssh.ParseAuthorizedKey(line)
		if e == nil && ssh.FingerprintSHA256(k) == fingerprint {
			return true
		}
	}
	return false
}
