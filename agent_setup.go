package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func runWindowsSetup(ctx context.Context, user, publicFile, expected string, apply, install bool) error {
	return agentReply(windowsSetup(ctx, user, publicFile, expected, apply, install, false))
}

func windowsSetup(ctx context.Context, user, publicFile, expected string, apply, install, prepare bool, scoped ...bool) agentResult {
	fail := func(code, message string) agentResult {
		return agentResult{Action: "setup-ssh", Code: code, Message: message}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_.\\-]{1,128}$`).MatchString(user) {
		return fail("LOCAL_USER_REQUIRED", "Specify the authorized local Windows account with --user")
	}
	var publicKey string
	if publicFile != "" {
		data, err := os.ReadFile(publicFile)
		if err != nil || len(data) > 16384 {
			return fail("PUBLIC_KEY_INVALID", "Cannot read the supplied public key")
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return fail("PUBLIC_KEY_INVALID", "Provide exactly one plain SSH public key, never a private key")
		}
		if expected != "" && expected != ssh.FingerprintSHA256(key) {
			return fail("PUBLIC_KEY_MISMATCH", "Supplied public key differs from the authorized fingerprint")
		}
		expected = ssh.FingerprintSHA256(key)
		publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
	if !prepare && !regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(expected) {
		return fail("APPROVED_KEY_REQUIRED", "Supply --public-key or the independently approved --fingerprint")
	}
	if runtime.GOOS != "windows" {
		return fail("WINDOWS_REQUIRED", "Windows setup must run on the target Windows computer; no system changes performed")
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	report := nativeWindowsSetup(ctx, sshSetupInput{User: user, PublicKey: publicKey, Fingerprint: expected, Apply: apply, InstallServer: install, PrepareOnly: prepare, ScopedAuthorization: len(scoped) > 0 && scoped[0]})
	result := struct {
		OK                  bool
		Code, Message, Port string
	}{setupBool(report, "ok"), setupString(report, "code"), setupString(report, "message"), setupString(report, "port")}
	if result.OK {
		key, probeErr := probeSSH(net.JoinHostPort("127.0.0.1", result.Port))
		report["localSshReachable"] = probeErr == nil
		if probeErr != nil {
			result.OK, result.Code = false, "LOCAL_SSH_UNREACHABLE"
			result.Message = "Service configuration passed but SSH is not reachable at its reported loopback port"
			report["configurationReady"] = false
		} else {
			report["hostFingerprint"] = ssh.FingerprintSHA256(key)
		}
	}
	report["ok"], report["code"], report["message"] = result.OK, result.Code, result.Message
	data, _ := json.Marshal(report)
	return agentResult{Action: "setup-ssh", OK: result.OK, Code: result.Code, Message: result.Message, Setup: data, NextActions: []string{"If elevationRequired=true, run this exact command in an administrator terminal after the user accepts UAC", "After configurationReady=true, start the provider and verify whoami from the caller; local checks never prove remote login"}}
}
