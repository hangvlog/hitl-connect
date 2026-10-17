package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// This explicit provider uses Microsoft's installed sshd for authentication,
// command execution and SFTP. HITL remains the visible interactive relay app;
// it creates no replacement service, scheduled task or account-token worker.
func runSystemSSHHost(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("system-ssh-host", flag.ContinueOnError)
	base := f.String("dir", "", "existing desktop profile")
	bind := f.String("ui-address", "127.0.0.1:0", "loopback panel")
	prepare := f.Bool("prepare-only", false, "prepare system SSH without starting the relay")
	open := f.Bool("open", false, "open the local panel after starting")
	reportURL := f.String("install-report-url", "", "local result endpoint")
	reportToken := f.String("install-report-token", "", "local result capability")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *base == "" {
		return errors.New("EXISTING_PROFILE_REQUIRED")
	}
	stage := "validate-elevation"
	root, policy, err := prepareSystemSSH(ctx, *base, &stage)
	report := installReport(stage, err)
	if err == nil {
		report.Code, report.Message = "SYSTEM_SSH_READY", "系统 OpenSSH 已准备，远程登录仍需验证"
	}
	if *reportURL != "" {
		if e := sendInstallReport(*reportURL, *reportToken, report); e != nil && err == nil {
			return e
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	if err != nil || *prepare {
		return err
	}
	servicePolicy = &policy // Same account-scoped local API, without SCM/WTS.
	return runGUI(ctx, root, *bind, !*open)
}

func prepareSystemSSH(ctx context.Context, base string, stage *string) (string, hostAuthorization, error) {
	return prepareSystemSSHOwner(ctx, base, stage, "")
}

func prepareSystemSSHOwner(ctx context.Context, base string, stage *string, ownerSID string) (string, hostAuthorization, error) {
	var policy hostAuthorization
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", policy, errors.New("ELEVATION_REQUIRED")
	}
	sid, err := currentOwnerSID()
	if err != nil {
		return "", policy, err
	}
	*stage = "read-existing-authorization"
	isService := false
	if ownerSID != "" {
		isService, err = svc.IsWindowsService()
		if err != nil {
			return "", policy, err
		}
	}
	root, sid, err := systemSSHProfile(base, sid, ownerSID, isService)
	if err != nil {
		return root, policy, err
	}
	profile := filepath.Join(root, "public-host")
	policy, err = readHostAuthorization(profile)
	if err != nil {
		return root, policy, err
	}
	if ownerSID != "" && policy.SID != ownerSID {
		return root, policy, errors.New("HOST_SCOPE_FIXED")
	}
	if policy.Privilege != "administrator" || (policy.Engine != "embedded" && policy.Engine != "openssh") {
		return root, policy, errors.New("SYSTEM_SSH_ADMINISTRATOR_MIGRATION_REQUIRED")
	}
	name, accountSID, err := nativeLocalAccount(policy.User)
	if err != nil || accountSID != policy.SID {
		return root, policy, errors.New("HOST_SCOPE_FIXED")
	}
	*stage = "inspect-system-sshd"
	m, service, err := nativeSSHService(true)
	if m != nil {
		defer m.Disconnect()
	}
	if err != nil {
		return root, policy, err
	}
	defer service.Close()
	cfg, err := service.Config()
	if err != nil {
		return root, policy, err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return root, policy, err
	}
	if err = prepareSystemSSHAlias(ctx, cfg.BinaryPathName, system); err != nil {
		return root, policy, err
	}
	exe, err := systemSSHExecutable(cfg.BinaryPathName, system)
	if err != nil {
		return root, policy, err
	}
	state, err := service.Query()
	if err != nil {
		return root, policy, err
	}
	if state.State != svc.Stopped && policy.Engine != "openssh" {
		return root, policy, errors.New("EXISTING_SSHD_RUNNING")
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return root, policy, err
	}
	config := filepath.Join(pd, "ssh", "sshd_config")
	*stage = "prepare-system-ssh-config"
	// Reference the existing host keys, preserving pinned identities. Never
	// regenerate, disclose or weaken their administrator-only permissions.
	var hostKeys []string
	var expectedKeys []ssh.PublicKey
	for _, kind := range []string{"ed25519", "ecdsa", "rsa"} {
		path := filepath.Join(profile, "ssh-host-"+kind+".key")
		data, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return root, policy, e
		}
		key, e := ssh.ParsePrivateKey(data)
		if e != nil {
			return root, policy, errors.New("EXISTING_HOST_KEY_INVALID")
		}
		hostKeys = append(hostKeys, "HostKey \""+filepath.ToSlash(path)+"\"\r\n")
		expectedKeys = append(expectedKeys, key.PublicKey())
	}
	if len(hostKeys) == 0 {
		return root, policy, errors.New("EXISTING_HOST_KEY_MISSING")
	}
	keyFile := filepath.Join(profile, "openssh.authorized_keys")
	want := []byte("# HITL Connect system OpenSSH provider\r\nPort 22\r\nListenAddress 127.0.0.1\r\n" + strings.Join(hostKeys, "") + "PubkeyAuthentication yes\r\nPasswordAuthentication no\r\nKbdInteractiveAuthentication no\r\nAuthenticationMethods publickey\r\nAllowUsers " + strings.ToLower(name) + "\r\nAuthorizedKeysFile \"" + filepath.ToSlash(keyFile) + "\"\r\nAllowTcpForwarding no\r\nAllowAgentForwarding no\r\nX11Forwarding no\r\nPermitTunnel no\r\nPermitTTY no\r\nLogLevel VERBOSE\r\nSubsystem sftp sftp-server.exe\r\n")
	if service.Name == systemSSHServerService {
		if err = prepareSystemSFTPAlias(ctx, system, service); err != nil {
			return root, policy, err
		}
		want, err = namedSFTPConfig(want, system)
		if err != nil {
			return root, policy, err
		}
	}
	if old, e := os.ReadFile(config); e == nil {
		if !bytes.Equal(old, want) {
			return root, policy, errors.New("EXISTING_SSHD_CONFIG_REVIEW_REQUIRED")
		}
	} else if os.IsNotExist(e) {
		if e = nativeSSHDirectory(filepath.Dir(config), sshSDDL("S-1-5-32-544", false, true)); e != nil {
			return root, policy, e
		}
		if e = nativeSSHWrite(config, want, sshSDDL("S-1-5-32-544", false, false)); e != nil {
			return root, policy, e
		}
	} else {
		return root, policy, e
	}
	if _, err = nativeSSHCommand(ctx, exe, "-t", "-f", config); err != nil {
		return root, policy, fmt.Errorf("SYSTEM_SSH_CONFIG_INVALID: %w", err)
	}
	*stage = "prepare-authorized-keys"
	unlock, err := lockAccess(profile)
	if err != nil {
		return root, policy, err
	}
	keys, err := systemSSHKeys(profile, policy, nil)
	if err == nil {
		err = nativeSSHWrite(keyFile, keys, sshSDDL("S-1-5-32-544", false, false))
	}
	unlock()
	if err != nil {
		return root, policy, err
	}
	*stage = "start-system-sshd"
	if err = nativeStartSSH(ctx, service, false); err != nil {
		return root, policy, err
	}
	key, err := probeSSH("127.0.0.1:22", expectedKeys[0].Type())
	if err != nil {
		return root, policy, err
	}
	if !bytes.Equal(key.Marshal(), expectedKeys[0].Marshal()) {
		return root, policy, errors.New("HOST_KEY_MIGRATION_CONFLICT")
	}
	*stage = "save-system-ssh-authorization"
	if policy.Engine != "openssh" {
		backup := filepath.Join(profile, "host-authorization.before-openssh.json")
		if _, e := os.Stat(backup); os.IsNotExist(e) {
			if err = copyInstallFile(filepath.Join(profile, "host-authorization.json"), backup); err != nil {
				return root, policy, err
			}
		} else if e != nil {
			return root, policy, e
		}
		policy.Version, policy.Engine, policy.Address = 3, "openssh", "127.0.0.1:22"
		if err = writeHostAuthorization(profile, policy); err != nil {
			return root, policy, err
		}
	}
	plan, err := readConnectionPlan(root)
	if err != nil {
		return root, policy, err
	}
	plan.Host.Target = policy.Address
	if err = privateJSON(filepath.Join(root, "connection-plan.json"), plan); err != nil {
		return root, policy, err
	}
	*stage = "system-ssh-ready"
	return root, policy, nil
}

func systemSSHProfile(base, callerSID, ownerSID string, isService bool) (string, string, error) {
	sid := callerSID
	if ownerSID != "" {
		if !isService || callerSID != "S-1-5-18" {
			return "", "", errors.New("SERVICE_MANAGER_REQUIRED")
		}
		sid = ownerSID
	}
	expected, _, err := managedLocation(base, sid)
	if err != nil {
		return "", sid, err
	}
	if ownerSID != "" {
		// SCM fixes the owner and base. Boot must not depend on a user's AppData
		// locator (which can be missing or redirected). The caller still reads
		// the protected authorization and verifies its SID before using this root.
		return expected, sid, nil
	}
	root, err := managedProfile(base)
	if err != nil || root == "" {
		return "", sid, errors.New("EXISTING_MANAGED_PROFILE_REQUIRED")
	}
	if !strings.EqualFold(canonicalProfile(root), canonicalProfile(expected)) {
		return root, sid, errors.New("MANAGED_PROFILE_INVALID")
	}
	return root, sid, nil
}

func installSystemSSHKey(profile string, candidate sshAccess, account string) agentResult {
	unlock, err := lockAccess(profile)
	if err != nil {
		return agentResult{Code: "ACCESS_BUSY"}
	}
	defer unlock()
	return installSystemSSHKeyLocked(profile, candidate, account)
}

func installSystemSSHKeyLocked(profile string, candidate sshAccess, account string) agentResult {
	p, ok := systemSSHPolicy(profile)
	if !ok || p.User != account {
		return agentResult{Code: "HOST_SCOPE_FIXED"}
	}
	keys, err := systemSSHKeys(profile, p, &candidate)
	if err == nil {
		err = nativeSSHWrite(filepath.Join(profile, "openssh.authorized_keys"), keys, sshSDDL("S-1-5-32-544", false, false))
	}
	if err != nil {
		return agentResult{Code: "SYSTEM_SSH_KEY_INSTALL_FAILED", Message: err.Error()}
	}
	return agentResult{OK: true}
}

// Caller holds the grant metadata lock. Remove revoked keys from the private
// system-SSH key file too, so loopback cannot reuse a disabled HITL grant.
func syncSystemSSHKeys(profile string) error {
	p, ok := systemSSHPolicy(profile)
	if !ok {
		return nil
	}
	keys, err := systemSSHKeys(profile, p, nil)
	if err != nil {
		return err
	}
	return nativeSSHWrite(filepath.Join(profile, "openssh.authorized_keys"), keys, sshSDDL("S-1-5-32-544", false, false))
}
