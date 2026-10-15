package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// USER_INFO_1 is returned by NetUserGetInfo on the local computer. Resolving a
// name alone is insufficient: a domain user must never alias a local account.
type localUserInfo1 struct {
	Name, Password    *uint16
	PasswordAge, Priv uint32
	HomeDir, Comment  *uint16
	Flags             uint32
	ScriptPath        *uint16
}

func nativeLocalAccount(account string) (name, sid string, err error) {
	resolved, _, kind, e := windows.LookupSID("", account)
	if e != nil || kind != windows.SidTypeUser {
		return "", "", errors.New("LOCAL_ACCOUNT_REQUIRED")
	}
	name, _, _, e = resolved.LookupAccount("")
	if e != nil {
		return "", "", e
	}
	user, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return "", "", e
	}
	var buffer *byte
	if e = windows.NetUserGetInfo(nil, user, 1, &buffer); e != nil {
		return "", "", errors.New("LOCAL_ACCOUNT_REQUIRED")
	}
	defer windows.NetApiBufferFree(buffer)
	info := (*localUserInfo1)(unsafe.Pointer(buffer))
	computer, e := os.Hostname()
	if e != nil {
		return "", "", e
	}
	local, _, kind, e := windows.LookupSID("", computer+`\`+name)
	if e != nil || kind != windows.SidTypeUser || !windows.EqualSid(local, resolved) {
		return "", "", errors.New("LOCAL_ACCOUNT_REQUIRED")
	}
	if info.Flags&2 != 0 {
		return "", "", errors.New("ACCOUNT_DISABLED")
	}
	return name, resolved.String(), nil
}
func nativeSSHService(apply bool) (*mgr.Mgr, *mgr.Service, error) {
	access := uint32(windows.SC_MANAGER_CONNECT)
	if apply {
		access |= windows.SC_MANAGER_CREATE_SERVICE
	}
	h, e := windows.OpenSCManager(nil, nil, access)
	if e != nil {
		return nil, nil, e
	}
	m := &mgr.Mgr{Handle: h}
	desired := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	if apply {
		desired |= windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_START | windows.SERVICE_STOP | windows.DELETE
	}
	for _, name := range []string{systemSSHServerService, "sshd"} {
		n, _ := windows.UTF16PtrFromString(name)
		sh, e := windows.OpenService(h, n, desired)
		if errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) && name == systemSSHServerService {
			continue
		}
		if e != nil {
			return m, nil, e
		}
		s := &mgr.Service{Name: name, Handle: sh}
		if name == systemSSHServerService {
			cfg, err := s.Config()
			if err == nil {
				err = validateNamedSSHService(cfg)
			}
			if err != nil {
				s.Close()
				return m, nil, err
			}
		}
		return m, s, nil
	}
	return m, nil, windows.ERROR_SERVICE_DOES_NOT_EXIST
}
func nativeServiceCommand(command string) (string, []string, error) {
	args, e := windows.DecomposeCommandLine(command)
	if e != nil || len(args) == 0 || !filepath.IsAbs(args[0]) || (!strings.EqualFold(filepath.Base(args[0]), "sshd.exe") && !strings.EqualFold(filepath.Base(args[0]), "hitlconnect.exe")) {
		return "", nil, errors.New("CUSTOM_SSHD_SERVICE")
	}
	var options []string
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-D", "-e":
		case "-f", "-p":
			if seen[args[i]] || i+1 >= len(args) {
				return "", nil, errors.New("CUSTOM_SSHD_SERVICE_OPTIONS")
			}
			seen[args[i]] = true
			options = append(options, args[i], args[i+1])
			i++
		default:
			return "", nil, errors.New("CUSTOM_SSHD_SERVICE_OPTIONS")
		}
	}
	return args[0], options, nil
}
func nativeSSHCommand(ctx context.Context, exe string, args ...string) ([]byte, error) {
	if e := rejectReparse(exe); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.WaitDelay = time.Second
	hideGUIChild(cmd)
	out, e := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, e
}
func nativeServiceState(ctx context.Context, s *mgr.Service, desired svc.State) error {
	for {
		v, e := s.Query()
		if e != nil {
			return e
		}
		if v.State == desired {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func nativeStartSSH(ctx context.Context, s *mgr.Service, restart bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	status, e := s.Query()
	if e != nil {
		return e
	}
	if restart && status.State != svc.Stopped {
		if _, e = s.Control(svc.Stop); e != nil && e != windows.ERROR_SERVICE_NOT_ACTIVE {
			return e
		}
		if e = nativeServiceState(ctx, s, svc.Stopped); e != nil {
			return e
		}
	}
	status, e = s.Query()
	if e != nil {
		return e
	}
	if status.State == svc.StopPending {
		if e = nativeServiceState(ctx, s, svc.Stopped); e != nil {
			return e
		}
		status.State = svc.Stopped
	}
	if status.State == svc.Stopped {
		if e = s.Start(); e != nil && e != windows.ERROR_SERVICE_ALREADY_RUNNING {
			return e
		}
	}
	return nativeServiceState(ctx, s, svc.Running)
}
func nativeAutomaticSSH(s *mgr.Service) error {
	// Change only StartType; preserve service account, type, executable and flags.
	return windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil)
}
func nativeProfile(sid string) (string, error) {
	key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid, registry.QUERY_VALUE)
	if e != nil {
		return "", errors.New("USER_PROFILE_MISSING")
	}
	defer key.Close()
	p, _, e := key.GetStringValue("ProfileImagePath")
	if e != nil {
		return "", e
	}
	p, e = registry.ExpandString(p)
	if e != nil {
		return "", e
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("USER_PROFILE_MISSING")
	}
	return p, nil
}
func nativeWindowsSetup(ctx context.Context, p sshSetupInput) sshSetupReport {
	r := newSSHSetupReport()
	e := configureNativeSSH(ctx, p, r)
	r.failure(e)
	return r
}
func configureNativeSSH(ctx context.Context, p sshSetupInput, r sshSetupReport) error {
	r["stage"] = "resolve-local-account"
	elevated := windows.GetCurrentProcessToken().IsElevated()
	r["elevated"] = elevated
	name, sid, e := nativeLocalAccount(p.User)
	if e != nil {
		return r.fail(e.Error(), "The account must be an enabled local Windows user; account policy was preserved")
	}
	r["account"], r["accountSid"], r["publicKeyFingerprint"] = name, sid, p.Fingerprint
	if p.Apply && !elevated {
		r["elevationRequired"] = true
		return r.fail("ELEVATION_REQUIRED", "Accept Windows UAC or use an administrator terminal")
	}
	programData, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return e
	}
	if p.Apply {
		// One machine-wide file lock serializes installer and all future device
		// grants, including different provider profiles modifying the same account.
		root := filepath.Join(programData, "HITLConnect-SSH")
		if e = nativeSSHDirectory(root, sshSDDL("S-1-5-32-544", false, true)); e != nil {
			return e
		}
		for {
			unlock, ok, e := tryProfileLock(root, "setup.lock")
			if e != nil {
				return e
			}
			if ok {
				defer unlock()
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	r["stage"] = "inspect-sshd-service"
	manager, service, e := nativeSSHService(p.Apply)
	if manager != nil {
		defer manager.Disconnect()
	}
	if e != nil && !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return e
	}
	if service != nil {
		defer service.Close()
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	sshd := filepath.Join(system, "OpenSSH", "sshd.exe")
	options := []string{}
	if service != nil {
		cfg, e := service.Config()
		if e != nil {
			return e
		}
		sshd, options, e = nativeServiceCommand(cfg.BinaryPathName)
		if e != nil {
			return r.fail(e.Error(), "Preserve the custom sshd service and review its executable/options")
		}
		if strings.EqualFold(filepath.Base(sshd), "hitlconnect.exe") {
			if e = validateSystemSSHAlias(sshd, filepath.Join(system, "OpenSSH", "sshd.exe")); e != nil {
				return r.fail(e.Error(), "Review the system OpenSSH alias before using it")
			}
		}
	}
	r["serviceExecutable"] = sshd
	_, statErr := os.Stat(sshd)
	if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if service != nil && os.IsNotExist(statErr) {
		return r.fail("SSHD_SERVICE_EXECUTABLE_MISSING", "The existing service executable is missing; preserve its configuration and repair its original OpenSSH distribution")
	}
	installed := statErr == nil && service != nil
	r["serverInstalled"] = installed
	if !installed {
		r.change("install-windows-openssh-server-with-loopback-listener")
		r["elevationRequired"] = !elevated
		if !p.Apply {
			return r.fail("OPENSSH_SERVER_MISSING", "Review then use --apply --install-server")
		}
		if !p.InstallServer {
			return r.fail("INSTALL_PERMISSION_REQUIRED", "Installing OpenSSH requires --install-server")
		}
		r["stage"] = "install-openssh-capability"
		// Native Windows servicing executable, no shell or PowerShell loader.
		cmd := exec.CommandContext(ctx, filepath.Join(system, "dism.exe"), "/Online", "/Add-Capability", "/CapabilityName:OpenSSH.Server~~~~0.0.1.0", "/NoRestart", "/Quiet")
		cmd.WaitDelay = time.Second
		hideGUIChild(cmd)
		e = cmd.Run()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			r["processExitCode"] = exit.ExitCode()
			if exit.ExitCode() == 3010 {
				return r.fail("REBOOT_REQUIRED", "Windows servicing requires a reboot; no reboot was initiated")
			}
			return r.fail("OPENSSH_INSTALL_FAILED", "Windows servicing failed; inspect DISM/CBS logs without changing organizational policy")
		}
		if e != nil {
			return e
		}
		if _, e = os.Stat(sshd); e != nil {
			return r.fail("OPENSSH_INSTALL_INCOMPLETE", "Windows did not provide sshd.exe")
		}
		config := filepath.Join(programData, "ssh", "sshd_config")
		if e = nativeEnsureSSHConfig(config, filepath.Join(filepath.Dir(sshd), "sshd_config_default")); e != nil {
			return e
		}
		if _, e = nativeSSHCommand(ctx, filepath.Join(filepath.Dir(sshd), "ssh-keygen.exe"), "-A"); e != nil {
			return r.fail("HOST_KEY_GENERATION_FAILED", "OpenSSH could not generate missing host keys")
		}
		if service == nil {
			// DISM normally registers sshd. Query it again before creating it.
			m, s, openErr := nativeSSHService(true)
			if m != nil {
				defer m.Disconnect()
			}
			if openErr == nil {
				service = s
			} else if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
				service, e = manager.CreateService("sshd", sshd, mgr.Config{DisplayName: "OpenSSH SSH Server", StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem"})
				if e != nil {
					return e
				}
			} else {
				return openErr
			}
			defer service.Close()
		}
		r["serverInstalled"] = true
	}
	r["stage"] = "inspect-effective-ssh-policy"
	effectiveArgs := append(append([]string{}, options...), "-T", "-C", "user="+name+",host=localhost,addr=127.0.0.1")
	output, e := nativeSSHCommand(ctx, sshd, effectiveArgs...)
	if e != nil {
		return r.fail("SSHD_CONFIG_INVALID_OR_UNREADABLE", "sshd -T failed; inspect configuration syntax and administrator access")
	}
	settings := sshEffectiveSettings(output)
	for dst, src := range map[string]string{"publicKeyAuthentication": "pubkeyauthentication", "authenticationMethods": "authenticationmethods", "authorizedKeysSetting": "authorizedkeysfile", "listenAddress": "listenaddress", "port": "port"} {
		r[dst] = settings[src]
	}
	if settings["pubkeyauthentication"] != "yes" {
		return r.fail("PUBLIC_KEY_AUTH_DISABLED", "Effective SSH policy disables public-key authentication; it was preserved")
	}
	if v := settings["authenticationmethods"]; v != "" && v != "any" && v != "publickey" {
		return r.fail("ADDITIONAL_AUTH_REQUIRED", "SSH policy requires additional authentication; it was preserved")
	}
	for _, k := range []string{"allowusers", "denyusers", "allowgroups", "denygroups"} {
		if settings[k] != "" {
			return r.fail("ACCOUNT_POLICY_REVIEW_REQUIRED", "Explicit account/group restrictions require review; no policy was widened")
		}
	}
	r["stage"] = "resolve-authorized-keys"
	current := strings.ReplaceAll(strings.Trim(settings["authorizedkeysfile"], `"`), `\`, "/")
	scoped := "__PROGRAMDATA__/ssh/hitl-" + sid + ".authorized_keys"
	if p.ScopedAuthorization && strings.EqualFold(current, "__PROGRAMDATA__/ssh/administrators_authorized_keys") {
		if !p.Apply {
			return r.fail("SCOPED_AUTHORIZATION_REQUIRED", "Allow connection to configure account-specific administrator keys")
		}
		r["stage"] = "scope-administrator-authorization"
		if e = nativeScopeSSH(ctx, programData, sshd, options, service, name, sid, current, r); e != nil {
			return e
		}
		current = scoped + " " + current
		r["authorizedKeysSetting"] = current
	}
	fields := strings.Fields(current)
	if len(fields) == 0 {
		return r.fail("CUSTOM_AUTHORIZED_KEYS_POLICY", "Empty AuthorizedKeysFile; configuration preserved")
	}
	authorized, sshDir := "", ""
	owner := "S-1-5-32-544"
	userACL := false
	switch {
	case strings.EqualFold(fields[0], scoped):
		authorized = filepath.Join(programData, "ssh", "hitl-"+sid+".authorized_keys")
	case strings.EqualFold(current, "__PROGRAMDATA__/ssh/administrators_authorized_keys"):
		authorized = filepath.Join(programData, "ssh", "administrators_authorized_keys")
	case current == ".ssh/authorized_keys" || current == "%h/.ssh/authorized_keys":
		profile, e := nativeProfile(sid)
		if e != nil {
			return e
		}
		sshDir = filepath.Join(profile, ".ssh")
		authorized = filepath.Join(sshDir, "authorized_keys")
		owner = sid
		userACL = true
	default:
		return r.fail("CUSTOM_AUTHORIZED_KEYS_POLICY", "Customized AuthorizedKeysFile was preserved; review its path explicitly")
	}
	r["authorizedKeysPath"] = authorized
	r["stage"] = "inspect-key-and-service"
	state, e := service.Query()
	if e != nil {
		return e
	}
	cfg, e := service.Config()
	if e != nil {
		return e
	}
	running, automatic := state.State == svc.Running, cfg.StartType == mgr.StartAutomatic
	r["serviceRunning"] = running
	if !running {
		r.change("start-openssh-service")
	}
	if !automatic {
		r.change("set-openssh-service-startup-automatic")
	}
	fileSD := sshSDDL(owner, userACL, false)
	dirSD := sshSDDL(owner, userACL, true)
	data := []byte{}
	keyPresent, aclOK, dirOK := false, false, true
	if !p.PrepareOnly {
		if e = rejectExistingSSHPath(authorized); e != nil {
			return e
		}
		data, e = os.ReadFile(authorized)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		keyPresent = authorizedFingerprint(data, p.Fingerprint)
		aclOK = nativeSSHACLMatches(authorized, fileSD)
		dirOK = sshDir == "" || nativeSSHACLMatches(sshDir, dirSD)
		if !keyPresent {
			r.change("append-only-the-approved-public-key")
		}
		if !aclOK {
			r.change("set-authorized-key-file-owner-and-restricted-acl")
		}
		if !dirOK {
			r.change("set-user-ssh-directory-owner-and-restricted-acl")
		}
	}
	r["elevationRequired"] = len(r["changes"].([]string)) > 0 && !elevated
	if p.Apply {
		if !p.PrepareOnly && (!keyPresent || !aclOK || !dirOK) {
			if !keyPresent && p.PublicKey == "" {
				return r.fail("APPROVED_PUBLIC_KEY_REQUIRED", "Supply the existing approved public key; do not replace its private key")
			}
			r["stage"] = "backup-and-install-key"
			if sshDir != "" && !dirOK {
				if e = nativeSSHBackup(programData, sshDir, r); e != nil {
					return e
				}
				if e = nativeSSHDirectory(sshDir, dirSD); e != nil {
					return e
				}
			}
			if !keyPresent || !aclOK {
				if e = nativeSSHBackup(programData, authorized, r); e != nil {
					return e
				}
				if !keyPresent {
					if len(data) > 0 && data[len(data)-1] != '\n' {
						data = append(data, '\r', '\n')
					}
					data = append(data, []byte(p.PublicKey+"\r\n")...)
				}
				if e = nativeSSHWrite(authorized, data, fileSD); e != nil {
					return e
				}
			}
			data, e = os.ReadFile(authorized)
			if e != nil {
				return e
			}
			keyPresent = authorizedFingerprint(data, p.Fingerprint)
			aclOK = nativeSSHACLMatches(authorized, fileSD)
			dirOK = sshDir == "" || nativeSSHACLMatches(sshDir, dirSD)
		}
		r["stage"] = "start-and-verify-sshd"
		if !automatic {
			if e = nativeAutomaticSSH(service); e != nil {
				return e
			}
		}
		if !running {
			if e = nativeStartSSH(ctx, service, false); e != nil {
				return e
			}
		}
		state, e = service.Query()
		if e != nil {
			return e
		}
		cfg, e = service.Config()
		if e != nil {
			return e
		}
		running, automatic = state.State == svc.Running, cfg.StartType == mgr.StartAutomatic
	}
	r["serviceRunning"] = running
	ready := running && automatic
	if p.PrepareOnly {
		r["sshServiceReady"] = ready
		r["ok"] = ready
		r["code"], r["message"] = "SSH_SERVICE_READY", "SSH service ready; caller login still requires verification"
	} else {
		r["publicKeyPresent"], r["aclValid"] = keyPresent, aclOK
		ready = ready && keyPresent && aclOK && dirOK
		r["configurationReady"], r["ok"] = ready, ready
		r["code"], r["message"] = "LOCAL_SSH_CONFIG_READY", "Local SSH configuration passed; verify caller whoami"
	}
	if !ready {
		r["code"], r["message"] = "CHANGES_REQUIRED", "Review changes and rerun with --apply; existing files and ACLs will be backed up"
	}
	r["stage"] = "complete"
	return nil
}

func nativeScopeSSH(ctx context.Context, programData, sshd string, options []string, s *mgr.Service, user, sid, current string, r sshSetupReport) error {
	config := filepath.Join(programData, "ssh", "sshd_config")
	for i := 0; i < len(options)-1; i++ {
		if options[i] == "-f" {
			config = options[i+1]
		}
	}
	if !filepath.IsAbs(config) {
		return r.fail("CUSTOM_SSHD_SERVICE_OPTIONS", "Relative sshd config paths require review")
	}
	if e := rejectReparse(config); e != nil {
		return e
	}
	original, e := os.ReadFile(config)
	if e != nil {
		return e
	}
	sd, e := nativeSSHDescriptor(config)
	if e != nil {
		return e
	}
	if e = nativeSSHBackup(programData, config, r); e != nil {
		return e
	}
	candidate := config + ".hitl-" + rand.Text()
	if e = nativeSSHWrite(candidate, scopedSSHConfig(original, sid, user, current), sd); e != nil {
		return e
	}
	defer os.Remove(candidate)
	if _, e = nativeSSHCommand(ctx, sshd, "-t", "-f", candidate); e != nil {
		return r.fail("SCOPED_CONFIG_INVALID", "Candidate config failed validation; original preserved")
	}
	if e = os.Rename(candidate, config); e != nil {
		return e
	}
	args := append(append([]string{}, options...), "-T", "-C", "user="+user+",host=localhost,addr=127.0.0.1")
	out, e := nativeSSHCommand(ctx, sshd, args...)
	fields := strings.Fields(sshEffectiveSettings(out)["authorizedkeysfile"])
	if e == nil && (len(fields) == 0 || !strings.EqualFold(fields[0], "__PROGRAMDATA__/ssh/hitl-"+sid+".authorized_keys")) {
		e = errors.New("SCOPED_CONFIG_NOT_EFFECTIVE")
	}
	state, stateErr := s.Query()
	if e == nil {
		e = stateErr
	}
	if e == nil && state.State == svc.Running {
		e = nativeStartSSH(ctx, s, true)
	}
	if e != nil {
		// Preserve the source bytes and descriptor, and expose rollback failures.
		if rollback := nativeSSHWrite(config, original, sd); rollback != nil {
			return r.fail("SSH_CONFIG_ROLLBACK_FAILED", "Restore the recorded configuration backup before retrying")
		}
		if state.State == svc.Running {
			if rollback := nativeStartSSH(ctx, s, true); rollback != nil {
				return r.fail("SSH_SERVICE_ROLLBACK_FAILED", "Configuration restored but sshd restart failed")
			}
		}
		return r.fail("SCOPED_CONFIG_NOT_EFFECTIVE", "Account-specific configuration failed; original configuration restored")
	}
	r.change("isolate-selected-administrator-account-key-file")
	return nil
}
func nativeEnsureSSHConfig(config, defaults string) error {
	if e := rejectExistingSSHPath(config); e != nil {
		return e
	}
	if _, e := os.Stat(config); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	data, e := os.ReadFile(defaults)
	if e != nil {
		return fmt.Errorf("SSHD_DEFAULT_CONFIG_MISSING: %w", e)
	}
	// Only a newly created configuration is constrained to loopback. Existing
	// settings, host keys, service arguments and firewall rules are preserved.
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.EqualFold(f[0], "ListenAddress") {
			continue
		}
		lines = append(lines, line)
	}
	if e = nativeSSHDirectory(filepath.Dir(config), sshSDDL("S-1-5-32-544", false, true)); e != nil {
		return e
	}
	return nativeSSHWrite(config, []byte("ListenAddress 127.0.0.1\r\n"+strings.Join(lines, "\n")), sshSDDL("S-1-5-32-544", false, false))
}
