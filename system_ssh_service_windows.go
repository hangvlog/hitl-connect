package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const systemSSHRelayService = "HITLConnect-SystemSSH"

func systemSSHRecoveryActions() []mgr.RecoveryAction {
	// SCM repeats the last action for every later failure. End explicitly in
	// no action so a persistent startup failure cannot create a restart loop.
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}
}

type systemSSHRelay struct{ base, owner string }

func (s *systemSSHRelay) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stage := "service-start"
	root, policy, err := prepareSystemSSHOwner(ctx, s.base, &stage, s.owner)
	if err != nil {
		// Best-effort local startup diagnostics contain no identity or credentials.
		if root != "" {
			_ = privateJSON(filepath.Join(root, "system-ssh-startup.json"), installReport(stage, err))
		}
		return true, 1
	}
	_ = privateJSON(filepath.Join(root, "system-ssh-startup.json"), installReport("system-ssh-ready", nil))
	servicePolicy = &policy
	done := make(chan error, 1)
	go func() { done <- runGUI(ctx, root, "127.0.0.1:59369", true) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			return err != nil, func() uint32 {
				if err != nil {
					return 2
				}
				return 0
			}()
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				select {
				case <-done:
				case <-time.After(12 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func runSystemSSHServiceCommand(ctx context.Context, args []string) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	base := f.String("dir", "", "existing authorized profile")
	owner := f.String("owner-sid", "", "service owner")
	interrupt := f.Bool("interrupt-sessions", false, "explicitly allow stopping current SSH sessions")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if *base == "" || f.NArg() != 0 {
		return errors.New("EXISTING_PROFILE_REQUIRED")
	}
	if args[0] == "system-ssh-service" {
		isService, err := svc.IsWindowsService()
		if err != nil {
			return err
		}
		if !isService || *owner == "" {
			return errors.New("SERVICE_MANAGER_REQUIRED")
		}
		return svc.Run(systemSSHRelayService, &systemSSHRelay{*base, *owner})
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("ELEVATION_REQUIRED")
	}
	err := installSystemSSHService(ctx, *base, *interrupt)
	_ = json.NewEncoder(os.Stdout).Encode(installReport("install-system-ssh-service", err))
	return err
}

func installSystemSSHService(ctx context.Context, base string, interrupt bool) (result error) {
	stage := "preflight"
	root, policy, err := prepareSystemSSH(ctx, base, &stage)
	if err != nil {
		return err
	}
	sid, err := currentOwnerSID()
	if err != nil {
		return err
	}
	if policy.SID != sid {
		return errors.New("HOST_SCOPE_FIXED")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	allowed := filepath.Join(programFiles, "HITL Connect") + string(os.PathSeparator)
	if !strings.HasPrefix(strings.ToLower(exe), strings.ToLower(allowed)) {
		return errors.New("PROTECTED_INSTALLATION_REQUIRED")
	}
	if err = rejectReparse(exe); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	existing, err := manager.OpenService(systemSSHRelayService)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	if existing != nil {
		defer existing.Close()
	} else {
		defer func() {
			if existing != nil {
				existing.Close()
			}
		}()
	}
	var previous *mgr.Config
	if existing != nil {
		cfg, e := existing.Config()
		if e != nil {
			return e
		}
		argv, e := windows.DecomposeCommandLine(cfg.BinaryPathName)
		if e != nil || len(argv) != 6 || argv[1] != "system-ssh-service" || argv[2] != "--dir" || !strings.EqualFold(argv[3], base) || argv[4] != "--owner-sid" || argv[5] != sid {
			return errors.New("EXISTING_SYSTEM_SSH_SERVICE_CONFLICT")
		}
		previous = &cfg
	}
	m, sshService, err := nativeSSHService(true)
	if m != nil {
		defer m.Disconnect()
	}
	if err != nil {
		return err
	}
	defer sshService.Close()
	sshConfig, err := sshService.Config()
	if err != nil {
		return err
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	original := filepath.Join(system, "OpenSSH", "sshd.exe")
	alias := filepath.Join(system, "OpenSSH", "hitlconnect.exe")
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	sshConfigPath := filepath.Join(pd, "ssh", "sshd_config")
	oldSSHConfig, err := os.ReadFile(sshConfigPath)
	if err != nil {
		return err
	}
	newSSHConfig, err := namedSFTPConfig(oldSSHConfig, system)
	if err != nil {
		return err
	}
	plan, err := readConnectionPlan(root)
	if err != nil {
		return err
	}
	backup := filepath.Join(root, "rollback-system-ssh-"+time.Now().UTC().Format("20060102T150405.000000000"))
	if err = managedDirectory(backup, sid); err != nil {
		return err
	}
	if err = privateJSON(filepath.Join(backup, "services.json"), map[string]any{"sshName": sshService.Name, "ssh": sshConfig, "relay": previous, "plan": plan}); err != nil {
		return err
	}
	if err = copyInstallFile(sshConfigPath, filepath.Join(backup, "sshd_config")); err != nil {
		return err
	}
	serviceActive := false
	if existing != nil {
		state, e := existing.Query()
		if e != nil {
			return e
		}
		serviceActive = state.State != svc.Stopped
	}
	if err = quiesceSystemSSHProvider(ctx, root, interrupt, serviceActive); err != nil {
		return err
	}
	if existing != nil {
		if _, err = stopManagedUpgrade(ctx, existing); err != nil {
			return err
		}
	}
	// Wait for the old interactive panel to release its profile, without PID guesses.
	for i := 0; i < 100; i++ {
		release, acquired, e := tryProfileLock(root, ".panel.lock")
		if e != nil {
			return e
		}
		if acquired {
			release()
			break
		}
		if i == 99 {
			return errors.New("OLD_PROVIDER_STILL_RUNNING")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = privateJSON(filepath.Join(root, "connection-plan.json"), plan); err != nil {
		return err
	}
	if _, err = stopManagedUpgrade(ctx, sshService); err != nil {
		return err
	}
	// On any post-stop error restore the service configuration and SSH availability.
	committed := false
	var renamed *mgr.Service
	defer func() {
		if renamed != nil {
			renamed.Close()
		}
	}()
	defer func() {
		if !committed {
			recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if existing != nil {
				if _, e := stopManagedUpgrade(recovery, existing); e != nil {
					result = errors.Join(result, fmt.Errorf("ROLLBACK_RELAY_STOP_FAILED: %w", e))
					return
				}
				if previous != nil {
					if e := existing.UpdateConfig(*previous); e != nil {
						result = errors.Join(result, e)
					}
				}
			}
			if renamed != nil {
				if _, e := stopManagedUpgrade(recovery, renamed); e != nil {
					result = errors.Join(result, e)
					return
				}
				if e := renamed.Delete(); e != nil {
					result = errors.Join(result, e)
					return
				}
				renamed.Close()
				renamed = nil
			}
			if e := nativeSSHWrite(sshConfigPath, oldSSHConfig, sshSDDL("S-1-5-32-544", false, false)); e != nil {
				result = errors.Join(result, e)
				return
			}
			if e := sshService.UpdateConfig(sshConfig); e != nil {
				result = errors.Join(result, e)
			}
			if e := nativeStartSSH(recovery, sshService, false); e != nil {
				result = errors.Join(result, e)
			}
			if existing != nil && previous != nil {
				if e := existing.Start(); e != nil {
					result = errors.Join(result, e)
				}
			}
		}
	}()
	if err = refreshSystemSSHAlias(ctx, original, true); err != nil {
		return err
	}
	if err = prepareSystemSFTPAlias(ctx, system, sshService); err != nil {
		return err
	}
	if err = nativeSSHWrite(sshConfigPath, newSSHConfig, sshSDDL("S-1-5-32-544", false, false)); err != nil {
		return err
	}
	if _, err = nativeSSHCommand(ctx, alias, "-t", "-f", sshConfigPath); err != nil {
		return err
	}
	changed := sshConfig
	changed.BinaryPathName = alias
	changed.DisplayName = systemSSHServerService
	changed.StartType = mgr.StartManual
	if sshService.Name != systemSSHServerService {
		// SCM service names and display names share the uniqueness check. Free
		// the legacy alias display name before creating the named replacement.
		// The rollback above restores the complete original configuration.
		disabled := sshConfig
		disabled.StartType = mgr.StartDisabled
		disabled.DisplayName = "HITL Connect previous SSH " + filepath.Base(backup)
		if err = sshService.UpdateConfig(disabled); err != nil {
			return err
		}
		renamed, err = manager.CreateService(systemSSHServerService, alias, changed)
		if err != nil {
			return err
		}
		// Keep the stopped old definition for transactional rollback until the
		// new server and relay are confirmed ready. It must not compete at boot.
	} else {
		if err = sshService.UpdateConfig(changed); err != nil {
			return err
		}
	}
	config := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: "HITL Connect", Description: "HITL Connect relay for the authorized Windows SSH account", StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem", DelayedAutoStart: true}
	if existing == nil {
		existing, err = manager.CreateService(systemSSHRelayService, exe, config, "system-ssh-service", "--dir", base, "--owner-sid", sid)
		if err != nil {
			return err
		}
	} else {
		config.BinaryPathName = windows.ComposeCommandLine([]string{exe, "system-ssh-service", "--dir", base, "--owner-sid", sid})
		if err = existing.UpdateConfig(config); err != nil {
			return err
		}
	}
	if err = existing.SetRecoveryActions(systemSSHRecoveryActions(), 86400); err != nil {
		return err
	}
	if err = existing.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	if err = existing.Start(); err != nil {
		return err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err = nativeServiceState(readyCtx, existing, svc.Running); err != nil {
		return err
	}
	for {
		d, e := agentSession(root)
		var state guiState
		if e == nil {
			e = agentCall(readyCtx, d, "state", nil, &state)
		}
		if e == nil && state.Version == guiVersion && state.Managed && (!plan.Resume || state.Running) {
			break
		}
		select {
		case <-readyCtx.Done():
			return errors.New("SYSTEM_SSH_SERVICE_NOT_READY")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if renamed != nil {
		// SCM has no rename operation; remove the old definition only after the
		// replacement is operational. System component files remain untouched.
		if err = sshService.Delete(); err != nil {
			return err
		}
	}
	committed = true
	return nil
}
