package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func waitSystemSSHRelay(ctx context.Context, root string, resume bool) error {
	for {
		d, err := agentSession(root)
		var state guiState
		if err == nil {
			err = agentCall(ctx, d, "state", nil, &state)
		}
		if err == nil && state.Version == guiVersion && state.Managed && (!resume || state.Running) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("SYSTEM_SSH_SERVICE_NOT_READY")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Both registrations present is ambiguous. Never stop or delete an unrelated
// service, or interpret missing configuration as a new installation.
func openSystemSSHRelay(manager *mgr.Mgr) (*mgr.Service, error) {
	var found *mgr.Service
	for _, name := range []string{systemSSHRelayService, legacySystemSSHRelayService} {
		service, err := manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		if err != nil {
			if found != nil {
				found.Close()
			}
			return nil, err
		}
		if found != nil {
			found.Close()
			service.Close()
			return nil, errors.New("EXISTING_SYSTEM_SSH_SERVICE_CONFLICT")
		}
		found = service
	}
	return found, nil
}

func systemSSHRelayScope(cfg mgr.Config, base, sid, allowed string) bool {
	argv, err := windows.DecomposeCommandLine(cfg.BinaryPathName)
	if err != nil || len(argv) != 6 || argv[1] != "system-ssh-service" || argv[2] != "--dir" || !strings.EqualFold(argv[3], base) || argv[4] != "--owner-sid" || argv[5] != sid {
		return false
	}
	// Only migrate this product's protected executable and SYSTEM service.
	return strings.HasPrefix(strings.ToLower(filepath.Clean(argv[0])), strings.ToLower(allowed)) &&
		strings.EqualFold(cfg.ServiceStartName, "LocalSystem") && cfg.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS
}
