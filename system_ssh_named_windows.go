package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const systemSSHServerService = "hitlconnect-server"

func validateNamedSSHService(cfg mgr.Config) error {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(cfg.BinaryPathName)
	if err != nil || len(args) != 1 || !strings.EqualFold(args[0], filepath.Join(system, "OpenSSH", "hitlconnect.exe")) || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || !strings.EqualFold(cfg.ServiceStartName, "LocalSystem") || cfg.DisplayName != systemSSHServerService {
		return errors.New("EXISTING_HITLCONNECT_SERVICE_CONFLICT")
	}
	return nil
}

func systemSFTPAlias(system string) string {
	return filepath.Join(system, "OpenSSH", "HITL-SFTP", "hitlconnect.exe")
}

func namedSFTPConfig(old []byte, system string) ([]byte, error) {
	legacy := []byte("Subsystem sftp sftp-server.exe\r\n")
	internal := []byte("Subsystem sftp " + filepath.ToSlash(systemSFTPAlias(system)) + "\r\n")
	// The caller first verifies the entire managed configuration. This helper
	// changes only its exact subsystem line, never a user-defined command.
	if bytes.Count(old, internal) == 1 && !bytes.Contains(old, legacy) {
		return bytes.Clone(old), nil
	}
	if bytes.Count(old, legacy) != 1 || bytes.Contains(old, internal) {
		return nil, errors.New("SFTP_CONFIG_REVIEW_REQUIRED")
	}
	return bytes.Replace(old, legacy, internal, 1), nil
}

func prepareSystemSFTPAlias(ctx context.Context, system string, service *mgr.Service) error {
	state, err := service.Query()
	if err != nil {
		return err
	}
	alias := systemSFTPAlias(system)
	if err = rejectExistingSSHPath(alias); err != nil {
		return err
	}
	// The directory inherits the protected Windows OpenSSH parent ACL.
	if err = os.Mkdir(filepath.Dir(alias), 0755); err != nil && !os.IsExist(err) {
		return err
	}
	return refreshSignedSSHCopy(ctx, filepath.Join(system, "OpenSSH", "sftp-server.exe"), alias, state.State == svc.Stopped)
}
