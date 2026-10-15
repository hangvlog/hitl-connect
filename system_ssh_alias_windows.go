package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func verifySSHSignature(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name}
	data := windows.WinTrustData{Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file)}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if err != nil {
		// Windows optional components commonly use catalog signatures instead of
		// an embedded PE signature. Both paths must use the Windows trust engine.
		if catalogErr := verifySSHCatalog(path); catalogErr != nil {
			return fmt.Errorf("SYSTEM_SSH_SIGNATURE_INVALID: %w", catalogErr)
		}
	}
	return nil
}

// At boot the manual-start SSH service is stopped. Refresh only then: never
// replace an executing server or interrupt active sessions during recovery.
func refreshSystemSSHAlias(ctx context.Context, original string, stopped bool) error {
	return refreshSignedSSHCopy(ctx, original, filepath.Join(filepath.Dir(original), "hitlconnect.exe"), stopped)
}

func refreshSignedSSHCopy(ctx context.Context, original, alias string, stopped bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSSHCopy(alias, original); err == nil {
		return nil
	}
	if !stopped {
		return errors.New("SYSTEM_SSH_ALIAS_REFRESH_REQUIRES_STOPPED_SERVICE")
	}
	if err := rejectReparse(original); err != nil {
		return err
	}
	if err := rejectExistingSSHPath(alias); err != nil {
		return err
	}
	if err := verifySSHSignature(original); err != nil {
		return err
	}
	data, err := os.ReadFile(original)
	if err != nil {
		return err
	}
	// Retain the existing protected system directory permissions on a new copy.
	temp, err := os.CreateTemp(filepath.Dir(alias), ".hitlconnect-update-*.exe")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	_, err = temp.Write(data)
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := verifySSHSignature(name); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(name, alias); err != nil {
		return err
	}
	return validateSSHCopy(alias, original)
}

func prepareSystemSSHAlias(ctx context.Context, command, system string) error {
	exe, options, err := nativeServiceCommand(command)
	if err != nil || len(options) != 0 {
		return errors.New("CUSTOM_SSHD_SERVICE")
	}
	original := filepath.Join(system, "OpenSSH", "sshd.exe")
	if strings.EqualFold(exe, original) {
		return nil
	}
	if !strings.EqualFold(exe, filepath.Join(filepath.Dir(original), "hitlconnect.exe")) {
		return errors.New("CUSTOM_SSHD_SERVICE")
	}
	m, s, err := nativeSSHService(false)
	if m != nil {
		defer m.Disconnect()
	}
	if err != nil {
		return err
	}
	defer s.Close()
	state, err := s.Query()
	if err != nil {
		return err
	}
	return refreshSystemSSHAlias(ctx, original, state.State == svc.Stopped)
}

// Keep the original Windows component intact. Only its byte-identical alias
// beside it is supported; arbitrary wrappers are rejected.
func systemSSHExecutable(command, system string) (string, error) {
	exe, options, err := nativeServiceCommand(command)
	if err != nil || len(options) != 0 {
		return "", errors.New("CUSTOM_SSHD_SERVICE")
	}
	original := filepath.Join(system, "OpenSSH", "sshd.exe")
	if strings.EqualFold(exe, original) {
		return exe, nil
	}
	if err := validateSystemSSHAlias(exe, original); err != nil {
		return "", err
	}
	return exe, nil
}

func validateSystemSSHAlias(alias, original string) error {
	want := filepath.Join(filepath.Dir(original), "hitlconnect.exe")
	if !strings.EqualFold(alias, want) {
		return errors.New("CUSTOM_SSHD_SERVICE")
	}
	return validateSSHCopy(alias, original)
}

func validateSSHCopy(alias, original string) error {
	for _, path := range []string{original, alias} {
		if err := rejectReparse(path); err != nil {
			return err
		}
	}
	source, err := os.ReadFile(original)
	if err != nil {
		return err
	}
	copy, err := os.ReadFile(alias)
	if err != nil {
		return err
	}
	if len(source) == 0 || !bytes.Equal(source, copy) {
		return errors.New("SYSTEM_SSH_ALIAS_OUTDATED_OR_MODIFIED")
	}
	return nil
}
