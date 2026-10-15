package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type hostAuthorization struct {
	Version   int    `json:"version"`
	Profile   string `json:"profile"`
	User      string `json:"user"`
	Address   string `json:"address"`
	Engine    string `json:"engine,omitempty"`
	SID       string `json:"sid,omitempty"`
	Privilege string `json:"privilege,omitempty"`
}

func canonicalProfile(profile string) string {
	abs, _ := filepath.Abs(profile)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs)
}
func readHostAuthorization(profile string) (hostAuthorization, error) {
	var a hostAuthorization
	file, err := os.Open(filepath.Join(profile, "host-authorization.json"))
	if err != nil {
		return a, err
	}
	defer file.Close()
	if err = checkAuthorizationProtection(file); err != nil {
		return a, err
	}
	decoder := json.NewDecoder(io.LimitReader(file, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&a) != nil || decoder.Decode(new(any)) != io.EOF || (a.Version != 1 && a.Version != 2 && a.Version != 3) || a.User == "" || a.Profile != canonicalProfile(profile) {
		return a, errors.New("HOST_AUTHORIZATION_INVALID")
	}
	if (a.Version == 2 && (a.Engine != "embedded" || a.SID == "" || (a.Privilege != "standard" && a.Privilege != "administrator"))) || (a.Version == 1 && (a.Engine != "" || a.SID != "" || a.Privilege != "")) {
		return a, errors.New("HOST_AUTHORIZATION_INVALID")
	}
	if a.Version == 3 && (a.Engine != "openssh" || a.SID == "" || a.Privilege != "administrator") {
		return a, errors.New("HOST_AUTHORIZATION_INVALID")
	}
	if _, err = loopback(a.Address); err != nil {
		return a, err
	}
	return a, nil
}
func saveHostAuthorization(profile, account, address string) error {
	return writeHostAuthorization(profile, hostAuthorization{Version: 1, Profile: canonicalProfile(profile), User: strings.TrimSpace(account), Address: address})
}
func writeHostAuthorization(profile string, a hostAuthorization) error {
	if err := os.MkdirAll(profile, 0700); err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_DIRECTORY_FAILED: %w", err)
	}
	// Windows creates the file with its final protected owner and DACL. There is
	// no intermediate writable policy or second handle to change its ownership.
	file, err := createAuthorizationFile(profile)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = json.NewEncoder(file).Encode(a); err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_WRITE_FAILED: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_SYNC_FAILED: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_CLOSE_FAILED: %w", err)
	}
	if err = os.Rename(file.Name(), filepath.Join(profile, "host-authorization.json")); err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_COMMIT_FAILED: %w", err)
	}
	// Read through the same protection/identity checks used by the service before
	// registering or starting it. A successful write alone is not readiness.
	got, err := readHostAuthorization(profile)
	if err != nil {
		return fmt.Errorf("HOST_AUTHORIZATION_READBACK_FAILED: %w", err)
	}
	if got != a {
		return errors.New("HOST_AUTHORIZATION_READBACK_MISMATCH")
	}
	return nil
}
