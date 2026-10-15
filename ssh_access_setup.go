package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func localSSHUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// Unix setup is deliberately limited to the current account's standard key
// file. It never needs sudo or edits server-wide account policy.
func installCurrentUserKey(account, public string) error {
	u, err := user.Current()
	if err != nil || account != u.Username {
		return errors.New("LOCAL_CURRENT_USER_REQUIRED")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("PLATFORM_UNSUPPORTED")
	}
	dir := filepath.Join(u.HomeDir, ".ssh")
	if info, e := os.Lstat(dir); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("SSH_DIRECTORY_UNSAFE")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	file := filepath.Join(dir, "authorized_keys")
	info, err := os.Lstat(file)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("AUTHORIZED_KEYS_UNSAFE")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	old, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(old) > 1024*1024 {
		return errors.New("AUTHORIZED_KEYS_TOO_LARGE")
	}
	key, err := plainSSHKey([]byte(public))
	if err != nil {
		return err
	}
	for _, line := range bytes.Split(old, []byte{'\n'}) {
		existing, _, options, _, e := ssh.ParseAuthorizedKey(line)
		if e == nil && bytes.Equal(existing.Marshal(), key.Marshal()) {
			// Do not silently broaden an existing constrained authorization.
			if len(options) != 0 {
				return errors.New("EXISTING_KEY_HAS_RESTRICTIONS")
			}
			return os.Chmod(file, 0600)
		}
	}
	if len(old) > 0 {
		backup := file + ".hitl-backup-" + time.Now().UTC().Format("20060102T150405.000000000")
		if err = privateText(backup, string(old)); err != nil {
			return err
		}
		if old[len(old)-1] != '\n' {
			old = append(old, '\n')
		}
	}
	return privateText(file, string(old)+string(ssh.MarshalAuthorizedKey(key)))
}

// Only a local control action can reach this function. No remote request carries
// an account or an approval flag, and the exact request ID binds the shown key.
func decideSSHAccess(ctx context.Context, base, id, account, expected string, approve bool) agentResult {
	r := agentResult{Action: "approve", Code: "ACCESS_APPROVAL_FAILED"}
	if !approve {
		r.Action = "reject"
	}
	profile := filepath.Join(base, "public-host")
	file, err := accessPath(profile, id)
	if err != nil {
		r.Code = "ACCESS_REQUEST_INVALID"
		return r
	}
	unlock, err := lockAccess(profile)
	if err != nil {
		r.Code = "ACCESS_BUSY"
		return r
	}
	defer unlock()
	var a sshAccess
	if readJSON(file, &a) != nil || a.ID != id {
		r.Code = "ACCESS_REQUEST_NOT_FOUND"
		return r
	}
	if expected != "" && expected != a.Fingerprint {
		r.Code = "PUBLIC_KEY_MISMATCH"
		return r
	}
	if a.Status == "rejected" || a.Status == "revoked" || accessExpired(a) {
		r.Code = "ACCESS_REQUEST_CLOSED"
		return r
	}
	if !approve {
		if a.Status != "pending" {
			r.Code = "ACCESS_ALREADY_DECIDED"
			return r
		}
		a.Status = "rejected"
	} else {
		if strings.TrimSpace(account) == "" {
			r.Code = "LOCAL_USER_REQUIRED"
			return r
		}
		if a.Status == "approved" && a.User != account {
			r.Code = "ACCESS_ALREADY_DECIDED"
			return r
		}
		key, e := plainSSHKey([]byte(a.PublicKey))
		if e != nil || ssh.FingerprintSHA256(key) != a.Fingerprint {
			r.Code = "PUBLIC_KEY_MISMATCH"
			return r
		}
		var setup agentResult
		if _, system := systemSSHPolicy(profile); system {
			// This path already holds the metadata lock. Default grant setup
			// acquires it separately; do not recursively lock on local approval.
			setup = installSystemSSHKeyLocked(profile, a, account)
		} else {
			setup = installSSHAccessKey(ctx, profile, a, account)
		}
		if !setup.OK {
			setup.Action = "approve"
			return setup
		}

		a.Status, a.User = "approved", account
	}
	if privateJSON(file, a) != nil {
		return r
	}
	r.OK, r.Code = true, "ACCESS_"+strings.ToUpper(a.Status)
	r.Message = "Local decision saved. Only the caller's successful whoami proves login."
	return r
}
