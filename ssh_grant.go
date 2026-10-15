package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// A grant is separate from the long-lived tunnel invitation. Only its hash is
// stored here; the original token stays in the private connection-code file.
type sshGrant struct {
	Hash     string `json:"hash"`
	User     string `json:"user"`
	Expires  int64  `json:"expires"` // legacy field; time no longer expires a code
	Disabled bool   `json:"disabled,omitempty"`
	Request  string `json:"request,omitempty"` // legacy single-device binding
}

func validGrantToken(token string) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32
}
func grantHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func prepareAllowedSSH(ctx context.Context, account, address string) (string, error) {
	if runtime.GOOS == "windows" {
		r := windowsSetup(ctx, account, "", "", true, true, true, true)
		if !r.OK {
			return "", errors.New(r.Code + ": " + r.Message)
		}
		var setup struct {
			Port string `json:"port"`
		}
		if json.Unmarshal(r.Setup, &setup) != nil || setup.Port == "" {
			return "", errors.New("SSH_PORT_UNKNOWN")
		}
		return loopback(net.JoinHostPort("127.0.0.1", setup.Port))
	}
	if account != localSSHUser() {
		return "", errors.New("LOCAL_CURRENT_USER_REQUIRED")
	}
	if _, err := probeSSH(address); err != nil {
		return "", errors.New("LOCAL_SSH_UNAVAILABLE")
	}
	return address, nil
}

func issueSSHGrant(c *Config, account string) error {
	keyPath := localPath(c, "connection-key-ssh.txt")
	key, err := readConnectionKey(keyPath)
	if err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return err
	}
	key.SSHGrant = base64.RawURLEncoding.EncodeToString(token)
	profile := filepath.Dir(c.path)
	unlock, err := lockAccess(profile)
	if err != nil {
		return err
	}
	defer unlock()
	var previous sshGrant
	if err = readJSON(filepath.Join(profile, "ssh-grant.json"), &previous); err == nil {
		if err = revokeGrantRequest(profile, previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	g := sshGrant{Hash: grantHash(key.SSHGrant), User: account, Expires: 0}
	if err = privateJSON(filepath.Join(profile, "ssh-grant.json"), g); err != nil {
		return err
	}
	if err = syncSystemSSHKeys(profile); err != nil {
		return err
	}
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err = privateText(keyPath, "hitl1."+base64.RawURLEncoding.EncodeToString(data)+"\n"); err != nil {
		return err
	}
	if _, ok := embeddedPolicy(profile); ok {
		e, err := loadEmbeddedSSH(profile)
		if err != nil {
			return err
		}
		if err = e.audit("code-issued", "", "", "", "grant", 0); err != nil {
			return err
		}
	}
	fmt.Println("allow-ready=multiple-devices")
	return nil
}

var grantInstallations sync.Map

// Bind each device to this code generation before its idempotent key installation.
func redeemSSHGrant(c *Config, a sshAccess, token string) (sshAccess, error) {
	profile := filepath.Dir(c.path)
	unlock, err := lockAccess(profile)
	if err != nil {
		return a, err
	}
	defer unlock()
	path, _ := accessPath(profile, a.ID)
	if err = readJSON(path, &a); err != nil {
		return a, err
	}
	if a.Status == "rejected" {
		return a, nil
	}
	deny := func(code string) (sshAccess, error) { a.Status, a.Code = "denied", code; return a, nil }
	var g sshGrant
	if !validGrantToken(token) || readJSON(filepath.Join(profile, "ssh-grant.json"), &g) != nil || subtle.ConstantTimeCompare([]byte(g.Hash), []byte(grantHash(token))) != 1 {
		return deny("CONNECTION_CODE_INVALID_OR_REPLACED")
	}
	if g.Disabled {
		return deny("CONNECTION_CODE_DISABLED")
	}
	if g.User == "" || c.sshAccount == "" || g.User != c.sshAccount {
		return deny("LOCAL_ACCOUNT_NOT_AUTHORIZED")
	}
	if accessUsesGrant(a, g) {
		if a.Status == "approved" || a.Status == "setup-failed" {
			return a, nil
		}
	}
	a.GrantHash, a.Code = g.Hash, ""
	a.Status = "configuring"
	if err = privateJSON(path, a); err != nil {
		return a, err
	}
	if _, active := grantInstallations.LoadOrStore(path, true); !active {
		go func() {
			defer grantInstallations.Delete(path)
			installGrantedKey(profile, a, g)
		}()
	}
	return a, nil
}

func installSSHAccessKey(ctx context.Context, profile string, a sshAccess, account string) agentResult {
	if _, ok := systemSSHPolicy(profile); ok {
		return installSystemSSHKey(profile, a, account)
	}
	if policy, ok := embeddedPolicy(profile); ok {
		key, err := plainSSHKey([]byte(a.PublicKey))
		if account != policy.User || err != nil || ssh.FingerprintSHA256(key) != a.Fingerprint {
			return agentResult{Code: "PUBLIC_KEY_OR_ACCOUNT_MISMATCH"}
		}
		return agentResult{OK: true}
	}
	if runtime.GOOS == "windows" {
		publicFile := filepath.Join(accessDirectory(profile), a.ID+".pub")
		if privateText(publicFile, a.PublicKey) != nil {
			return agentResult{Code: "PUBLIC_KEY_WRITE_FAILED"}
		}
		defer os.Remove(publicFile)
		return windowsSetup(ctx, account, publicFile, a.Fingerprint, true, false, false, true)
	}
	if err := installCurrentUserKey(account, a.PublicKey); err != nil {
		return agentResult{Code: "LOCAL_SSH_SETUP_FAILED", Message: err.Error()}
	}
	return agentResult{OK: true}
}

// Reuse the same connection code on restart or upgrade, including old codes
// with an elapsed deadline. Only a local renew changes its value.
func ensureSSHGrant(c *Config, account string) error {
	profile := filepath.Dir(c.path)
	unlock, err := lockAccess(profile)
	if err != nil {
		return err
	}
	var existing sshGrant
	err = readJSON(filepath.Join(profile, "ssh-grant.json"), &existing)
	if err == nil && existing.User == account {
		key, e := readConnectionKey(localPath(c, "connection-key-ssh.txt"))
		if e != nil || !validGrantToken(key.SSHGrant) || grantHash(key.SSHGrant) != existing.Hash {
			unlock()
			return errors.New("SAVED_CONNECTION_CODE_UNAVAILABLE")
		}
		existing.Expires = 0
		err = privateJSON(filepath.Join(profile, "ssh-grant.json"), existing)
		unlock()
		if err == nil {
			fmt.Println("allow-ready=multiple-devices")
		}
		return err
	}
	unlock()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return issueSSHGrant(c, account)
}
