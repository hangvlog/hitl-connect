package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Caller holds the cross-process access lock. Keep a tombstone so existing
// SSH keys cannot use this HITL path after their code is explicitly disabled.
func revokeGrantRequest(profile string, grant sshGrant) error {
	for _, entry := range listSSHAccess(profile) {
		if !accessUsesGrant(entry, grant) {
			continue
		}
		path, err := accessPath(profile, entry.ID)
		if err != nil {
			return err
		}
		var a sshAccess
		if err = readJSON(path, &a); err != nil {
			return err
		}
		a.Status, a.Code = "revoked", "CONNECTION_CODE_DISABLED"
		if err = privateJSON(path, a); err != nil {
			return err
		}
	}
	return nil
}

func disableSSHGrant(profile string) error {
	unlock, err := lockAccess(profile)
	if err != nil {
		return err
	}
	defer unlock()
	var grant sshGrant
	file := filepath.Join(profile, "ssh-grant.json")
	if err = readJSON(file, &grant); err != nil {
		return err
	}
	// Deny forwarding first, even if a later tombstone write fails.
	grant.Disabled = true
	if err = privateJSON(file, grant); err != nil {
		return err
	}
	if err = revokeGrantRequest(profile, grant); err != nil {
		return err
	}
	if err = syncSystemSSHKeys(profile); err != nil {
		return err
	}
	if _, ok := embeddedPolicy(profile); ok {
		e, err := loadEmbeddedSSH(profile)
		if err != nil {
			return err
		}
		return e.audit("code-disabled", "", "", "", "revoke", 0)
	}
	return nil
}

func (g *guiSession) disableGrant() error {
	g.mu.Lock()
	account, role := g.state.AuthorizedUser, g.state.Role
	g.mu.Unlock()
	if role != "host" || account == "" {
		return errors.New("先选择提供端账号")
	}
	if err := disableSSHGrant(filepath.Join(g.base, "public-host")); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state.GrantDisabled, g.state.HasInvitation = true, false
	g.stepLocked("login", "attention", "连接码已手动停用，所有已授权设备的 HITL 连接已撤销")
	return nil
}

func sshPeerAllowed(profile, peer, device string) bool {
	var grant sshGrant
	err := readJSON(filepath.Join(profile, "ssh-grant.json"), &grant)
	legacy := os.IsNotExist(err)
	if !legacy && (err != nil || grant.Disabled) {
		return false
	}
	revoked := false
	for _, a := range listSSHAccess(profile) {
		if a.Peer != peer || a.DeviceKey != device {
			continue
		}
		if a.Status == "approved" && (legacy || accessUsesGrant(a, grant)) {
			return true
		}
		if a.Status == "revoked" {
			revoked = true
		}
	}
	// Unknown identities may use manual SSH only on grant-free legacy profiles.
	return legacy && !revoked
}

func sshDeviceAllowed(c *Config, encrypted *tls.Conn, peer string) bool {
	certs := encrypted.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	digest := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return sshPeerAllowed(filepath.Dir(c.path), peer, hex.EncodeToString(digest[:]))
}

func watchSSHDevice(c *Config, encrypted *tls.Conn, peer string, done <-chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if !sshDeviceAllowed(c, encrypted, peer) {
				_ = encrypted.Close()
				return
			}
		}
	}
}
