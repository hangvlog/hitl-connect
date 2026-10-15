package main

import (
	"context"
	"path/filepath"
	"time"
)

// Old profiles keep their first device and code without re-pairing. New records
// carry the generation so delayed installers cannot restore replaced authority.
func accessUsesGrant(a sshAccess, g sshGrant) bool {
	return g.Hash != "" && (a.GrantHash == g.Hash || (a.GrantHash == "" && g.Request == a.ID))
}

func grantInstallationCurrent(profile string, a sshAccess, g sshGrant) bool {
	var current sshAccess
	var grant sshGrant
	path, err := accessPath(profile, a.ID)
	return err == nil && readJSON(path, &current) == nil && current.Status == "configuring" &&
		current.GrantHash == g.Hash && readJSON(filepath.Join(profile, "ssh-grant.json"), &grant) == nil &&
		!grant.Disabled && grant.Hash == g.Hash && grant.User == g.User
}

func installGrantedKey(profile string, a sshAccess, g sshGrant) {
	// Serialize read/modify/write of authorized_keys and Windows SSH setup across
	// devices and processes. The OS releases this lock if an installer crashes.
	// Do not hold the short metadata lock while waiting or running system setup.
	for {
		if !grantInstallationCurrent(profile, a, g) {
			return
		}
		unlock, acquired, err := tryProfileLock(profile, ".ssh-install.lock")
		if err != nil {
			finishGrantInstallation(profile, a, g, agentResult{Code: "SSH_INSTALL_LOCK_FAILED"})
			return
		}
		if !acquired {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		defer unlock()
		if !grantInstallationCurrent(profile, a, g) {
			return
		}
		result := installSSHAccessKey(context.Background(), profile, a, g.User)
		finishGrantInstallation(profile, a, g, result)
		return
	}
}

func finishGrantInstallation(profile string, a sshAccess, g sshGrant, result agentResult) {
	unlock, err := lockAccess(profile)
	if err != nil {
		return
	}
	defer unlock()
	if !grantInstallationCurrent(profile, a, g) {
		return
	}
	path, _ := accessPath(profile, a.ID)
	var current sshAccess
	if readJSON(path, &current) != nil {
		return
	}
	if result.OK {
		if _, ok := embeddedPolicy(profile); ok {
			server, e := loadEmbeddedSSH(profile)
			if e == nil {
				e = server.audit("device-authorized", a.Peer, a.Fingerprint, "", "grant", 0)
			}
			if e != nil {
				current.Status, current.Code = "setup-failed", "AUDIT_UNAVAILABLE"
				_ = privateJSON(path, current)
				return
			}
		}
		current.Status, current.User, current.Code = "approved", g.User, ""
	} else {
		current.Status, current.Code = "setup-failed", result.Code
	}
	_ = privateJSON(path, current)
}
