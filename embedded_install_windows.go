package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

func prepareEmbeddedSSH(profile, account, address, privilege string) error {
	_, sid, err := nativeLocalAccount(account)
	if err != nil {
		return err
	}
	if privilege != "standard" && privilege != "administrator" {
		return errors.New("INVALID_PRIVILEGE")
	}

	if err = os.MkdirAll(profile, 0700); err != nil {
		return err
	}
	old, oldErr := readHostAuthorization(profile)
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return oldErr
	}
	if oldErr == nil && (old.User != account || (old.SID != "" && old.SID != sid)) {
		return errors.New("HOST_SCOPE_FIXED")
	}
	// Upgrades preserve the old host keys, including all supported algorithms,
	// so existing known_hosts pins are not silently reset. Never regenerate a
	// broken saved key or guess when custom sshd configuration is in use.
	if oldErr == nil && old.Engine == "" {
		key, err := probeSSH(old.Address)
		if err != nil {
			return errors.New("HOST_KEY_MIGRATION_REQUIRES_EXISTING_SSH")
		}
		pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
		if err != nil {
			return err
		}
		matched := false
		for _, kind := range []string{"ed25519", "ecdsa", "rsa"} {
			from := filepath.Join(pd, "ssh", "ssh_host_"+kind+"_key")
			data, err := os.ReadFile(from)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			signer, err := ssh.ParsePrivateKey(data)
			if err != nil {
				return errors.New("EXISTING_HOST_KEY_INVALID")
			}
			if bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
				matched = true
			}
			dest := filepath.Join(profile, "ssh-host-"+kind+".key")
			if existing, err := os.ReadFile(dest); err == nil {
				if !bytes.Equal(existing, data) {
					return errors.New("HOST_KEY_MIGRATION_CONFLICT")
				}
			} else if os.IsNotExist(err) {
				if err = nativeSSHWrite(dest, data, sshSDDL("S-1-5-32-544", false, false)); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		if !matched {
			return errors.New("CUSTOM_HOST_KEY_MIGRATION_REQUIRED")
		}
	}
	if oldErr != nil {
		if err = createEmbeddedHostKey(profile); err != nil {
			return err
		}
	}
	// Host private keys are readable only by SYSTEM/administrators, even when
	// the panel owner is an ordinary account with read access to the profile.
	for _, kind := range []string{"ed25519", "ecdsa", "rsa"} {
		path := filepath.Join(profile, "ssh-host-"+kind+".key")
		if _, err = os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err = applySSHDescriptor(path, sshSDDL("S-1-5-32-544", false, false)); err != nil {
			return err
		}
	}
	a := hostAuthorization{Version: 2, Profile: canonicalProfile(profile), User: account, Address: address, Engine: "embedded", SID: sid, Privilege: privilege}
	if oldErr == nil {
		backup := filepath.Join(profile, "host-authorization.previous.json")
		if _, err = os.Stat(backup); os.IsNotExist(err) {
			if err = copyInstallFile(filepath.Join(profile, "host-authorization.json"), backup); err != nil {
				return err
			}
		}
	}
	if err = writeHostAuthorization(profile, a); err != nil {
		return err
	}
	server, err := loadEmbeddedSSH(profile)
	if err != nil {
		return err
	}
	return server.audit("local-authorization", "", "", "", "install", 0)
}
