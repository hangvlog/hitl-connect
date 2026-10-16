package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func managedLocation(base, sid string) (string, string, error) {
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return "", "", e
	}
	sum := sha256.Sum256([]byte(strings.ToLower(canonicalProfile(base)) + "|" + sid))
	id := hex.EncodeToString(sum[:8])
	return filepath.Join(root, "HITLConnect", id), "HITLConnect-" + id, nil
}
func currentOwnerSID() (string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	return u.User.Sid.String(), nil
}

// New directories get their protected DACL at creation, before any secret or
// executable is written. Existing installations must have the same owner/ACL.
func managedDirectory(path, sid string) error {
	readSID := sid
	if readSID == "" {
		readSID = "BU"
	}
	text := "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + readSID + ")"
	sd, e := windows.SecurityDescriptorFromString(text)
	if e != nil {
		return e
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	e = windows.CreateDirectory(name, &sa)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = rejectReparse(path); e != nil {
		return e
	}
	actual, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	if !equivalentFilesystemACL(actual, sd) {
		return errors.New("INSTALL_DIRECTORY_UNPROTECTED")
	}
	return nil
}
func rejectReparse(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		name, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return e
		}
		a, e := windows.GetFileAttributes(name)
		if e != nil {
			return e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("INSTALL_REPARSE_POINT_REJECTED")
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}
func copyInstallFile(source, dest string) error {
	if e := rejectReparse(source); e != nil {
		return e
	}
	f, e := os.Open(source)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return errors.New("INSTALL_SOURCE_INVALID")
	}
	target, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(target, io.LimitReader(f, (64<<20)+1))
	closeErr := target.Close()
	if e == nil {
		e = closeErr
	}
	return e
}
func migrateProvider(source, dest string) error {
	if _, e := os.Stat(filepath.Join(dest, "config.json")); e == nil {
		return nil
	}
	if _, e := os.Stat(filepath.Join(source, "config.json")); os.IsNotExist(e) {
		// Fresh installs carry deployment settings, not a pre-authorized identity.
		if _, err := localProviderRelay(source); err != nil {
			return err
		}
		if err := os.MkdirAll(dest, 0700); err != nil {
			return err
		}
		return copyInstallFile(filepath.Join(source, "relay.local.json"), filepath.Join(dest, "relay.local.json"))
	}
	c, e := load(filepath.Join(source, "config.json"))
	if e != nil {
		return e
	}
	if c.Key != "identity.key" || c.Certificate != "identity.crt" || len(c.Services) > 1 {
		return errors.New("CUSTOM_PROFILE_MIGRATION_REQUIRED")
	}
	if _, ok := c.Services["ssh"]; !ok {
		return errors.New("CUSTOM_PROFILE_MIGRATION_REQUIRED")
	}
	live := dest
	dest, e = os.MkdirTemp(filepath.Dir(live), ".provider-migration-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dest)
	finish := func() error { return os.Rename(dest, live) }
	// Copy data only; never execute scripts or accept path references from it.
	for _, name := range []string{"identity.key", "identity.crt", "identity.json", "config.json", "ssh-grant.json", "connection-key-ssh.txt"} {
		from := filepath.Join(source, name)
		if _, e = os.Stat(from); os.IsNotExist(e) {
			continue
		}
		if e = copyInstallFile(from, filepath.Join(dest, name)); e != nil {
			return e
		}
	}
	entries, e := os.ReadDir(filepath.Join(source, "ssh-access"))
	if os.IsNotExist(e) {
		return finish()
	}
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if e = os.MkdirAll(filepath.Join(dest, "ssh-access"), 0700); e != nil {
			return e
		}
		if e = copyInstallFile(filepath.Join(source, "ssh-access", entry.Name()), filepath.Join(dest, "ssh-access", entry.Name())); e != nil {
			return e
		}
	}
	return finish()
}

func installWindowsHost(ctx context.Context, base, account, address, sid string, stage *string, privileges ...string) (outcome error) {
	*stage = "validate-elevation"
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("ELEVATION_REQUIRED")
	}
	*stage = "validate-owner"
	owner, e := windows.StringToSid(sid)
	if e != nil || !strings.HasPrefix(sid, "S-1-5-21-") {
		return errors.New("LOCAL_OWNER_REQUIRED")
	}
	if _, _, kind, e := owner.LookupAccount(""); e != nil || kind != windows.SidTypeUser {
		return errors.New("LOCAL_OWNER_REQUIRED")
	}
	*stage = "locate-installation"
	root, name, e := managedLocation(base, sid)
	if e != nil {
		return e
	}
	*stage = "protect-install-root"
	if e = managedDirectory(filepath.Dir(root), ""); e != nil {
		return e
	}
	*stage = "protect-profile-directory"
	if e = managedDirectory(root, sid); e != nil {
		return e
	}

	// This is the sole account/service setup step. Restarts read its protected result.
	*stage = "prepare-ssh"
	_, _, e = nativeLocalAccount(account)
	if address == "" {
		address = "127.0.0.1:22"
	}
	if e != nil {
		return e
	}
	if oldAuth, err := readHostAuthorization(filepath.Join(root, "public-host")); err == nil && oldAuth.User != account {
		return errors.New("HOST_SCOPE_FIXED")
	}
	*stage = "open-service-manager"
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	service, old, e := inspectManagedService(manager, name, stage)
	if e != nil {
		return e
	}
	var rollbackAuthorization *hostAuthorization
	var rollbackPlan *connectionPlan
	if a, err := readHostAuthorization(filepath.Join(root, "public-host")); err == nil {
		rollbackAuthorization = &a
	}
	if p, err := readConnectionPlan(root); err == nil {
		rollbackPlan = &p
	}
	if service != nil {
		defer service.Close()
	}
	*stage = "install-executable"
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	installed, digest, e := prepareManagedExecutable(root, exe)
	if e != nil {
		return e
	}
	if old.BinaryPathName != "" {
		*stage = "backup-existing-service"
		backup := filepath.Join(root, "rollback-"+time.Now().UTC().Format("20060102T150405.000000000"))
		if e = os.Mkdir(backup, 0700); e != nil {
			return e
		}
		if e = privateJSON(filepath.Join(backup, "service.json"), old); e != nil {
			return e
		}
		if rollbackAuthorization != nil {
			if e = privateJSON(filepath.Join(backup, "host-authorization.json"), rollbackAuthorization); e != nil {
				return e
			}
		}
		if rollbackPlan != nil {
			if e = privateJSON(filepath.Join(backup, "connection-plan.json"), rollbackPlan); e != nil {
				return e
			}
		}
	}
	if service != nil {
		*stage = "drain-existing-sessions"
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State != svc.Stopped {
			if status.State != svc.Running {
				return errors.New("HOST_SERVICE_BUSY")
			}
			if e = drainManagedBeforeUpgrade(ctx, root); e != nil {
				return e
			}
		}
		*stage = "stop-existing-service"
		wasRunning, err := stopManagedUpgrade(ctx, service)
		if err != nil {
			return err
		}
		// Arm rollback only after a successful stop. A rejected/unknown stop
		// must not trigger another stop, rewrite configuration, or start it.
		defer func() {
			if outcome == nil || old.BinaryPathName == "" {
				return
			}
			restore := func() error {
				if rollbackAuthorization != nil {
					if err := writeHostAuthorization(filepath.Join(root, "public-host"), *rollbackAuthorization); err != nil {
						return err
					}
				}
				if rollbackPlan != nil {
					if err := privateJSON(filepath.Join(root, "connection-plan.json"), *rollbackPlan); err != nil {
						return err
					}
				}
				return nil
			}
			if err := rollbackManagedUpgrade(service, old, wasRunning, outcome, restore); err != nil {
				outcome = fmt.Errorf("HOST_INSTALL_ROLLBACK_INCOMPLETE: original stage=%s code=%s; rollback: %w", *stage, installReport(*stage, outcome).Code, err)
			}
		}()
	}
	// Copy only once. A later upgrade keeps the live, protected identity and grants.
	profile := filepath.Join(root, "public-host")
	*stage = "migrate-provider"
	if e = migrateProvider(filepath.Join(base, "public-host"), profile); e != nil {
		return e
	}
	if _, err := os.Stat(filepath.Join(profile, "host-authorization.json")); os.IsNotExist(err) {
		if _, err = os.Stat(filepath.Join(profile, "config.json")); err == nil {
			if e = saveHostAuthorization(profile, account, address); e != nil {
				return e
			}
		}
	}
	var grant sshGrant
	if readJSON(filepath.Join(profile, "ssh-grant.json"), &grant) == nil && !grant.Disabled {
		for _, entry := range listSSHAccess(profile) {
			if !accessUsesGrant(entry, grant) || entry.Status != "setup-failed" {
				continue
			}
			path, err := accessPath(profile, entry.ID)
			if err != nil {
				return err
			}
			var access sshAccess
			if e = readJSON(path, &access); e != nil {
				return e
			}
			access.Status, access.Code = "pending", ""
			if e = privateJSON(path, access); e != nil {
				return e
			}
		}
	}
	*stage = "save-authorization"
	privilege := "standard"
	if previous, err := readHostAuthorization(profile); err == nil && previous.Privilege != "" {
		privilege = previous.Privilege
	}
	if len(privileges) > 0 && privileges[0] != "" {
		privilege = privileges[0]
	}
	if e = prepareEmbeddedSSH(profile, account, address, privilege); e != nil {
		return e
	}
	*stage = "save-plan"
	plan := connectionPlan{Version: 1, Role: "host", Host: guiRequest{Role: "host", User: account, Target: address, AllowSSH: true, Privilege: privilege}, Resume: true}
	if e = privateJSON(filepath.Join(root, "connection-plan.json"), plan); e != nil {
		return e
	}
	manifest, _ := json.Marshal(map[string]string{"version": guiVersion, "binarySha256": digest, "sourceProfile": base, "installedExecutable": installed, "service": name})
	// CreateService supplies this type implicitly; UpdateConfig does not.
	config := managedServiceConfig()
	*stage = "register-service"
	if service == nil {
		service, e = manager.CreateService(name, installed, config, "host-service", "--dir", root, "--service-name", name)
		if e != nil {
			return e
		}
		defer service.Close()
	} else {
		// Retain the previous command as a private, auditable rollback record.
		if e = privateJSON(filepath.Join(root, "service-rollback.json"), old); e != nil {
			return e
		}
		config.BinaryPathName = windows.ComposeCommandLine([]string{installed, "host-service", "--dir", root, "--service-name", name})
		if e = service.UpdateConfig(config); e != nil {
			return e
		}
	}
	*stage = "configure-recovery"
	if e = service.SetRecoveryActions(managedRecoveryActions(), 86400); e != nil {
		return e
	}
	if e = service.SetRecoveryActionsOnNonCrashFailures(false); e != nil {
		return e
	}
	*stage = "start-service"
	if e = service.Start(); e != nil && e != windows.ERROR_SERVICE_ALREADY_RUNNING {
		return e
	}
	*stage = "verify-service"
	for i := 0; i < 100; i++ {
		if managedReady(ctx, root) == nil {
			*stage = "save-installation-record"
			return privateText(filepath.Join(root, "installation.json"), string(manifest))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("HOST_SERVICE_NOT_READY")
}
