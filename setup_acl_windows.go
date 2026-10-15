package main

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sshSDDL(owner string, user, directory bool) string {
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	s := "O:" + owner + "G:" + owner + "D:P(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BA)"
	if user {
		s += "(A;" + inheritance + ";FA;;;" + owner + ")"
	}
	return s
}
func nativeSSHDescriptor(path string) (string, error) {
	if e := rejectReparse(path); e != nil {
		return "", e
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return "", e
	}
	return sd.String(), nil
}
func nativeSSHACLMatches(path, sddl string) bool {
	if e := rejectReparse(path); e != nil {
		return false
	}
	actual, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return false
	}
	expected, e := windows.SecurityDescriptorFromString(sddl)
	return e == nil && equivalentFilesystemACL(actual, expected)
}
func applySSHDescriptor(path, sddl string) error {
	if e := rejectReparse(path); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return e
	}
	group, _, e := sd.Group()
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	control, _, e := sd.Control()
	if e != nil {
		return e
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, owner, group, acl, nil)
	runtime.KeepAlive(sd)
	return e
}

// Check existing ancestors even for a not-yet-created leaf. Never follow a
// junction or symbolic link while an elevated installer writes SSH authority.
func rejectExistingSSHPath(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		if _, e := os.Lstat(p); e == nil {
			return rejectReparse(p)
		} else if !os.IsNotExist(e) {
			return e
		}
		if filepath.Dir(p) == p {
			return errors.New("SSH_PARENT_MISSING")
		}
	}
}
func nativeSSHDirectory(path, sddl string) error {
	if e := rejectExistingSSHPath(path); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	e = windows.CreateDirectory(name, &sa)
	runtime.KeepAlive(sd)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return e
	}
	if e = rejectReparse(path); e != nil {
		return e
	}
	if !nativeSSHACLMatches(path, sddl) {
		if e = applySSHDescriptor(path, sddl); e != nil {
			return e
		}
	}
	if !nativeSSHACLMatches(path, sddl) {
		return errors.New("SSH_DIRECTORY_ACL_INVALID")
	}
	return nil
}
func nativeSSHWrite(path string, data []byte, sddl string) error {
	if e := rejectExistingSSHPath(path); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return e
	}
	temp := filepath.Join(filepath.Dir(path), ".hitl-ssh-"+rand.Text())
	name, e := windows.UTF16PtrFromString(temp)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), temp)
	defer os.Remove(temp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	// A protected descriptor must survive filesystem normalization before commit.
	control, _, e := sd.Control()
	if e != nil {
		return e
	}
	if control&windows.SE_DACL_PROTECTED != 0 && !nativeSSHACLMatches(temp, sddl) {
		return errors.New("SSH_FILE_ACL_INVALID")
	}
	if e = rejectExistingSSHPath(path); e != nil {
		return e
	}
	return os.Rename(temp, path)
}
func nativeSSHBackup(programData, path string, r sshSetupReport) error {
	info, e := os.Stat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	sd, e := nativeSSHDescriptor(path)
	if e != nil {
		return e
	}
	dir := setupString(r, "backupDirectory")
	if dir == "" {
		root := filepath.Join(programData, "HITLConnect-SSH")
		// Keep old backups untouched; new ones use a protected, explicit namespace.
		if e = nativeSSHDirectory(root, sshSDDL("S-1-5-32-544", false, true)); e != nil {
			return e
		}
		dir = filepath.Join(root, "backup-"+rand.Text())
		if e = nativeSSHDirectory(dir, sshSDDL("S-1-5-32-544", false, true)); e != nil {
			return e
		}
		r["backupDirectory"] = dir
	}
	// Never overwrite an earlier snapshot during the same operation.
	dest := filepath.Join(dir, filepath.Base(path))
	if !info.IsDir() {
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if e = nativeSSHWrite(dest, data, sshSDDL("S-1-5-32-544", false, false)); e != nil {
			return e
		}
	}
	return nativeSSHWrite(dest+".acl.txt", []byte(sd), sshSDDL("S-1-5-32-544", false, false))
}
