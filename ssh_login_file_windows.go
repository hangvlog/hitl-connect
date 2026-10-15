package main

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sshLoginDescriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	sid, err := currentOwnerSID()
	if err != nil {
		return nil, "", err
	}
	// chmod(0600) does not remove inherited Windows permissions. Apply the
	// protected descriptor before any private-key bytes are written.
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "G:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")")
	return sd, sid, err
}

func createSSHLoginFile(path string) (*os.File, error) {
	if err := rejectExistingSSHPath(path); err != nil {
		return nil, err
	}
	sd, _, err := sshLoginDescriptor()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// Upgrade only HITL's own default key, retaining its bytes and identity.
// Imported keys are never passed here. Refuse another owner's file.
func protectSSHLoginFile(path string) error {
	if err := rejectReparse(path); err != nil {
		return err
	}
	want, sid, err := sshLoginDescriptor()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	actual, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := actual.Owner()
	if err != nil || owner.String() != sid {
		return errors.New("SSH_LOGIN_KEY_OWNER_MISMATCH")
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(want)
	return err
}
