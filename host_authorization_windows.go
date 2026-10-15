package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ordinary local users may inspect the account but cannot modify the consent.
const authorizationSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)"

func createAuthorizationFile(profile string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(authorizationSDDL)
	if err != nil {
		return nil, fmt.Errorf("HOST_AUTHORIZATION_DESCRIPTOR_FAILED: %w", err)
	}
	path := filepath.Join(profile, ".host-authorization-"+rand.Text())
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("HOST_AUTHORIZATION_PATH_FAILED: %w", err)
	}
	// Match the already verified directory-creation path: set the descriptor at
	// creation, instead of reopening an inherited file for WRITE_OWNER/WRITE_DAC.
	// CREATE_NEW rejects existing names (including reparse points). Keep writes
	// and deletion exclusive until the verified policy has been flushed/closed.
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, fmt.Errorf("HOST_AUTHORIZATION_CREATE_FAILED: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	// Fail before writing any policy bytes if the filesystem did not apply the
	// exact protected owner/group and effective permissions requested above.
	if err = checkAuthorizationProtection(file); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("HOST_AUTHORIZATION_PROTECTION_FAILED: %w", err)
	}
	return file, nil
}
func checkAuthorizationProtection(file *os.File) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	expected, err := windows.SecurityDescriptorFromString(authorizationSDDL)
	if err != nil {
		return err
	}
	if !equivalentFilesystemACL(sd, expected) {
		return errors.New("HOST_AUTHORIZATION_UNPROTECTED")
	}
	return nil
}
