package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDefaultSSHKeyProtectsInheritedWindowsAccess(t *testing.T) {
	base := t.TempDir()
	// A permissive parent must not leak the new key to inherited readers.
	parent, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, _ := parent.DACL()
	if err = windows.SetNamedSecurityInfo(base, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	file, _, err := accessKey(base, "")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(file)
	expected, _, _ := sshLoginDescriptor()
	if !nativeSSHACLMatches(file, expected.String()) {
		t.Fatal("new key inherited broad access")
	}
	if err = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err = accessKey(base, ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) || !nativeSSHACLMatches(file, expected.String()) {
		t.Fatal("repair changed identity or failed to protect the file")
	}
	imported := filepath.Join(base, "imported.key")
	if err = os.WriteFile(imported, before, 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, _ := nativeSSHDescriptor(imported)
	if _, _, err = accessKey(base, imported); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := nativeSSHDescriptor(imported)
	if descriptor != unchanged {
		t.Fatal("imported key permissions were modified")
	}
}
