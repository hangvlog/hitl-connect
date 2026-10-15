package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestNamedSFTPMigrationPreservesOtherConfiguration(t *testing.T) {
	old := []byte("HostKey existing\r\nPasswordAuthentication no\r\nSubsystem sftp sftp-server.exe\r\nAllowUsers original\r\n")
	got, err := namedSFTPConfig(old, `C:\Windows\System32`)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(old, []byte("sftp-server.exe"), []byte("C:/Windows/System32/OpenSSH/HITL-SFTP/hitlconnect.exe"), 1)
	// system is the actual system directory, not the Windows root.
	got, err = namedSFTPConfig(old, `C:\Windows\System32`)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("unrelated config changed", err, string(got))
	}
	again, err := namedSFTPConfig(got, `C:\Windows\System32`)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("migration is not idempotent", err)
	}
	for _, invalid := range []string{"Subsystem sftp custom.exe\r\n", "Subsystem sftp sftp-server.exe\r\nSubsystem sftp sftp-server.exe\r\n"} {
		if _, err := namedSFTPConfig([]byte(invalid), `C:\Windows\System32`); err == nil {
			t.Fatal("accepted ambiguous/custom config")
		}
	}
}

func TestNamedSSHServiceRejectsConflicts(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	valid := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem", DisplayName: systemSSHServerService, BinaryPathName: filepath.Join(system, "OpenSSH", "hitlconnect.exe")}
	if err := validateNamedSSHService(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*mgr.Config){
		func(c *mgr.Config) { c.BinaryPathName += " -f other" },
		func(c *mgr.Config) { c.BinaryPathName = strings.Replace(c.BinaryPathName, "OpenSSH", "Other", 1) },
		func(c *mgr.Config) { c.ServiceStartName = "other-user" },
		func(c *mgr.Config) { c.DisplayName = "another service" },
		func(c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS },
	} {
		c := valid
		mutate(&c)
		if validateNamedSSHService(c) == nil {
			t.Fatal("accepted unrelated service", c)
		}
	}
}
