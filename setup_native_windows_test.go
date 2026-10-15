package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestNativeSSHWindowsFilesystem(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("administrator test token required")
	}
	root := t.TempDir()
	sd := sshSDDL("S-1-5-32-544", false, true)
	dir := filepath.Join(root, "keys")
	if e := nativeSSHDirectory(dir, sd); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "authorized_keys")
	data := []byte("# existing key options and comments\r\n")
	if e := nativeSSHWrite(file, data, sshSDDL("S-1-5-32-544", false, false)); e != nil {
		t.Fatal(e)
	}
	r := newSSHSetupReport()
	if e := nativeSSHBackup(root, file, r); e != nil {
		t.Fatal(e)
	}
	backup := setupString(r, "backupDirectory")
	saved, e := os.ReadFile(filepath.Join(backup, "authorized_keys"))
	if e != nil || !bytes.Equal(saved, data) {
		t.Fatal(e)
	}
	descriptor, e := os.ReadFile(filepath.Join(backup, "authorized_keys.acl.txt"))
	if e != nil {
		t.Fatal(e)
	}
	if e = nativeSSHWrite(file, []byte("updated\r\n"), string(descriptor)); e != nil {
		t.Fatal(e)
	}
	if e = nativeSSHWrite(file, saved, string(descriptor)); e != nil {
		t.Fatal(e)
	}
	if !nativeSSHACLMatches(file, string(descriptor)) {
		t.Fatal("backup ACL not restored")
	}
	got, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(got, data) {
		t.Fatal("backup content not restored", e)
	}
	link := filepath.Join(root, "linked")
	if e = os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	if e = nativeSSHWrite(filepath.Join(link, "new"), data, sshSDDL("S-1-5-32-544", false, false)); e == nil {
		t.Fatal("junction/symlink write accepted")
	}
}
func TestNativeSSHWindowsServiceCommand(t *testing.T) {
	exe, args, e := nativeServiceCommand(`"C:\Program Files\OpenSSH\sshd.exe" -f "C:\ProgramData\ssh\sshd_config" -p 22 -D`)
	if e != nil || exe != `C:\Program Files\OpenSSH\sshd.exe` || len(args) != 4 {
		t.Fatal(exe, args, e)
	}
	for _, command := range []string{`C:\wrapper.exe`, `C:\sshd.exe -o AuthorizedKeysFile=other`, `C:\sshd.exe -f one -f two`, `sshd.exe`} {
		if _, _, e = nativeServiceCommand(command); e == nil {
			t.Fatal("custom wrapper/options accepted", command)
		}
	}
}

func TestManagedServiceInspection(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("administrator test token required")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	name := fmt.Sprintf("HITLConnect-InspectionTest-%d", time.Now().UnixNano())
	stage := ""
	s, _, err := inspectManagedService(m, name, &stage)
	if err != nil || s != nil || stage != "open-existing-service" {
		t.Fatalf("absent service: %v %v %s", s, err, stage)
	}
	// A disabled, never-started test service isolates SCM behavior from the
	// real provider. A missing executable alone must not fail config inspection.
	exe := filepath.Join(t.TempDir(), "missing-test-executable.exe")
	s, err = m.CreateService(name, exe, mgr.Config{StartType: mgr.StartDisabled, DisplayName: "HITL Connect inspection test (never started)"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() {
		if err := s.Delete(); err != nil {
			t.Error("remove test service:", err)
		}
	}()
	opened, config, err := inspectManagedService(m, name, &stage)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
	if config.StartType != mgr.StartDisabled || config.BinaryPathName == "" || stage != "read-existing-service-config" {
		t.Fatal("existing service configuration lost", stage)
	}
	// Reproduce a removed registration while SCM still holds the service.
	// Delete only this test-owned key; never touch any installed HITL service.
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name); err != nil {
		t.Fatal(err)
	}
	opened, _, err = inspectManagedService(m, name, &stage)
	if opened != nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("missing registration treated as a fresh install: %v %v", opened, err)
	}
	r := installReport(stage, err)
	if r.OK || r.Code != "HOST_SERVICE_CONFIG_MISSING" || r.Stage != "read-existing-service-config" || r.NativeCode == nil || *r.NativeCode != 2 {
		t.Fatalf("missing diagnosis: %+v", r)
	}
	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.READ); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("inspection recreated missing registration", err)
	}
}
