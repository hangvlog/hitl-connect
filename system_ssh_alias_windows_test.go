package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemSSHAliasValidation(t *testing.T) {
	system := t.TempDir()
	dir := filepath.Join(system, "OpenSSH")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "sshd.exe")
	alias := filepath.Join(dir, "hitlconnect.exe")
	for _, p := range []string{original, alias} {
		if err := os.WriteFile(p, []byte("same system binary"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{original, alias, strings.ToUpper(alias)} {
		if exe, err := systemSSHExecutable(`"`+p+`"`, system); err != nil || exe != p {
			t.Fatalf("valid path %q: %q %v", p, exe, err)
		}
	}
	for _, command := range []string{
		`"` + filepath.Join(system, "hitlconnect.exe") + `"`,
		`"` + filepath.Join(dir, "wrapper.exe") + `"`,
		`"` + alias + `" -f other`,
		`"` + alias + `" -o AuthorizedKeysFile=other`,
		`hitlconnect.exe`,
	} {
		if _, err := systemSSHExecutable(command, system); err == nil {
			t.Fatalf("accepted %q", command)
		}
	}
	if err := os.WriteFile(original, []byte("updated Windows binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := systemSSHExecutable(`"`+alias+`"`, system); err == nil || err.Error() != "SYSTEM_SSH_ALIAS_OUTDATED_OR_MODIFIED" {
		t.Fatalf("stale alias: %v", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := systemSSHExecutable(`"`+alias+`"`, system); err == nil {
		t.Fatal("missing alias accepted")
	}
	if err := os.Symlink(original, alias); err == nil {
		if _, err := systemSSHExecutable(`"`+alias+`"`, system); err == nil {
			t.Fatal("symlink alias accepted")
		}
	}
}
