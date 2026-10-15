package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSystemSSHAliasRefresh(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(system, "OpenSSH", "sshd.exe")
	data, err := os.ReadFile(signed)
	if os.IsNotExist(err) {
		t.Skip("system OpenSSH unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "sshd.exe")
	alias := filepath.Join(dir, "hitlconnect.exe")
	if err = os.WriteFile(original, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(alias, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = refreshSystemSSHAlias(context.Background(), original, false); err == nil {
		t.Fatal("running server would be replaced")
	}
	if err = refreshSystemSSHAlias(context.Background(), original, true); err != nil {
		t.Fatal(err)
	}
	if err = validateSystemSSHAlias(alias, original); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(original, []byte("unsigned replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = refreshSystemSSHAlias(context.Background(), original, true); err == nil {
		t.Fatal("unsigned source accepted")
	}
	after, err := os.ReadFile(alias)
	if err != nil || len(after) != len(data) {
		t.Fatal("valid alias overwritten", err)
	}
}
