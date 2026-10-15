package main

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestEmbeddedWindowsAccountAliases(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	_, sid, err := nativeLocalAccount(name)
	if err != nil {
		t.Skip("requires a local user test process")
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	p := hostAuthorization{User: domain + `\` + name, SID: sid}
	for _, alias := range []string{name, domain + `\` + name, host + `\` + name} {
		if !embeddedLoginUser(p, alias) {
			t.Fatalf("same SID alias rejected: %s", alias)
		}
	}
	p.SID = "S-1-5-21-0-0-0-9999"
	if embeddedLoginUser(p, name) {
		t.Fatal("different SID accepted")
	}
	p.SID = sid
	for _, bad := range []string{"", `NT AUTHORITY\SYSTEM`, "hitl-nonexistent-account-test", " " + name} {
		if embeddedLoginUser(p, bad) {
			t.Fatal("unauthorized account accepted")
		}
	}
}

func TestBackgroundCommandPreservesAccountAndCommandLine(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	attrs := &syscall.SysProcAttr{
		Token:         syscall.Token(123),
		CmdLine:       `cmd.exe /d /s /c "echo quoted & exit /b 7"`,
		CreationFlags: windows.CREATE_UNICODE_ENVIRONMENT,
	}
	cmd.SysProcAttr = attrs
	hideGUIChild(cmd)
	if cmd.SysProcAttr != attrs || attrs.Token != syscall.Token(123) || attrs.CmdLine != `cmd.exe /d /s /c "echo quoted & exit /b 7"` {
		t.Fatal("background configuration replaced account token or command line")
	}
	if !attrs.HideWindow || attrs.CreationFlags != windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW {
		t.Fatal("background configuration must suppress the console and preserve other flags")
	}
	plain := exec.Command("cmd.exe")
	hideGUIChild(plain)
	if !plain.SysProcAttr.HideWindow || plain.SysProcAttr.CreationFlags != windows.CREATE_NO_WINDOW {
		t.Fatal("plain shell was not configured without a console")
	}
}
