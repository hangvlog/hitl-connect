package main

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestSystemSSHRelayMigrationScope(t *testing.T) {
	base, sid := `C:\Users\owner\profile`, "S-1-5-21-1001"
	allowed := `C:\Program Files\HITL Connect\`
	args := []string{allowed + `v1\hitl-connect-cli.exe`, "system-ssh-service", "--dir", base, "--owner-sid", sid}
	config := mgr.Config{BinaryPathName: windows.ComposeCommandLine(args), ServiceStartName: "LocalSystem", ServiceType: windows.SERVICE_WIN32_OWN_PROCESS}
	if !systemSSHRelayScope(config, base, sid, allowed) {
		t.Fatal("matching product service rejected")
	}
	for _, tc := range []struct {
		index int
		value string
	}{
		{0, `C:\Program Files\HITL Connect-other\app.exe`},
		{0, allowed + `..\other\app.exe`},
		{1, "other-service"}, {2, "--other"}, {3, base + "-other"}, {4, "--other-sid"}, {5, sid + "-other"},
	} {
		changed := append([]string(nil), args...)
		changed[tc.index] = tc.value
		cfg := config
		cfg.BinaryPathName = windows.ComposeCommandLine(changed)
		if systemSSHRelayScope(cfg, base, sid, allowed) {
			t.Fatalf("accepted unrelated service: %v", changed)
		}
	}
	config.ServiceStartName = `NT AUTHORITY\LocalService`
	if systemSSHRelayScope(config, base, sid, allowed) {
		t.Fatal("accepted wrong service account")
	}
}
