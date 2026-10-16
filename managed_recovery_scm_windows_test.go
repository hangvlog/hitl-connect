package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type recoverySCMProbe struct{ log string }

func (p recoverySCMProbe) Execute(_ []string, _ <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	f, err := os.OpenFile(p.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return false, 1
	}
	_, err = fmt.Fprintln(f, time.Now().UTC().Format(time.RFC3339Nano))
	f.Close()
	if err != nil {
		return false, 1
	}
	status <- svc.Status{State: svc.Running}
	time.Sleep(200 * time.Millisecond)
	os.Exit(71) // Deliberate user-mode process crash, never a machine restart.
	return false, 0
}

// Invoked only by the temporary SCM service below, never by ordinary tests.
func TestManagedRecoverySCMHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--hitl-scm-probe" && i+2 < len(os.Args) {
			if err := svc.Run(os.Args[i+1], recoverySCMProbe{log: os.Args[i+2]}); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Skip("SCM helper")
}

// Opt-in native Windows acceptance. Creates one temporary demand-start service,
// observes actual SCM recovery, and deletes only that service on completion.
// No provider profile, existing service, boot setting or protection is changed.
func TestManagedRecoverySCM(t *testing.T) {
	if os.Getenv("HITL_SCM_INTEGRATION") != "1" {
		t.Skip("set HITL_SCM_INTEGRATION=1 in an elevated Windows test session")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("SCM acceptance requires elevation")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("HITLConnect-RecoveryTest-%d-%d", os.Getpid(), time.Now().Unix())
	log := filepath.Join(t.TempDir(), "starts.txt")
	c := managedServiceConfig()
	c.DisplayName = name
	c.Description = "Temporary HITL Connect recovery acceptance test"
	c.StartType, c.DelayedAutoStart = mgr.StartManual, false
	s, err := m.CreateService(name, exe, c, "-test.run=^TestManagedRecoverySCMHelper$", "--", "--hitl-scm-probe", name, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer func() {
		// Clear pending recovery before removing our service registration.
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.NoAction}}, 0); err != nil {
			t.Error("clear test recovery:", err)
		}
		if state, err := s.Query(); err == nil && state.State != svc.Stopped {
			t.Error("test service did not stop")
		}
		if err := s.Delete(); err != nil {
			t.Error("delete test service:", err)
		}
	}()
	if err := s.SetRecoveryActions(managedRecoveryActions(), 86400); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(false); err != nil {
		t.Fatal(err)
	}
	actions, err := s.RecoveryActions()
	if err != nil || len(actions) != 3 || actions[2].Type != mgr.NoAction {
		t.Fatal("SCM did not retain bounded recovery:", actions, err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	readStarts := func() []string {
		data, err := os.ReadFile(log)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Fields(string(data))
	}
	deadline := time.Now().Add(65 * time.Second)
	for len(readStarts()) < 3 && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
	if got := len(readStarts()); got != 3 {
		t.Fatalf("expected initial start plus two recovery starts, got %d", got)
	}
	// Longer than the last restart delay: SCM must not repeat that action.
	time.Sleep(35 * time.Second)
	starts := readStarts()
	if len(starts) != 3 {
		t.Fatalf("persistent crash kept restarting: %v", starts)
	}
	state, err := s.Query()
	if err != nil || state.State != svc.Stopped {
		t.Fatal("expected stopped after two retries:", state, err)
	}
	c, err = s.Config()
	if err != nil {
		t.Fatal(err)
	}
	c.BinaryPathName = windows.EscapeArg(filepath.Join(filepath.Dir(log), "missing-program.exe"))
	if err = s.UpdateConfig(c); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(); !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatal("missing executable should fail with file-not-found:", err)
	}
	state, err = s.Query()
	if err != nil || state.State != svc.Stopped {
		t.Fatal("missing executable must stay stopped:", state, err)
	}
	t.Logf("SCM observed three starts and then stopped; missing executable rejected: %v", starts)
}
