package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type upgradeTestService struct {
	state             svc.State
	queryErr, stopErr error
	stops             int
	onStop            func()
}

type upgradeRollbackService struct {
	upgradeTestService
	configErr, updateErr, startErr error
	updates, starts, reads         int
}

func (s *upgradeRollbackService) Config() (mgr.Config, error) {
	s.reads++
	return mgr.Config{}, s.configErr
}
func (s *upgradeRollbackService) UpdateConfig(mgr.Config) error {
	s.updates++
	return s.updateErr
}
func (s *upgradeRollbackService) Start(...string) error {
	s.starts++
	return s.startErr
}

func TestManagedRollbackRequiresKnownStoppedService(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		service                               upgradeRollbackService
		wasRunning                            bool
		cause, restoreErr                     error
		wantRestores, wantUpdates, wantStarts int
		wantErr                               error
	}{
		{name: "restore running", wasRunning: true, cause: windows.ERROR_DISK_FULL, service: upgradeRollbackService{upgradeTestService: upgradeTestService{state: svc.Stopped}}, wantRestores: 1, wantUpdates: 1, wantStarts: 1},
		{name: "preserve stopped", cause: windows.ERROR_DISK_FULL, service: upgradeRollbackService{upgradeTestService: upgradeTestService{state: svc.Stopped}}, wantRestores: 1, wantUpdates: 1},
		{name: "protection decision", wasRunning: true, cause: windows.ERROR_VIRUS_DELETED},
		{name: "deleted registration", cause: windows.ERROR_DISK_FULL, service: upgradeRollbackService{configErr: windows.ERROR_FILE_NOT_FOUND}, wantErr: windows.ERROR_FILE_NOT_FOUND},
		{name: "stop rejected", cause: windows.ERROR_DISK_FULL, service: upgradeRollbackService{upgradeTestService: upgradeTestService{state: svc.Running, stopErr: windows.ERROR_ACCESS_DENIED}}, wantErr: windows.ERROR_ACCESS_DENIED},
		{name: "restore rejected", wasRunning: true, cause: windows.ERROR_DISK_FULL, restoreErr: windows.ERROR_ACCESS_DENIED, service: upgradeRollbackService{upgradeTestService: upgradeTestService{state: svc.Stopped}}, wantRestores: 1, wantErr: windows.ERROR_ACCESS_DENIED},
		{name: "config rejected", wasRunning: true, cause: windows.ERROR_DISK_FULL, service: upgradeRollbackService{upgradeTestService: upgradeTestService{state: svc.Stopped}, updateErr: windows.ERROR_ACCESS_DENIED}, wantRestores: 1, wantUpdates: 1, wantErr: windows.ERROR_ACCESS_DENIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restores := 0
			err := rollbackManagedUpgrade(&tc.service, mgr.Config{}, tc.wasRunning, tc.cause, func() error { restores++; return tc.restoreErr })
			if !errors.Is(err, tc.wantErr) || restores != tc.wantRestores || tc.service.updates != tc.wantUpdates || tc.service.starts != tc.wantStarts {
				t.Fatalf("err=%v restores=%d updates=%d starts=%d", err, restores, tc.service.updates, tc.service.starts)
			}
			if managedProtectionBlocked(tc.cause) && tc.service.reads != 0 {
				t.Fatal("protection decision triggered rollback")
			}
		})
	}
}

func TestManagedInstallerProtectionReportPreservesNativeEvidence(t *testing.T) {
	for _, native := range []error{windows.ERROR_VIRUS_INFECTED, windows.ERROR_VIRUS_DELETED, windows.ERROR_ACCESS_DISABLED_BY_POLICY} {
		err := &os.PathError{Op: "open", Path: "private-profile", Err: native}
		r := installReport("install-executable", err)
		if r.OK || r.Code != "HOST_INSTALL_BLOCKED_BY_PROTECTION" || r.NativeCode == nil || r.Stage != "install-executable" {
			t.Fatal(r)
		}
		var failure *installerError
		if !errors.As(installerOutcome(nil, err), &failure) || failure.Report.Code != r.Code || failure.Report.NativeCode == nil || *failure.Report.NativeCode != *r.NativeCode {
			t.Fatal("process launch discarded protection evidence")
		}
	}
}

func (s *upgradeTestService) Query() (svc.Status, error) {
	return svc.Status{State: s.state}, s.queryErr
}
func (s *upgradeTestService) Control(cmd svc.Cmd) (svc.Status, error) {
	if cmd != svc.Stop {
		panic("unexpected control")
	}
	s.stops++
	if s.stopErr == nil {
		s.state = svc.Stopped
	}
	if s.onStop != nil {
		s.onStop()
	}
	return svc.Status{State: s.state}, s.stopErr
}

func TestManagedUpgradeStopRespectsExistingState(t *testing.T) {
	for _, tc := range []struct {
		name                string
		state               svc.State
		stopErr             error
		stops               int
		wasRunning, wantErr bool
	}{
		{"running", svc.Running, nil, 1, true, false},
		{"already stopped", svc.Stopped, nil, 0, false, false},
		{"stop denied", svc.Running, windows.ERROR_ACCESS_DENIED, 1, false, true},
		{"concurrent stop", svc.StopPending, nil, 0, false, true},
		{"concurrent start", svc.StartPending, nil, 0, false, true},
		{"paused", svc.Paused, nil, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &upgradeTestService{state: tc.state, stopErr: tc.stopErr}
			running, err := stopManagedUpgrade(context.Background(), s)
			if running != tc.wasRunning || (err != nil) != tc.wantErr || s.stops != tc.stops {
				t.Fatalf("running=%v err=%v stops=%d", running, err, s.stops)
			}
			if tc.stopErr != nil && !errors.Is(err, tc.stopErr) {
				t.Fatal("lost native failure", err)
			}
		})
	}
}

func TestManagedUpgradeUnknownStopDoesNotArmRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &upgradeTestService{state: svc.Running, onStop: cancel}
	running, err := stopManagedUpgrade(ctx, s)
	if running || !errors.Is(err, context.Canceled) || s.stops != 1 {
		t.Fatal(running, err, s.stops)
	}
	s = &upgradeTestService{state: svc.Running, queryErr: windows.ERROR_SERVICE_DOES_NOT_EXIST}
	if _, err := stopManagedUpgrade(context.Background(), s); !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) || s.stops != 0 {
		t.Fatal("removed service must remain untouched", err, s.stops)
	}
}

func TestManagedExecutablePreparationPreservesExistingFile(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.exe")
	data := []byte("test-only inert executable fixture")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	installed, digest, err := prepareManagedExecutable(root, source)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong recorded digest", digest)
	}
	if _, _, err := prepareManagedExecutable(root, source); err != nil {
		t.Fatal("identical staged file should be reusable", err)
	}
	if err := os.WriteFile(installed, []byte("unexpected existing content"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareManagedExecutable(root, source); err == nil || err.Error() != "INSTALL_HASH_MISMATCH" {
		t.Fatal("unverified replacement accepted", err)
	}
	got, err := os.ReadFile(installed)
	if err != nil || string(got) != "unexpected existing content" {
		t.Fatal("existing file overwritten", err)
	}
	_, _, err = prepareManagedExecutable(root, filepath.Join(root, "missing.exe"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read error discarded", err)
	}
}

func TestManagedProtectionDecisionsAreNotRollbackTriggers(t *testing.T) {
	for _, native := range []error{windows.ERROR_VIRUS_INFECTED, windows.ERROR_VIRUS_DELETED, windows.ERROR_ACCESS_DISABLED_BY_POLICY} {
		if !managedProtectionBlocked(&os.PathError{Op: "open", Path: "private", Err: native}) {
			t.Fatal("protection failure was not recognized", native)
		}
	}
	if managedProtectionBlocked(windows.ERROR_DISK_FULL) || managedProtectionBlocked(nil) {
		t.Fatal("ordinary failure misclassified")
	}
}
