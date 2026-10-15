package main

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

func TestSystemSSHRecoveryStopsAfterTwoRetries(t *testing.T) {
	actions := systemSSHRecoveryActions()
	if len(actions) == 0 {
		t.Fatal("missing recovery policy")
	}
	// Model SCM's repeat-last-action behavior across persistent failures.
	restarts := 0
	for failure := 0; failure < 100; failure++ {
		index := failure
		if index >= len(actions) {
			index = len(actions) - 1
		}
		action := actions[index]
		switch action.Type {
		case mgr.ServiceRestart:
			restarts++
			if action.Delay < 10*time.Second || failure >= 2 {
				t.Fatal("unbounded or rapid service restart", failure, action)
			}
		case mgr.NoAction:
		default:
			t.Fatal("recovery must never reboot Windows or run a command", action)
		}
	}
	if restarts != 2 {
		t.Fatal("expected only two service restart attempts", restarts)
	}
}
