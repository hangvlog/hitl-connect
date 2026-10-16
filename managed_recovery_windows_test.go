package main

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestManagedRecoveryPersistentFailureStops(t *testing.T) {
	actions := managedRecoveryActions()
	if len(actions) == 0 {
		t.Fatal("missing recovery policy")
	}
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
			if failure >= 2 || action.Delay < 10*time.Second {
				t.Fatal("unbounded or rapid restart", failure, action)
			}
		case mgr.NoAction:
		default:
			t.Fatal("recovery must not reboot Windows or run a command", action)
		}
	}
	if restarts != 2 {
		t.Fatal("expected only two restart attempts", restarts)
	}
}

func TestManagedServiceStartupIsNonCriticalAndDelayed(t *testing.T) {
	c := managedServiceConfig()
	if c.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || c.StartType != mgr.StartAutomatic || !c.DelayedAutoStart {
		t.Fatal("expected delayed automatic user-mode service", c)
	}
	if c.ErrorControl != mgr.ErrorNormal {
		t.Fatal("service failure must not be a severe or critical boot error", c.ErrorControl)
	}
	if len(c.Dependencies) != 0 || c.LoadOrderGroup != "" {
		t.Fatal("provider must not participate in boot-critical dependencies", c)
	}
}
