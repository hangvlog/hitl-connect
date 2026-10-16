package main

import (
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func managedServiceConfig() mgr.Config {
	return mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		DisplayName:      "HITL Connect",
		Description:      "HITL Connect embedded SSH; explicitly authorized account sessions and local audit.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: "LocalSystem",
	}
}

func managedRecoveryActions() []mgr.RecoveryAction {
	// SCM repeats its final action indefinitely. A persistent crash must stop
	// after two attempts; it must never reboot Windows or run another program.
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}
}
