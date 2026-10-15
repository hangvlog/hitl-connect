//go:build !windows

package main

import (
	"context"
	"errors"
)

func (g *guiSession) installManagedHost(guiRequest) (bool, error) { return false, nil }
func runManagedCommand(context.Context, []string) error           { return errors.New("WINDOWS_REQUIRED") }

func queryManagedService(source, managed string) managedServiceStatus {
	return managedServiceStatus{Code: "HOST_SERVICE_UNAVAILABLE", State: "UNKNOWN", Stage: "query-service"}
}
