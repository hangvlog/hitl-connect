//go:build !windows

package main

import (
	"context"
	"errors"
)

func runEmbeddedWorker(context.Context, hostAuthorization, string, string, workerIO) (int, error) {
	return 1, errors.New("WINDOWS_REQUIRED")
}
func embeddedWorkerCommand([]string) error { return errors.New("WINDOWS_REQUIRED") }
