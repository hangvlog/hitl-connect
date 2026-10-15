//go:build !windows

package main

import (
	"context"
	"errors"
	"golang.org/x/crypto/ssh"
)

func runEmbeddedWorker(context.Context, hostAuthorization, string, string, ssh.Channel) (int, error) {
	return 1, errors.New("WINDOWS_REQUIRED")
}
func embeddedWorkerCommand([]string) error { return errors.New("WINDOWS_REQUIRED") }
