//go:build !windows

package main

import (
	"context"
	"errors"
)

func runSystemSSHHost(context.Context, []string) error { return errors.New("WINDOWS_REQUIRED") }
func runSystemSSHServiceCommand(context.Context, []string) error {
	return errors.New("WINDOWS_REQUIRED")
}
func installSystemSSHKey(string, sshAccess, string) agentResult {
	return agentResult{Code: "WINDOWS_REQUIRED"}
}
func syncSystemSSHKeys(string) error { return nil }
func installSystemSSHKeyLocked(string, sshAccess, string) agentResult {
	return agentResult{Code: "WINDOWS_REQUIRED"}
}
