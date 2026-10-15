//go:build !windows

package main

import "context"

func nativeWindowsSetup(_ context.Context, _ sshSetupInput) sshSetupReport {
	r := newSSHSetupReport()
	_ = r.fail("WINDOWS_REQUIRED", "Run setup on the Windows provider")
	return r
}
