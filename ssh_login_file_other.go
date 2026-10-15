//go:build !windows

package main

import "os"

func createSSHLoginFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func protectSSHLoginFile(path string) error { return os.Chmod(path, 0600) }
