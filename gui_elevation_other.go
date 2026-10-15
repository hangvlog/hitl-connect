//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

func needsHostElevation() bool { return false }
func startElevatedHost(context.Context, *exec.Cmd, string) (io.ReadCloser, io.ReadCloser, func() error, error) {
	return nil, nil, nil, errors.New("WINDOWS_REQUIRED")
}
