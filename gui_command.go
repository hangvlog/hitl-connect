package main

import (
	"context"
	"io"
	"os/exec"
)

func startGUICommand(ctx context.Context, cmd *exec.Cmd, allow bool, base string) (io.ReadCloser, io.ReadCloser, func() error, error) {
	if allow && needsHostElevation() {
		return startElevatedHost(ctx, cmd, base)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	errout, err := cmd.StderrPipe()
	if err != nil {
		out.Close()
		return nil, nil, nil, err
	}
	if err = cmd.Start(); err != nil {
		out.Close()
		errout.Close()
		return nil, nil, nil, err
	}
	return out, errout, cmd.Wait, nil
}

func startBrowser(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
