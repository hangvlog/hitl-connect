package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

func (g *guiSession) installManagedHost(r guiRequest) (bool, error) {
	if servicePolicy != nil {
		return false, nil
	}
	// Retain the result beside the existing profile as a local, non-authoritative
	// diagnostic too. This is written by the parent, never by the elevated child.
	record := func(report installerReport) {
		_ = privateJSON(filepath.Join(g.base, "install-result.json"), report)
		g.mu.Lock()
		g.state.Installation = &report
		g.mu.Unlock()
	}
	sid, e := currentOwnerSID()
	if e != nil {
		report := installReport("caller-identity", e)
		record(report)
		return true, &installerError{report}
	}
	root, _, e := managedLocation(g.base, sid)
	if e != nil {
		report := installReport("locate-installation", e)
		record(report)
		return true, &installerError{report}
	}
	receiver, e := newInstallResultReceiver()
	if e != nil {
		report := installReport("result-channel", e)
		record(report)
		return true, &installerError{report}
	}
	defer receiver.Close()
	g.step("local", "working", "正在安装后台服务；请接受一次 Windows 系统授权")
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.exe, "install-host", "--dir", g.base, "--allow-user", r.User, "--target", r.Target, "--owner-sid", sid, "--install-report-url", receiver.URL, "--install-report-token", receiver.Token)
	if r.Privilege != "" {
		cmd.Args = append(cmd.Args, "--privilege", r.Privilege)
	}
	out, errout, wait, e := startGUICommand(ctx, cmd, true, g.base)
	if e != nil {
		report := installReport("elevation", e)
		record(report)
		return true, &installerError{report}
	}
	var drains sync.WaitGroup
	drains.Add(2)
	for _, stream := range []io.ReadCloser{out, errout} {
		go func(stream io.ReadCloser) {
			defer drains.Done()
			defer stream.Close()
			_, _ = io.Copy(io.Discard, stream)
		}(stream)
	}
	drains.Wait()
	e = wait()
	if ctx.Err() != nil {
		e = fmt.Errorf("HOST_INSTALL_TIMEOUT: %w", ctx.Err())
	}
	result := receiver.Result()
	if e = installerOutcome(result, e); e != nil {
		var failure *installerError
		if errors.As(e, &failure) {
			record(failure.Report)
		}
		return true, e
	}
	if e = managedReady(ctx, root); e != nil {
		report := installReport("verify-service", e)
		record(report)
		return true, &installerError{report}
	}
	if e = privateJSON(filepath.Join(g.base, "managed-host.json"), managedLocator{root}); e != nil {
		report := installReport("save-locator", e)
		record(report)
		return true, &installerError{report}
	}
	record(*result)
	return true, nil
}
