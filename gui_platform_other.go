//go:build !windows

package main

import (
	"os/exec"
	"runtime"
	"syscall"
)

func hideGUIChild(cmd *exec.Cmd)  {}
func showGUIError(message string) {}
func detachAgentPanel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
func openGUIBrowser(url string) error {
	program := "xdg-open"
	if runtime.GOOS == "darwin" {
		program = "open"
	}
	cmd := exec.Command(program, url)
	return startBrowser(cmd)
}
