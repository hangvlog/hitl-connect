package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func hideGUIChild(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Retain account tokens and raw cmd.exe quoting when configuring SSH workers.
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
}
func detachAgentPanel(cmd *exec.Cmd) {
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: an agent shell exiting must
	// not send its console-control events to the long-running local panel.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200}
}
func openGUIBrowser(url string) error {
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	hideGUIChild(cmd)
	return startBrowser(cmd)
}

func showGUIError(message string) {
	title, _ := syscall.UTF16PtrFromString("HITL Connect")
	text, _ := syscall.UTF16PtrFromString("连接面板无法启动：\n" + message)
	proc := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	_, _, _ = proc.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
