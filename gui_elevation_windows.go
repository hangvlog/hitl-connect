package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func needsHostElevation() bool { return !windows.GetCurrentProcessToken().IsElevated() }

// ShellExecuteEx retains a real process handle. Stop terminates only this child,
// never a PID read from a mutable file. UAC occurs before any code is issued.
func startElevatedHost(ctx context.Context, cmd *exec.Cmd, base string) (io.ReadCloser, io.ReadCloser, func() error, error) {
	f, err := os.CreateTemp(base, ".host-output-*")
	if err != nil {
		return nil, nil, nil, err
	}
	name := f.Name()
	clean := func() { f.Close(); os.Remove(name) }
	args := cmd.Args[1:]
	if len(args) == 0 || args[0] != "install-host" {
		args = append(args, "--host-log", name)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		clean()
		return nil, nil, nil, err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		clean()
		return nil, nil, nil, err
	}
	type shellInfo struct {
		Size                              uint32
		Mask                              uint32
		Window                            uintptr
		Verb, File, Parameters, Directory *uint16
		Show                              int32
		Instance                          uintptr
		IDList                            uintptr
		Class                             *uint16
		ClassKey                          uintptr
		HotKey                            uint32
		Icon                              uintptr
		Process                           windows.Handle
	}
	info := shellInfo{Mask: 0x40 | 0x100 | 0x400, Verb: verb, File: file, Parameters: params, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	call := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	ok, _, callErr := call.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		clean()
		if callErr == windows.ERROR_CANCELLED {
			return nil, nil, nil, fmt.Errorf("UAC_CANCELLED: 未生成连接码；再次点击允许连接即可重试: %w", callErr)
		}
		return nil, nil, nil, fmt.Errorf("ELEVATION_FAILED: %w", callErr)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		defer clean()
		defer windows.CloseHandle(info.Process)
		defer writer.Close()
		var outcome error
		for {
			if ctx.Err() != nil {
				_ = windows.TerminateProcess(info.Process, 1)
			}
			status, e := windows.WaitForSingleObject(info.Process, 100)
			_, _ = io.Copy(writer, f)
			if e != nil {
				outcome = e
				break
			}
			if status == windows.WAIT_OBJECT_0 {
				var code uint32
				e = windows.GetExitCodeProcess(info.Process, &code)
				if e != nil {
					outcome = e
				} else if code != 0 {
					outcome = fmt.Errorf("elevated process exited with code %d", code)
				}
				break
			}
		}
		// Ensure Wait cannot complete until the final log bytes are drained.
		done <- outcome
	}()
	return reader, io.NopCloser(strings.NewReader("")), func() error {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			select {
			case err := <-done:
				return err
			case <-time.After(3 * time.Second):
				return ctx.Err()
			}
		}
	}, nil
}
