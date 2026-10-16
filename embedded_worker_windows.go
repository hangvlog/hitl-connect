package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/sftp"
	"golang.org/x/sys/windows"
)

// WTS exposes only a real logged-on user's primary token. No passwords are
// saved and no SYSTEM, synthetic logon or unrelated process token is used.
func embeddedAccountToken(a hostAuthorization) (windows.Token, error) {
	_, sid, err := nativeLocalAccount(a.User)
	if err != nil || sid != a.SID {
		return 0, errors.New("AUTHORIZED_ACCOUNT_CHANGED_OR_DISABLED")
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err = windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, s := range unsafe.Slice(sessions, count) {
		var token windows.Token
		if windows.WTSQueryUserToken(s.SessionID, &token) != nil {
			continue
		}
		u, e := token.GetTokenUser()
		if e != nil || u.User.Sid.String() != a.SID {
			token.Close()
			continue
		}
		wantAdmin := a.Privilege == "administrator"
		if token.IsElevated() != wantAdmin {
			linked, e := token.GetLinkedToken()
			token.Close()
			if e != nil {
				return 0, errors.New("ACCOUNT_PRIVILEGE_UNAVAILABLE")
			}
			token = linked
		}
		u, e = token.GetTokenUser()
		if e != nil || u.User.Sid.String() != a.SID || token.IsElevated() != wantAdmin {
			token.Close()
			return 0, errors.New("ACCOUNT_PRIVILEGE_MISMATCH")
		}
		return token, nil
	}
	return 0, errors.New("AUTHORIZED_ACCOUNT_NOT_LOGGED_ON: sign in to the authorized Windows account")
}

type workerRequest struct{ SID, Privilege, Operation, Command string }

func runEmbeddedWorker(ctx context.Context, a hostAuthorization, operation, command string, ch workerIO) (int, error) {
	token, err := embeddedAccountToken(a)
	if err != nil {
		return 1, err
	}
	defer token.Close()
	home, err := token.GetUserProfileDirectory()
	if err != nil {
		return 1, errors.New("ACCOUNT_PROFILE_UNAVAILABLE")
	}
	env, err := token.Environ(false)
	if err != nil {
		return 1, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 1, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 1, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 1, err
	}
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	defer func() { close(finished); <-watcherDone }()
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = windows.TerminateJobObject(job, 1)
		case <-finished:
		}
	}()
	cmd := exec.CommandContext(ctx, exe, "ssh-account-worker")
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir, cmd.Env = home, env
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	hideGUIChild(cmd)
	input, err := cmd.StdinPipe()
	if err != nil {
		return 1, err
	}
	cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
	if err = cmd.Start(); err != nil {
		return 1, errors.New("ACCOUNT_WORKER_START_FAILED")
	}
	defer input.Close()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 1, errors.New("ACCOUNT_WORKER_CONTAINMENT_FAILED")
	}
	// Worker blocks on this record before starting commands/SFTP, so there is no
	// gap where a descendant can escape the job before assignment.
	if err = json.NewEncoder(input).Encode(workerRequest{a.SID, a.Privilege, operation, command}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 1, err
	}
	go func() { _, _ = io.Copy(input, ch); _ = input.Close() }()
	err = cmd.Wait()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, errors.New("ACCOUNT_WORKER_FAILED")
	}
	return 0, nil
}

type workerStream struct {
	io.Reader
	io.Writer
}

func (workerStream) Close() error { return nil }
func embeddedWorkerCommand(args []string) error {
	if len(args) != 0 {
		return errors.New("INVALID_ARGUMENT")
	}
	input := bufio.NewReader(os.Stdin)
	line, err := input.ReadString('\n')
	if err != nil || len(line) > 65536 {
		return errors.New("WORKER_REQUEST_INVALID")
	}
	var request workerRequest
	if json.Unmarshal([]byte(line), &request) != nil {
		return errors.New("WORKER_REQUEST_INVALID")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || !validWorkerIdentity(user.User.Sid.String(), request.SID, request.Privilege, token.IsElevated()) {
		return errors.New("WORKER_ACCOUNT_MISMATCH")
	}
	home, err := token.GetUserProfileDirectory()
	if err != nil {
		return err
	}
	if err = os.Chdir(home); err != nil {
		return err
	}
	switch request.Operation {
	case "sftp":
		server, err := sftp.NewServer(workerStream{input, os.Stdout}, sftp.WithServerWorkingDirectory(home), sftp.WindowsRootEnumeratesDrives())
		if err != nil {
			return err
		}
		defer server.Close()
		err = server.Serve()
		if err == io.EOF {
			return nil
		}
		return err
	case "exec", "shell":
		system, err := windows.GetSystemDirectory()
		if err != nil {
			return err
		}
		shell := filepath.Join(system, "cmd.exe")
		cmd := exec.Command(shell)
		if request.Operation == "exec" {
			cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: windows.EscapeArg(shell) + " /d /s /c \"" + request.Command + "\""}
		} else {
			cmd.Args = []string{shell, "/d", "/q"}
		}
		hideGUIChild(cmd)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = input, os.Stdout, os.Stderr
		if err = cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return &agentExit{exit.ExitCode()}
			}
			return fmt.Errorf("COMMAND_START_FAILED: %w", err)
		}
		return nil
	default:
		return errors.New("WORKER_OPERATION_DENIED")
	}
}
