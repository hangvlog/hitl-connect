package desktopupgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var inventory = []string{"HITL-Connect.exe", "hitl-connect-cli.exe", "Uninstall.exe", "AGENTS.md", "README.md", "SECURITY-REVIEW.md", "Verify-Package.ps1", "manifest.json"}

type process struct {
	handle windows.Handle
	pid    uint32
	args   []string
}

func commandLine(h windows.Handle) ([]string, error) {
	// Query Windows process command-line information without reading
	// arbitrary process memory. The returned string must stay within this buffer.
	buf := make([]byte, 131072)
	var size uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &size); err != nil {
		return nil, err
	}
	if size < uint32(unsafe.Sizeof(windows.NTUnicodeString{})) || size > uint32(len(buf)) {
		return nil, errors.New("invalid process command line size")
	}
	s := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	base, ptr := uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(s.Buffer))
	if s.Length == 0 || s.Length%2 != 0 || ptr < base || ptr-base > uintptr(size) || uintptr(s.Length) > uintptr(size)-(ptr-base) {
		return nil, errors.New("invalid process command line")
	}
	args, err := windows.DecomposeCommandLine(s.String())
	runtime.KeepAlive(buf)
	return args, err
}

func imagePath(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
	if err != nil {
		return "", err
	}
	return filepath.Clean(windows.UTF16ToString(buf[:n])), nil
}

func inspect(dir string, closePanels bool) ([]process, error) {
	var found []process
	fail := func(err error) ([]process, error) {
		for _, p := range found {
			windows.CloseHandle(p.handle)
		}
		return nil, err
	}
	owner, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	var ownSession uint32
	if err = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &ownSession); err != nil {
		return nil, err
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if !strings.EqualFold(name, "HITL-Connect.exe") && !strings.EqualFold(name, "hitl-connect-cli.exe") {
			continue
		}
		access := uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE)
		if closePanels {
			access |= windows.PROCESS_TERMINATE
		}
		h, e := windows.OpenProcess(access, false, entry.ProcessID)
		if e != nil {
			// The later write probe still blocks any inaccessible file holder.
			continue
		}
		image, e := imagePath(h)
		target := filepath.Join(dir, name)
		if e != nil || !strings.EqualFold(image, target) {
			windows.CloseHandle(h)
			continue
		}
		var token windows.Token
		e = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
		var sid string
		if e == nil {
			u, te := token.GetTokenUser()
			if te == nil {
				sid = u.User.Sid.String()
			} else {
				e = te
			}
			token.Close()
		}
		var session uint32
		if e == nil {
			e = windows.ProcessIdToSessionId(entry.ProcessID, &session)
		}
		args, ce := commandLine(h)
		// CLI invocations are never closed, even if they happen to have no args.
		if e != nil || ce != nil || !strings.EqualFold(name, "HITL-Connect.exe") || !eligiblePanel(image, target, sid, owner.User.Sid.String(), session, ownSession, args) {
			windows.CloseHandle(h)
			return fail(fmt.Errorf("PID %d is not an eligible desktop panel. Finish that operation and retry; no service or other session was stopped", entry.ProcessID))
		}
		found = append(found, process{h, entry.ProcessID, args})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fail(err)
	}
	return found, nil
}

// Prepare returns 10 when panels need explicit consent, 20 for a blocker.
// Handles remain open from identification to termination, preventing PID reuse.
func Prepare(dir string, closePanels bool) (int, error) {
	if !filepath.IsAbs(dir) {
		return 20, errors.New("Install directory must be absolute")
	}
	dir = filepath.Clean(dir)
	// Refuse redirected installation paths; do not broaden process matching.
	for p := dir; ; p = filepath.Dir(p) {
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return 20, err
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return 20, err
		}
		if err == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return 20, errors.New("Install path is redirected; select a regular local directory")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	panels, err := inspect(dir, closePanels)
	if err != nil {
		return 20, err
	}
	defer func() {
		for _, p := range panels {
			windows.CloseHandle(p.handle)
		}
	}()
	if len(panels) > 0 && !closePanels {
		return 10, nil
	}
	for _, p := range panels {
		if err = drainPanel(p.args); err != nil {
			return 20, err
		}
	}
	for _, p := range panels {
		// No taskkill tree, no panel /quit API (which forwards to the service).
		if err = windows.TerminateProcess(p.handle, 0); err != nil {
			if state, _ := windows.WaitForSingleObject(p.handle, 0); state != windows.WAIT_OBJECT_0 {
				return 20, fmt.Errorf("Cannot close desktop panel PID %d: %w", p.pid, err)
			}
		}
		if state, e := windows.WaitForSingleObject(p.handle, 5000); e != nil || state != windows.WAIT_OBJECT_0 {
			return 20, errors.New("Desktop panel has not exited; retry later")
		}
	}
	if err = os.MkdirAll(dir, 0755); err != nil {
		return 20, fmt.Errorf("Cannot create install directory: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".hitl-install-check-")
	if err != nil {
		return 20, fmt.Errorf("Cannot write install directory: %w", err)
	}
	probe.Close()
	os.Remove(probe.Name())
	deadline := time.Now().Add(3 * time.Second)
	for {
		err = writableInventory(dir)
		if err == nil {
			return 0, nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Now().After(deadline) {
			return 20, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func writableInventory(dir string) error {
	for _, name := range inventory {
		path := filepath.Join(dir, name)
		u, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(u)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			return fmt.Errorf("Cannot inspect %s: %w", name, err)
		}
		if attrs&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			return fmt.Errorf("%s is not a regular file", name)
		}
		h, err := windows.CreateFile(u, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return fmt.Errorf("Cannot update %s; check file locks, permissions or endpoint reports: %w", name, err)
		}
		windows.CloseHandle(h)
	}
	return nil
}
