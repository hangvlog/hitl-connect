package main

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func tryProfileLock(base, name string) (func(), bool, error) {
	f, e := os.OpenFile(filepath.Join(base, name), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, false, e
	}
	o := &windows.Overlapped{}
	e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, o)
	if e != nil {
		f.Close()
		if e == windows.ERROR_LOCK_VIOLATION {
			return nil, false, nil
		}
		return nil, false, e
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); _ = f.Close() }, true, nil
}
