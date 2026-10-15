//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

func tryProfileLock(base, name string) (func(), bool, error) {
	f, e := os.OpenFile(filepath.Join(base, name), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, false, e
	}
	e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if e != nil {
		f.Close()
		if e == syscall.EWOULDBLOCK {
			return nil, false, nil
		}
		return nil, false, e
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, true, nil
}
