package main

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Windows filesystem filters can keep a just-deleted entry pending after all
// application handles close. Retry only that native cleanup error, not test
// assertions or access-denied failures. Never target a caller-supplied path.
func grantTestDirectory(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("", "hitl-grant-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			err = os.RemoveAll(dir)
			if err == nil {
				return
			}
			if !errors.Is(err, syscall.Errno(145)) { // ERROR_DIR_NOT_EMPTY
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Errorf("grant fixture cleanup: %v", err)
	})
	return dir
}
