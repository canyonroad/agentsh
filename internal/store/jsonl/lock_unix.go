//go:build unix

package jsonl

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func AcquireLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir lock dir: %w", err)
	}

	file, err := os.OpenFile(lockPath(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrLocked, err)
	}
	return file, nil
}

func ReleaseLock(file *os.File) error {
	if file == nil {
		return nil
	}
	defer file.Close()
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
