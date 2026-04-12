//go:build unix

package cli

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openAndLockAuditFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("agentsh server is running; stop it before resetting the chain")
	}
	return file, nil
}

func closeAndUnlockAuditFile(file *os.File) error {
	defer file.Close()
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
