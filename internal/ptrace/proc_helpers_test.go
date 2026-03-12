//go:build linux

package ptrace

import (
	"os"
	"testing"
)

func TestReadTGID(t *testing.T) {
	tgid, err := readTGID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if tgid != os.Getpid() {
		t.Errorf("readTGID(self) = %d, want %d", tgid, os.Getpid())
	}
}

func TestReadPPID(t *testing.T) {
	ppid, err := readPPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if ppid != os.Getppid() {
		t.Errorf("readPPID(self) = %d, want %d", ppid, os.Getppid())
	}
}
