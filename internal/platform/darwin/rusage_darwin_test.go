//go:build darwin && cgo

package darwin

import (
	"os"
	"testing"
)

func TestGetProcRusage(t *testing.T) {
	pid := os.Getpid()
	rusage, err := getProcRusage(pid)
	if err != nil {
		t.Fatalf("getProcRusage(%d) failed: %v", pid, err)
	}
	if rusage.UserTime == 0 && rusage.SystemTime == 0 {
		t.Error("expected non-zero CPU time for current process")
	}
	if rusage.ResidentSize == 0 {
		t.Error("expected non-zero resident memory")
	}
}

func TestGetProcRusageInvalidPID(t *testing.T) {
	_, err := getProcRusage(-1)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}
