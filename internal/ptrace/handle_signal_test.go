//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestExtractSignalArgs_Kill(t *testing.T) {
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_KILL, 42, 15, 0)
	if targetPID != 42 {
		t.Errorf("targetPID = %d, want 42", targetPID)
	}
	if signal != 15 {
		t.Errorf("signal = %d, want 15", signal)
	}
	if sigArgIndex != 1 {
		t.Errorf("sigArgIndex = %d, want 1", sigArgIndex)
	}
}

func TestExtractSignalArgs_Tkill(t *testing.T) {
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_TKILL, 100, 9, 0)
	if targetPID != 100 {
		t.Errorf("targetPID = %d, want 100", targetPID)
	}
	if signal != 9 {
		t.Errorf("signal = %d, want 9", signal)
	}
	if sigArgIndex != 1 {
		t.Errorf("sigArgIndex = %d, want 1", sigArgIndex)
	}
}

func TestExtractSignalArgs_Tgkill(t *testing.T) {
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_TGKILL, 50, 51, 15)
	if targetPID != 50 {
		t.Errorf("targetPID = %d, want 50 (tgid)", targetPID)
	}
	if signal != 15 {
		t.Errorf("signal = %d, want 15", signal)
	}
	if sigArgIndex != 2 {
		t.Errorf("sigArgIndex = %d, want 2", sigArgIndex)
	}
}

func TestExtractSignalArgs_RtSigqueueinfo(t *testing.T) {
	// rt_sigqueueinfo(pid, sig, info): arg0=pid, arg1=sig
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_RT_SIGQUEUEINFO, 42, 10, 0)
	if targetPID != 42 {
		t.Errorf("targetPID = %d, want 42", targetPID)
	}
	if signal != 10 {
		t.Errorf("signal = %d, want 10", signal)
	}
	if sigArgIndex != 1 {
		t.Errorf("sigArgIndex = %d, want 1", sigArgIndex)
	}
}

func TestExtractSignalArgs_RtTgsigqueueinfo(t *testing.T) {
	// rt_tgsigqueueinfo(tgid, tid, sig, info): arg0=tgid, arg2=sig
	targetPID, signal, sigArgIndex := extractSignalArgs(unix.SYS_RT_TGSIGQUEUEINFO, 50, 51, 10)
	if targetPID != 50 {
		t.Errorf("targetPID = %d, want 50 (tgid)", targetPID)
	}
	if signal != 10 {
		t.Errorf("signal = %d, want 10", signal)
	}
	if sigArgIndex != 2 {
		t.Errorf("sigArgIndex = %d, want 2", sigArgIndex)
	}
}
