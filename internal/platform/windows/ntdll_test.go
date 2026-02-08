package windows

import (
	"runtime"
	"testing"
)

func TestResumeProcessByPIDSignature(t *testing.T) {
	// Verify function exists with correct signature
	var fn func(uint32) error = ResumeProcessByPID
	if fn == nil {
		t.Fatal("ResumeProcessByPID should not be nil")
	}
	if runtime.GOOS != "windows" {
		err := ResumeProcessByPID(0)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestSuspendProcessByPIDSignature(t *testing.T) {
	var fn func(uint32) error = SuspendProcessByPID
	if fn == nil {
		t.Fatal("SuspendProcessByPID should not be nil")
	}
	if runtime.GOOS != "windows" {
		err := SuspendProcessByPID(0)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestTerminateProcessByPIDSignature(t *testing.T) {
	var fn func(uint32, uint32) error = TerminateProcessByPID
	if fn == nil {
		t.Fatal("TerminateProcessByPID should not be nil")
	}
	if runtime.GOOS != "windows" {
		err := TerminateProcessByPID(0, 1)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestCreateProcessAsChildSignature(t *testing.T) {
	var fn func(uint32, string, string, []string, string, bool, []uintptr) (uint32, error) = CreateProcessAsChild
	if fn == nil {
		t.Fatal("CreateProcessAsChild should not be nil")
	}
	if runtime.GOOS != "windows" {
		_, err := CreateProcessAsChild(0, "", "test.exe", nil, "", false, nil)
		if err == nil {
			t.Error("expected error on non-Windows")
		}
	}
}

func TestProcThreadAttributeParentProcess(t *testing.T) {
	if PROC_THREAD_ATTRIBUTE_PARENT_PROCESS != 0x00020000 {
		t.Errorf("PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: expected 0x00020000, got 0x%X", PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
	}
}
