//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewTracer(t *testing.T) {
	cfg := TracerConfig{}
	tr := NewTracer(cfg)
	if tr == nil {
		t.Fatal("NewTracer returned nil")
	}
	if tr.TraceeCount() != 0 {
		t.Error("new tracer should have 0 tracees")
	}
}

func TestPtraceOptions_WithPrefilter(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{SeccompPrefilter: true}}
	opts := tr.ptraceOptions()
	if opts&unix.PTRACE_O_EXITKILL == 0 {
		t.Error("PTRACE_O_EXITKILL must be set")
	}
	if opts&unix.PTRACE_O_TRACESECCOMP == 0 {
		t.Error("PTRACE_O_TRACESECCOMP must be set when prefilter enabled")
	}
	if opts&unix.PTRACE_O_TRACESYSGOOD == 0 {
		t.Error("PTRACE_O_TRACESYSGOOD must be set")
	}
}

func TestPtraceOptions_WithoutPrefilter(t *testing.T) {
	tr := &Tracer{cfg: TracerConfig{SeccompPrefilter: false}}
	opts := tr.ptraceOptions()
	if opts&unix.PTRACE_O_TRACESECCOMP != 0 {
		t.Error("PTRACE_O_TRACESECCOMP must not be set when prefilter disabled")
	}
	if opts&unix.PTRACE_O_TRACESYSGOOD == 0 {
		t.Error("PTRACE_O_TRACESYSGOOD must be set")
	}
}

func TestTracerConfig_HandlerFields(t *testing.T) {
	cfg := TracerConfig{
		TraceFile:    true,
		TraceNetwork: true,
		TraceSignal:  true,
	}
	tr := NewTracer(cfg)
	if tr.cfg.FileHandler != nil {
		t.Error("FileHandler should be nil by default")
	}
	if tr.cfg.NetworkHandler != nil {
		t.Error("NetworkHandler should be nil by default")
	}
	if tr.cfg.SignalHandler != nil {
		t.Error("SignalHandler should be nil by default")
	}
}

func TestNeedsExitStop(t *testing.T) {
	exitNeeded := []int{
		unix.SYS_READ, unix.SYS_PREAD64,
		unix.SYS_OPENAT, unix.SYS_OPENAT2,
		unix.SYS_CONNECT,
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
	}
	for _, nr := range exitNeeded {
		if !needsExitStop(nr) {
			t.Errorf("needsExitStop(%d) = false, want true", nr)
		}
	}

	entryOnly := []int{
		unix.SYS_WRITE, unix.SYS_CLOSE, unix.SYS_KILL,
		unix.SYS_BIND, unix.SYS_SOCKET, unix.SYS_SENDTO,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
	}
	for _, nr := range entryOnly {
		if needsExitStop(nr) {
			t.Errorf("needsExitStop(%d) = true, want false", nr)
		}
	}
}
