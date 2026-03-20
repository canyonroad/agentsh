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

func TestIsVforkFastPathSkipsNonExec(t *testing.T) {
	// Verify the fast-path condition: IsVforkChild && !isExecveSyscall && isVforkSafeSyscall
	tests := []struct {
		name     string
		isVfork  bool
		nr       int
		wantFast bool
	}{
		{"vfork child close", true, unix.SYS_CLOSE, true},
		{"vfork child dup2", true, unix.SYS_DUP2, true},
		{"vfork child dup3", true, unix.SYS_DUP3, true},
		{"vfork child sigaction", true, unix.SYS_RT_SIGACTION, true},
		{"vfork child exit_group", true, unix.SYS_EXIT_GROUP, true},
		{"vfork child openat", true, unix.SYS_OPENAT, false},     // not in safe list
		{"vfork child connect", true, unix.SYS_CONNECT, false},   // not in safe list
		{"vfork child execve", true, unix.SYS_EXECVE, false},     // exec gets full eval
		{"vfork child execveat", true, unix.SYS_EXECVEAT, false}, // exec gets full eval
		{"non-vfork close", false, unix.SYS_CLOSE, false},
		{"non-vfork openat", false, unix.SYS_OPENAT, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.isVfork && !isExecveSyscall(tt.nr) && isVforkSafeSyscall(tt.nr)
			if got != tt.wantFast {
				t.Errorf("fastPath(%v, %d) = %v, want %v",
					tt.isVfork, tt.nr, got, tt.wantFast)
			}
		})
	}
}

func TestNeedsExitStop(t *testing.T) {
	tests := []struct {
		name          string
		nr            int
		maskTracerPid bool
		traceNetwork  bool
		want          bool
	}{
		{"openat with mask on", unix.SYS_OPENAT, true, true, true},
		{"openat with mask off", unix.SYS_OPENAT, false, true, true},
		{"openat2 with mask off", unix.SYS_OPENAT2, false, true, true},
		{"connect with network on", unix.SYS_CONNECT, false, true, true},
		{"connect with network off", unix.SYS_CONNECT, false, false, false},
		{"read always true", unix.SYS_READ, false, false, true},
		{"pread64 always true", unix.SYS_PREAD64, false, false, true},
		{"execve always true", unix.SYS_EXECVE, false, false, true},
		{"execveat always true", unix.SYS_EXECVEAT, false, false, true},
		{"unlinkat never needs exit", unix.SYS_UNLINKAT, true, true, false},
		{"write never needs exit", unix.SYS_WRITE, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Tracer{cfg: TracerConfig{
				MaskTracerPid: tt.maskTracerPid,
				TraceNetwork:  tt.traceNetwork,
			}}
			if got := tr.needsExitStop(tt.nr); got != tt.want {
				t.Errorf("needsExitStop(%d) = %v, want %v", tt.nr, got, tt.want)
			}
		})
	}
}
