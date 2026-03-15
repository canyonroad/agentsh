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

func TestPtraceOptions_AlwaysSetsBoth(t *testing.T) {
	tr := &Tracer{}
	opts := tr.ptraceOptions()
	if opts&unix.PTRACE_O_EXITKILL == 0 {
		t.Error("PTRACE_O_EXITKILL must always be set")
	}
	if opts&unix.PTRACE_O_TRACESECCOMP == 0 {
		t.Error("PTRACE_O_TRACESECCOMP must always be set")
	}
	if opts&unix.PTRACE_O_TRACESYSGOOD == 0 {
		t.Error("PTRACE_O_TRACESYSGOOD must always be set")
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
