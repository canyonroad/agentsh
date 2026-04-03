//go:build darwin

package policysock

import (
	"testing"
)

func TestCommandResolver_RegisterAndLookup(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")

	got := cr.CommandForPID(100)
	if got != "cmd-abc" {
		t.Errorf("CommandForPID(100) = %q, want %q", got, "cmd-abc")
	}
}

func TestCommandResolver_UnknownPID(t *testing.T) {
	cr := NewCommandResolver()

	got := cr.CommandForPID(999)
	if got != "" {
		t.Errorf("CommandForPID(999) = %q, want empty", got)
	}
}

func TestCommandResolver_RegisterFork(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")
	cr.RegisterFork(100, 101)

	got := cr.CommandForPID(101)
	if got != "cmd-abc" {
		t.Errorf("CommandForPID(101) = %q, want %q", got, "cmd-abc")
	}
}

func TestCommandResolver_ForkUnknownParent(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterFork(999, 1000)

	got := cr.CommandForPID(1000)
	if got != "" {
		t.Errorf("CommandForPID(1000) = %q, want empty", got)
	}
}

func TestCommandResolver_Unregister(t *testing.T) {
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-abc")
	cr.UnregisterPID(100)

	got := cr.CommandForPID(100)
	if got != "" {
		t.Errorf("CommandForPID(100) after unregister = %q, want empty", got)
	}
}
