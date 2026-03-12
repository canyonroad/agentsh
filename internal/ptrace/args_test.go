//go:build linux

package ptrace

import "testing"

func TestRegsClone(t *testing.T) {
	r := createTestRegs()
	r.SetSyscallNr(42)
	r.SetArg(0, 0xDEAD)
	r.SetReturnValue(99)

	cloned := r.Clone()
	if cloned.SyscallNr() != 42 {
		t.Errorf("Clone SyscallNr: got %d, want 42", cloned.SyscallNr())
	}
	if cloned.Arg(0) != 0xDEAD {
		t.Errorf("Clone Arg(0): got %d, want 0xDEAD", cloned.Arg(0))
	}

	// Mutating clone must not affect original
	cloned.SetSyscallNr(99)
	if r.SyscallNr() != 42 {
		t.Errorf("Clone mutation leaked: original SyscallNr changed to %d", r.SyscallNr())
	}
}

func TestRegsSetInstructionPointer(t *testing.T) {
	r := createTestRegs()
	r.SetInstructionPointer(0xCAFE)
	if r.InstructionPointer() != 0xCAFE {
		t.Errorf("SetInstructionPointer: got 0x%X, want 0xCAFE", r.InstructionPointer())
	}
}
