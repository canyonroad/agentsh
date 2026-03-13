//go:build linux && arm64

package ptrace

// syscallGadgetAddr returns the address of an `svc #0` instruction in the
// tracee's address space. When stopped at a syscall-enter, the instruction
// pointer points right after the 4-byte `svc #0` instruction.
func syscallGadgetAddr(regs Regs) uint64 {
	return regs.InstructionPointer() - 4
}

// syscallInsnSize is the size of the syscall instruction on this architecture.
const syscallInsnSize = 4
