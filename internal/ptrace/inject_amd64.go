//go:build linux && amd64

package ptrace

// syscallGadgetAddr returns the address of a `syscall` instruction in the
// tracee's address space. When stopped at a syscall-enter or PTRACE_EVENT_SECCOMP,
// the instruction pointer points right after the 2-byte `syscall` instruction.
func syscallGadgetAddr(regs Regs) uint64 {
	return regs.InstructionPointer() - 2
}

// syscallInsnSize is the size of the syscall instruction on this architecture.
const syscallInsnSize = 2
