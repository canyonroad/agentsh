//go:build linux

package ptrace

// Regs abstracts architecture-specific register access for ptrace.
type Regs interface {
	SyscallNr() int
	SetSyscallNr(nr int)
	Arg(n int) uint64
	SetArg(n int, val uint64)
	ReturnValue() int64
	SetReturnValue(val int64)
	InstructionPointer() uint64
	SetInstructionPointer(addr uint64)
	Clone() Regs
}
