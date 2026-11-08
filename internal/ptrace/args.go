//go:build linux

package ptrace

// Regs abstracts architecture-specific register access for ptrace.
type Regs interface {
	SyscallNr() int
	SetSyscallNr(nr int)
	Arg(n int) uint64
	SetArg(n int, val uint64)
	// CodeSegment returns the code segment selector, used to tell a compat
	// (32-bit) syscall from a native one when the audit arch is unavailable.
	// 0 when the architecture has no such selector.
	CodeSegment() uint64

	ReturnValue() int64
	SetReturnValue(val int64)
	InstructionPointer() uint64
	SetInstructionPointer(addr uint64)
	Clone() Regs
}
