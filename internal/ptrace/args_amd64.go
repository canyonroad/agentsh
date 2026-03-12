//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

type amd64Regs struct {
	raw unix.PtraceRegsAmd64
}

func (r *amd64Regs) SyscallNr() int             { return int(int64(r.raw.Orig_rax)) }
func (r *amd64Regs) SetSyscallNr(nr int)         { r.raw.Orig_rax = uint64(nr) }
func (r *amd64Regs) ReturnValue() int64          { return int64(r.raw.Rax) }
func (r *amd64Regs) SetReturnValue(v int64)      { r.raw.Rax = uint64(v) }
func (r *amd64Regs) InstructionPointer() uint64    { return r.raw.Rip }
func (r *amd64Regs) SetInstructionPointer(addr uint64) { r.raw.Rip = addr }

func (r *amd64Regs) Clone() Regs {
	dup := *r
	return &dup
}

func (r *amd64Regs) Arg(n int) uint64 {
	switch n {
	case 0:
		return r.raw.Rdi
	case 1:
		return r.raw.Rsi
	case 2:
		return r.raw.Rdx
	case 3:
		return r.raw.R10
	case 4:
		return r.raw.R8
	case 5:
		return r.raw.R9
	default:
		return 0
	}
}

func (r *amd64Regs) SetArg(n int, val uint64) {
	switch n {
	case 0:
		r.raw.Rdi = val
	case 1:
		r.raw.Rsi = val
	case 2:
		r.raw.Rdx = val
	case 3:
		r.raw.R10 = val
	case 4:
		r.raw.R8 = val
	case 5:
		r.raw.R9 = val
	}
}

func getRegsArch(tid int) (Regs, error) {
	r := &amd64Regs{}
	err := unix.PtraceGetRegsAmd64(tid, &r.raw)
	return r, err
}

func setRegsArch(tid int, regs Regs) error {
	r := regs.(*amd64Regs)
	return unix.PtraceSetRegsAmd64(tid, &r.raw)
}
