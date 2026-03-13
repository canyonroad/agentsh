//go:build linux && arm64

package ptrace

import "golang.org/x/sys/unix"

type arm64Regs struct {
	raw unix.PtraceRegsArm64
}

func (r *arm64Regs) SyscallNr() int             { return int(int64(r.raw.Regs[8])) }
func (r *arm64Regs) SetSyscallNr(nr int)         { r.raw.Regs[8] = uint64(nr) }
func (r *arm64Regs) ReturnValue() int64          { return int64(r.raw.Regs[0]) }
func (r *arm64Regs) SetReturnValue(v int64)      { r.raw.Regs[0] = uint64(v) }
func (r *arm64Regs) InstructionPointer() uint64    { return r.raw.Pc }
func (r *arm64Regs) SetInstructionPointer(addr uint64) { r.raw.Pc = addr }

func (r *arm64Regs) Clone() Regs {
	dup := *r
	return &dup
}

func (r *arm64Regs) Arg(n int) uint64 {
	if n < 0 || n > 5 {
		return 0
	}
	return r.raw.Regs[n]
}

func (r *arm64Regs) SetArg(n int, val uint64) {
	if n >= 0 && n <= 5 {
		r.raw.Regs[n] = val
	}
}

func getRegsArch(tid int) (Regs, error) {
	r := &arm64Regs{}
	err := unix.PtraceGetRegsArm64(tid, &r.raw)
	return r, err
}

func setRegsArch(tid int, regs Regs) error {
	r := regs.(*arm64Regs)
	return unix.PtraceSetRegsArm64(tid, &r.raw)
}
