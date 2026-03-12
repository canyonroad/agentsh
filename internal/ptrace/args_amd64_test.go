//go:build linux && amd64

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAmd64Regs_SyscallNr(t *testing.T) {
	r := &amd64Regs{}
	r.raw.Orig_rax = 59 // SYS_EXECVE
	if r.SyscallNr() != 59 {
		t.Errorf("SyscallNr() = %d, want 59", r.SyscallNr())
	}
	r.SetSyscallNr(-1)
	if r.SyscallNr() != -1 {
		t.Errorf("SetSyscallNr(-1): got %d", r.SyscallNr())
	}
}

func TestAmd64Regs_Args(t *testing.T) {
	r := &amd64Regs{}
	r.SetArg(0, 100)
	if r.raw.Rdi != 100 {
		t.Errorf("Arg(0) maps to Rdi: got %d", r.raw.Rdi)
	}
	r.SetArg(1, 200)
	if r.raw.Rsi != 200 {
		t.Errorf("Arg(1) maps to Rsi: got %d", r.raw.Rsi)
	}
	r.SetArg(2, 300)
	if r.raw.Rdx != 300 {
		t.Errorf("Arg(2) maps to Rdx: got %d", r.raw.Rdx)
	}
	r.SetArg(3, 400)
	if r.raw.R10 != 400 {
		t.Errorf("Arg(3) maps to R10: got %d", r.raw.R10)
	}
	r.SetArg(4, 500)
	if r.raw.R8 != 500 {
		t.Errorf("Arg(4) maps to R8: got %d", r.raw.R8)
	}
	r.SetArg(5, 600)
	if r.raw.R9 != 600 {
		t.Errorf("Arg(5) maps to R9: got %d", r.raw.R9)
	}

	for i := 0; i < 6; i++ {
		expected := uint64((i + 1) * 100)
		if r.Arg(i) != expected {
			t.Errorf("Arg(%d) = %d, want %d", i, r.Arg(i), expected)
		}
	}

	if r.Arg(6) != 0 {
		t.Error("Arg(6) should return 0")
	}
	if r.Arg(-1) != 0 {
		t.Error("Arg(-1) should return 0")
	}
}

func TestAmd64Regs_ReturnValue(t *testing.T) {
	r := &amd64Regs{}
	r.SetReturnValue(-int64(unix.EACCES))
	if r.ReturnValue() != -int64(unix.EACCES) {
		t.Errorf("ReturnValue() = %d, want %d", r.ReturnValue(), -int64(unix.EACCES))
	}
}
