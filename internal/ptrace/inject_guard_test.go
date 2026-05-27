//go:build linux

package ptrace

import (
	"runtime"
	"testing"
)

func TestIsSyscallInsn(t *testing.T) {
	if runtime.GOARCH == "amd64" {
		if !isSyscallInsn([]byte{0x0f, 0x05}) {
			t.Fatal("0f05 should be a syscall insn")
		}
		if isSyscallInsn([]byte{0x48, 0x89}) {
			t.Fatal("mov must not be a syscall insn")
		}
		if isSyscallInsn([]byte{0x0f}) {
			t.Fatal("short buf must be rejected")
		}
	}
	if runtime.GOARCH == "arm64" {
		if !isSyscallInsn([]byte{0x01, 0x00, 0x00, 0xd4}) {
			t.Fatal("01 00 00 d4 should be a syscall insn")
		}
		if isSyscallInsn([]byte{0x00, 0x00, 0x00, 0x00}) {
			t.Fatal("nop must not be a syscall insn")
		}
		if isSyscallInsn([]byte{0x01, 0x00, 0x00}) {
			t.Fatal("short buf must be rejected")
		}
	}
}
