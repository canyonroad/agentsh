//go:build linux && arm64

package ptrace

func createTestRegs() Regs {
	return &arm64Regs{}
}
