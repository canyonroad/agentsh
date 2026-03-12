//go:build linux && amd64

package ptrace

func createTestRegs() Regs {
	return &amd64Regs{}
}
