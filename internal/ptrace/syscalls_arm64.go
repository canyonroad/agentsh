//go:build linux && arm64

package ptrace

func isLegacyFileSyscall(nr int) bool { return false }
func legacyFileSyscalls() []int       { return nil }
