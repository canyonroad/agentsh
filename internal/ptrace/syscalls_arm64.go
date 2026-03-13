//go:build linux && arm64

package ptrace

func isLegacyFileSyscall(nr int) bool   { return false }
func legacyFileSyscalls() []int         { return nil }
func legacyFilePathArgIndex(nr int) int { return -1 }
func isLegacyUnlink(nr int) bool        { return false }
