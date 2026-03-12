//go:build linux && arm64

package ptrace

func syscallToOperationLegacy(nr int, flags int) string {
	return "unknown"
}

func isLegacyOpenSyscall(nr int) bool      { return false }
func isLegacyCreatSyscall(nr int) bool     { return false }
func isLegacyTwoPathSyscall(nr int) bool   { return false }
func isLegacySymlinkSyscall(nr int) bool   { return false }
func isLegacyChmodChownSyscall(nr int) bool { return false }
