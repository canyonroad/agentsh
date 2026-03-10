//go:build linux && cgo && !amd64

package unix

// legacyFileSyscallList returns nil on non-amd64 architectures.
// ARM64 and others only have the -at variants.
func legacyFileSyscallList() []int32 { return nil }

// isLegacyFileSyscall returns false on non-amd64 architectures.
func isLegacyFileSyscall(nr int32) bool { return false }

// extractLegacyFileArgs returns empty FileArgs on non-amd64 architectures.
func extractLegacyFileArgs(args SyscallArgs) FileArgs { return FileArgs{} }

// legacySyscallToOperation returns empty string on non-amd64 architectures.
func legacySyscallToOperation(nr int32, flags uint32) string { return "" }

// legacyFileSyscallName returns empty string on non-amd64 architectures.
func legacyFileSyscallName(nr int32) string { return "" }
