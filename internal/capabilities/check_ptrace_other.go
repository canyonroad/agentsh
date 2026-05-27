//go:build !linux

package capabilities

// checkPtraceInject is a no-op on non-linux platforms (ptrace enforcement is
// linux-only). #369.
func checkPtraceInject() (injectable bool, detail string) { return false, "" }
