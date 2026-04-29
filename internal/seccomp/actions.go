package seccomp

// OnBlockAction determines what seccomp does when a block-listed syscall
// or socket family fires. Pure config type; importable from any package
// regardless of platform.
type OnBlockAction string

const (
	OnBlockErrno      OnBlockAction = "errno"
	OnBlockKill       OnBlockAction = "kill"
	OnBlockLog        OnBlockAction = "log"
	OnBlockLogAndKill OnBlockAction = "log_and_kill"
)

// ParseOnBlock converts a config string to a typed action.
// Empty string maps to OnBlockErrno (the default). Unknown strings
// return OnBlockErrno and false — callers should treat this as a
// defense-in-depth degradation and log a warning.
func ParseOnBlock(s string) (OnBlockAction, bool) {
	switch OnBlockAction(s) {
	case "", OnBlockErrno:
		return OnBlockErrno, true
	case OnBlockKill, OnBlockLog, OnBlockLogAndKill:
		return OnBlockAction(s), true
	default:
		return OnBlockErrno, false
	}
}
