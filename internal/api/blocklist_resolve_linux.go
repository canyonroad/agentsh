//go:build linux && cgo

package api

import "github.com/agentsh/agentsh/internal/seccomp"

// resolvableBlockListCount returns how many of the given syscall names
// resolve to a syscall number on the current arch. Used by
// blockListUsesNotify so the USER_NOTIF gate only flips when the
// wrapper will actually install ActNotify rules — otherwise the server
// would start a ptrace handshake that the wrapper never answers.
func resolvableBlockListCount(names []string) int {
	resolved, _ := seccomp.ResolveSyscalls(names)
	return len(resolved)
}
