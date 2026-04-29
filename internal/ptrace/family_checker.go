//go:build linux

package ptrace

import (
	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// FamilyChecker matches socket(2)/socketpair(2) calls against a list of
// blocked AF_* families. Reuses the same []seccomp.BlockedFamily slice
// that the seccomp engine consumes — single source of truth.
type FamilyChecker struct {
	// bySyscall: SYS_SOCKET / SYS_SOCKETPAIR → family number → entry.
	bySyscall map[uint64]map[uint64]seccomp.BlockedFamily
}

// NewFamilyChecker indexes the entries for fast lookup. nil/empty input
// produces a checker that never matches.
func NewFamilyChecker(entries []seccomp.BlockedFamily) *FamilyChecker {
	c := &FamilyChecker{bySyscall: map[uint64]map[uint64]seccomp.BlockedFamily{}}
	for _, sc := range []uint64{uint64(unix.SYS_SOCKET), uint64(unix.SYS_SOCKETPAIR)} {
		c.bySyscall[sc] = map[uint64]seccomp.BlockedFamily{}
	}
	for _, e := range entries {
		for sc := range c.bySyscall {
			c.bySyscall[sc][uint64(e.Family)] = e
		}
	}
	return c
}

// Check reports the BlockedFamily entry for a given syscall+arg0 pair.
// ok=false means no rule applies (the syscall should be allowed).
func (c *FamilyChecker) Check(syscall, arg0 uint64) (seccomp.BlockedFamily, bool) {
	if c == nil || c.bySyscall == nil {
		return seccomp.BlockedFamily{}, false
	}
	families, ok := c.bySyscall[syscall]
	if !ok {
		return seccomp.BlockedFamily{}, false
	}
	bf, ok := families[arg0]
	return bf, ok
}
