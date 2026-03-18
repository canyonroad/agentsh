//go:build linux

package ptrace

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// StaticDenyChecker is an optional interface that handlers implement to declare
// syscalls that are always denied regardless of arguments for the session lifetime.
// This enables BPF-level enforcement (SECCOMP_RET_ERRNO) without ptrace stops.
type StaticDenyChecker interface {
	StaticDenySyscalls() []StaticDeny
}

// StaticDeny represents a syscall that should be denied at the BPF level.
type StaticDeny struct {
	Nr    int
	Errno int // must be > 0
}

// collectStaticDenies gathers all static deny declarations from handlers and config.
func (t *Tracer) collectStaticDenies() []StaticDeny {
	var denies []StaticDeny

	// Category enabled but handler nil → deny all relevant syscalls
	if t.cfg.TraceNetwork && t.cfg.NetworkHandler == nil {
		denies = append(denies,
			StaticDeny{Nr: unix.SYS_CONNECT, Errno: int(unix.EACCES)},
			StaticDeny{Nr: unix.SYS_BIND, Errno: int(unix.EACCES)},
		)
	}

	// Handler-declared denies
	if checker, ok := t.cfg.NetworkHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.FileHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.ExecHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}
	if checker, ok := t.cfg.SignalHandler.(StaticDenyChecker); ok {
		denies = append(denies, checker.StaticDenySyscalls()...)
	}

	return validateStaticDenies(denies)
}

// escalationSyscalls is the set of syscalls used by lazy BPF escalation.
// Static denies must not overlap with these (seccomp stacking: lowest-value action wins,
// SECCOMP_RET_ERRNO < SECCOMP_RET_TRACE, so ERRNO cannot be overridden by later TRACE).
var escalationSyscalls = map[int]bool{
	unix.SYS_READ:    true,
	unix.SYS_PREAD64: true,
	unix.SYS_WRITE:   true,
}

// StaticAllowChecker is an optional interface that handlers implement to declare
// syscalls that are always allowed regardless of arguments for the session lifetime.
// These syscalls are excluded from the BPF traced set — the default SECCOMP_RET_ALLOW
// handles them in-kernel with zero ptrace overhead.
type StaticAllowChecker interface {
	StaticAllowSyscalls() []int
}

// collectStaticAllows gathers all static allow declarations from handlers.
func (t *Tracer) collectStaticAllows() map[int]bool {
	allows := make(map[int]bool)
	handlers := []interface{}{
		t.cfg.FileHandler,
		t.cfg.NetworkHandler,
		t.cfg.ExecHandler,
		t.cfg.SignalHandler,
	}
	for _, h := range handlers {
		if checker, ok := h.(StaticAllowChecker); ok {
			for _, nr := range checker.StaticAllowSyscalls() {
				allows[nr] = true
			}
		}
	}
	return allows
}

// validateStaticDenies filters out invalid entries and logs warnings.
func validateStaticDenies(denies []StaticDeny) []StaticDeny {
	valid := make([]StaticDeny, 0, len(denies))
	for _, d := range denies {
		if d.Errno <= 0 {
			slog.Warn("static deny: rejecting entry with invalid errno",
				"nr", d.Nr, "errno", d.Errno)
			continue
		}
		if escalationSyscalls[d.Nr] {
			slog.Warn("static deny: rejecting entry that overlaps escalation syscalls",
				"nr", d.Nr)
			continue
		}
		valid = append(valid, d)
	}
	return valid
}
