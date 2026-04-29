//go:build linux

package ptrace

import (
	"errors"
	"log/slog"
	"runtime"

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

// PtraceKillRequested is the sentinel error returned by Apply when the
// action requires sending SIGKILL to the tracee. The caller is responsible
// for delivering the signal; Apply does not kill the process itself.
var PtraceKillRequested = errors.New("ptrace: kill requested by family check")

// ptraceAlreadyResumed is an internal sentinel returned by Apply when
// the action has already resumed the tracee (e.g., via denySyscall).
// The caller must not call allowSyscall in this case.
var ptraceAlreadyResumed = errors.New("ptrace: tracee already resumed by Apply")

// Apply executes the blocking action for a matched family rule against a
// stopped tracee. The caller has already matched via Check.
//
// errno:        calls denySyscall(tid, EAFNOSUPPORT) so the tracer's exit-stop
//
//	machinery delivers the correct return value on syscall exit.
//	Returns ptraceAlreadyResumed (internal) to signal the tracee
//	was already continued; the caller must not call allowSyscall.
//
// kill:         calls unix.Tgkill(tgid, tid, SIGKILL). On success returns
//
//	PtraceKillRequested so the caller calls allowSyscall to let the
//	killed tracee run until it receives the signal. On ESRCH (process
//	already vanished) returns nil. On other Tgkill errors, fails closed
//	by calling denySyscall and returning ptraceAlreadyResumed (or the
//	deny error if deny also fails).
//
// log:          emits a slog event with audit_event=seccomp_socket_family_blocked
//
//	(cross-engine audit consistency) and then denies the syscall by
//	calling denySyscall(tid, EAFNOSUPPORT). Log means log-and-deny in
//	ptrace mode, mirroring the seccomp engine. Returns ptraceAlreadyResumed.
//
// log_and_kill: emits the audit event and behaves like kill above.
//
// On ESRCH from denySyscall (tracee vanished), Apply returns ptraceAlreadyResumed
// so the caller does not attempt another ptrace call on a dead TID.
func (c *FamilyChecker) Apply(
	tid int,
	tgid int,
	tracer *Tracer,
	action seccomp.OnBlockAction,
	syscallNr int,
	bf seccomp.BlockedFamily,
) error {
	switch action {
	case seccomp.OnBlockErrno:
		// denySyscall sets ORIG_RAX=-1 and records PendingDenyErrno so the
		// tracer's exit-stop handler overwrites RAX with -EAFNOSUPPORT.
		// It also calls unix.PtraceSyscall internally, so the tracee is
		// already continued — return ptraceAlreadyResumed.
		if err := tracer.denySyscall(tid, int(unix.EAFNOSUPPORT)); err != nil {
			// ESRCH means the tracee is already gone — same outcome.
			if errors.Is(err, unix.ESRCH) {
				return ptraceAlreadyResumed
			}
			return err
		}
		return ptraceAlreadyResumed

	case seccomp.OnBlockKill, seccomp.OnBlockLogAndKill:
		if action == seccomp.OnBlockLogAndKill {
			emitFamilyBlockedLog(tid, syscallNr, bf, action)
		}
		if err := unix.Tgkill(tgid, tid, unix.SIGKILL); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// Process already vanished; nothing to do.
				return nil
			}
			// Real failure: fail closed — deny the syscall and surface the error.
			if denyErr := tracer.denySyscall(tid, int(unix.EAFNOSUPPORT)); denyErr != nil {
				// denySyscall itself failed; log and let caller know tracee state
				// is uncertain — return ptraceAlreadyResumed to prevent a second
				// allowSyscall on an indeterminate tracee.
				slog.Warn("ptrace: tgkill failed and deny fallback also failed",
					"tid", tid, "tgkill_err", err, "deny_err", denyErr)
				return ptraceAlreadyResumed
			}
			// denySyscall succeeded (tracee already resumed via deny path).
			slog.Warn("ptrace: tgkill failed; denied syscall instead",
				"tid", tid, "tgkill_err", err)
			return ptraceAlreadyResumed
		}
		return PtraceKillRequested

	case seccomp.OnBlockLog:
		emitFamilyBlockedLog(tid, syscallNr, bf, action)
		// Deny the syscall — log == log_and_deny in ptrace mode, mirroring the
		// seccomp engine (OnBlockLog denies AND logs there too).
		if err := tracer.denySyscall(tid, int(unix.EAFNOSUPPORT)); err != nil {
			if errors.Is(err, unix.ESRCH) {
				return ptraceAlreadyResumed
			}
			return err
		}
		return ptraceAlreadyResumed

	default:
		// Unknown action — fail open: allow the syscall to proceed.
		return nil
	}
}

// emitFamilyBlockedLog emits a structured slog event for a family block.
// The event type "seccomp_socket_family_blocked" matches the seccomp engine
// (internal/netmonitor/unix/blocklist_linux.go) for cross-engine SIEM
// consistency.
func emitFamilyBlockedLog(tid int, syscallNr int, bf seccomp.BlockedFamily, action seccomp.OnBlockAction) {
	syscallName := familySyscallName(syscallNr)
	slog.Info("ptrace: socket family blocked",
		"audit_event", "seccomp_socket_family_blocked",
		"family_name", bf.Name,
		"family_number", bf.Family,
		"syscall", syscallName,
		"syscall_nr", syscallNr,
		"action", string(action),
		"engine", "ptrace",
		"pid", tid,
		"arch", runtime.GOARCH,
	)
}

// familySyscallName returns a human-readable name for socket/socketpair.
// For any other syscall number a numeric sentinel is returned.
func familySyscallName(nr int) string {
	switch nr {
	case unix.SYS_SOCKET:
		return "socket"
	case unix.SYS_SOCKETPAIR:
		return "socketpair"
	default:
		return "unknown"
	}
}
