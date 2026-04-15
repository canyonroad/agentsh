//go:build linux && cgo

package unix

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// BlockListConfig maps seccomp syscall numbers to the on-block action that
// should be taken when a block-listed syscall traps via USER_NOTIF.
// A nil receiver is treated as an empty configuration.
type BlockListConfig struct {
	ActionByNr map[uint32]seccompkg.OnBlockAction
}

// notifIDValidFn is a test seam wrapping seccomp.NotifIDValid so unit tests
// can inject "valid" / "invalid" outcomes without a real notify fd. Production
// callers hit the real syscall; tests swap it like the pidfd seams.
var notifIDValidFn = func(fd int, id uint64) error {
	return seccomp.NotifIDValid(seccomp.ScmpFd(fd), id)
}

// resolveTGIDFn is a test seam for mapping a TID to its thread-group leader
// (TGID). Production reads /proc/<tid>/status. Unit tests swap in a
// deterministic lookup. Returns unix.ESRCH when /proc/<tid>/ is absent — the
// canonical "that task is gone" signal. Any other non-nil error is a parse /
// I/O failure the caller should treat as non-fatal (the field is only used to
// pick the pidfd target; if we cannot resolve it, we fall back to the raw TID
// and let attemptKill observe whatever errno the kernel returns).
var resolveTGIDFn = resolveTGIDFromProc

// resolveTGIDFromProc parses /proc/<tid>/status and returns the Tgid field.
// seccomp_notif.pid is the TID of the syscalling thread (see man 2 seccomp
// under "struct seccomp_notif"); for multi-threaded callers whose blocked
// syscall came from a non-leader thread, pidfd_open(TID, 0) fails because
// PIDTYPE_TGID is not set on the struct pid. Resolving to TGID lets us open
// a whole-process pidfd that works regardless of which thread trapped.
//
// PIDFD_THREAD (kernel 6.9+) would let us open a thread-scoped pidfd directly
// and send SIGKILL to just that thread. We target kernel 5.3+ (pidfd_open
// baseline) and deployment hosts still on 6.8, so /proc is the portable path.
func resolveTGIDFromProc(tid int) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Thread/process has exited — same semantic as pidfd_open ESRCH.
			return 0, unix.ESRCH
		}
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed Tgid line in /proc/%d/status: %q", tid, line)
		}
		tgid, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("parse Tgid in /proc/%d/status: %w", tid, err)
		}
		return tgid, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/%d/status: %w", tid, err)
	}
	return 0, fmt.Errorf("Tgid field absent from /proc/%d/status", tid)
}

// IsBlockListed returns the configured action for the given syscall number.
// Nil receiver and empty map both return (_, false). The caller can then
// route to the normal allow/deny path.
func (c *BlockListConfig) IsBlockListed(nr uint32) (seccompkg.OnBlockAction, bool) {
	if c == nil || len(c.ActionByNr) == 0 {
		return "", false
	}
	act, ok := c.ActionByNr[nr]
	return act, ok
}

// handleBlockListNotify processes a seccomp notification for a syscall that
// matched the block-list. The kernel is trapped waiting on this fd+id pair
// and will resume the syscall only after we respond (or after we kill the
// process). Behavior:
//
//  1. Validate the notification is still live (kernel may have recycled it
//     if the target exited). ENOENT-style errors are normal — log debug,
//     respond deny, do not emit an event.
//  2. Resolve syscall name for logging/event payload.
//  3. For OnBlockLogAndKill: SIGKILL the target via pidfd FIRST, then respond
//     deny. Doing kill first makes outcome=killed accurate: if we responded
//     first, the process might exit naturally via the EPERM return before
//     SIGKILL lands, and the event would mis-label the cause.
//  4. Emit the audit event on the provided Emitter (guarded; nil skips emit).
//  5. Respond deny with EPERM so any log-only target sees a predictable errno.
//     ENOENT on the response is expected when the kill already succeeded —
//     the kernel already released the notif id.
func handleBlockListNotify(
	ctx context.Context,
	fd int,
	req *seccomp.ScmpNotifReq,
	action seccompkg.OnBlockAction,
	sessID string,
	emit Emitter,
) {
	if req == nil {
		return
	}

	// 1. TOCTOU check — notif id may have been recycled if the target exited
	//    between NotifReceive and now. Same convention as file_handler.
	if err := notifIDValidFn(fd, req.ID); err != nil {
		slog.Debug("seccomp block-list: notif id no longer valid",
			"session_id", sessID, "pid", req.Pid, "error", err)
		if derr := NotifRespondDeny(fd, req.ID, int32(unix.EPERM)); derr != nil && !isENOENT(derr) {
			slog.Warn("seccomp block-list: deny response failed after invalid id",
				"session_id", sessID, "pid", req.Pid, "error", derr)
		}
		return
	}

	syscallNr := uint32(req.Data.Syscall)
	syscallName := resolveSyscallName(syscallNr)
	tid := int(req.Pid)

	// seccomp_notif.pid is the TID of the trapped thread, not the TGID.
	// pidfd_open on a non-TGL TID fails with EINVAL or ENOENT depending on
	// kernel version (6.8 on Ubuntu 24.04 returns ENOENT), so for multi-
	// threaded callers we must resolve TGID before opening the pidfd. We also
	// keep TID in the event so the audit record identifies which thread
	// trapped (useful for post-mortem on multi-threaded agents).
	targetPID := tid
	if action == seccompkg.OnBlockLogAndKill {
		if tgid, err := resolveTGIDFn(tid); err == nil {
			targetPID = tgid
		} else if errors.Is(err, unix.ESRCH) {
			// Thread already gone by the time we looked it up — skip the kill
			// attempt (no viable target) and tag the event as killed, since
			// the trapped syscall will never resume.
			slog.Debug("seccomp block-list: TGID resolution ESRCH (target already exited)",
				"session_id", sessID, "tid", tid, "syscall", syscallName)
			targetPID = -1 // sentinel: skip attemptKill
		} else {
			slog.Warn("seccomp block-list: TGID resolution failed; falling back to TID",
				"session_id", sessID, "tid", tid, "syscall", syscallName, "error", err)
		}
	}

	// 2. For log_and_kill, SIGKILL first so the outcome field reflects reality.
	//    attemptKill revalidates the notif id after opening the pidfd to close
	//    the PID-reuse race: if the target exited between the check above and
	//    pidfd_open, the pidfd may point to an unrelated process. The second
	//    check ensures the kernel hasn't released the trapped task yet — so
	//    the pidfd is guaranteed to reference the original caller.
	outcome := "denied"
	if action == seccompkg.OnBlockLogAndKill {
		if targetPID == -1 {
			outcome = "killed" // target already gone; no signal to send
		} else {
			outcome = attemptKill(fd, req.ID, targetPID, sessID, syscallName)
		}
	}

	// 3. Build + emit the audit event. Tests pass nil.
	// Event PID is the TID (the thread that trapped), which matches the
	// notify record; audit consumers can resolve TGID themselves if needed.
	if emit != nil {
		ev := buildSeccompBlockedEvent(sessID, tid, syscallName, syscallNr, action, outcome)
		// Use a fresh background context so AppendEvent isn't cancelled by
		// a notify-loop shutdown mid-handoff — consistent with ServeNotify.
		if err := emit.AppendEvent(context.Background(), ev); err != nil {
			slog.Warn("seccomp block-list: AppendEvent failed",
				"session_id", sessID, "tid", tid, "syscall", syscallName, "error", err)
		}
		emit.Publish(ev)
	}

	// 4. Respond deny with EPERM. ENOENT after a successful kill is expected.
	_ = ctx // retained for future cancellation hooks; deny response is non-blocking.
	if err := NotifRespondDeny(fd, req.ID, int32(unix.EPERM)); err != nil {
		if isENOENT(err) {
			slog.Debug("seccomp block-list: deny response hit ENOENT (target already gone)",
				"session_id", sessID, "tid", tid, "syscall", syscallName)
			return
		}
		slog.Warn("seccomp block-list: deny response failed",
			"session_id", sessID, "tid", tid, "syscall", syscallName, "error", err)
	}
}

// attemptKill opens a pidfd for pid and SIGKILLs it. Uses the test seams
// pidfdOpenFn / pidfdSendSignalFn / notifIDValidFn so unit tests can inject
// errno branches without spawning real processes.
//
// Ordering closes a PID-reuse race. Between the caller's initial
// NotifIDValid check and pidfd_open, the target task could exit and its PID
// could be recycled by an unrelated process. The sequence below revalidates
// the notif id *after* opening the pidfd but *before* signalling: while the
// notif id stays valid, the kernel guarantees the trapped task hasn't been
// released, so the pidfd we just opened must reference the original caller.
//
// Returns "killed" on successful signal delivery or when the target is
// already gone (ESRCH on open/signal, or invalid notif id after open —
// all three mean the original caller cannot observe further syscalls).
// Returns "denied" on any other error path.
func attemptKill(notifyFD int, notifID uint64, pid int, sessID, syscallName string) string {
	pidfd, err := pidfdOpenFn(pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			// Target is already gone — effectively killed.
			slog.Debug("seccomp block-list: pidfd_open ESRCH (target already exited)",
				"session_id", sessID, "pid", pid, "syscall", syscallName)
			return "killed"
		}
		slog.Warn("seccomp block-list: pidfd_open failed",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
		return "denied"
	}
	defer unix.Close(pidfd)

	// Revalidate notif id *after* the pidfd is anchored. If the kernel has
	// released the trapped task (ENOENT — the canonical "notif id gone"
	// error), the pidfd we just opened may reference a PID-reused unrelated
	// process. Aborting here prevents SIGKILL from landing on the wrong
	// target. Any other error (EINVAL on a bad listener fd, transient
	// ioctl failures) is NOT evidence the target is gone, so we must not
	// silently downgrade to "killed" — report denied so the audit record
	// reflects that we could not deliver the signal.
	if err := notifIDValidFn(notifyFD, notifID); err != nil {
		if isENOENT(err) {
			slog.Debug("seccomp block-list: notif id invalid after pidfd_open — skipping signal (possible pid reuse)",
				"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
			return "killed"
		}
		slog.Warn("seccomp block-list: notif id revalidation failed with non-ENOENT error; refusing signal",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
		return "denied"
	}

	if err := pidfdSendSignalFn(pidfd, unix.SIGKILL); err != nil {
		if errors.Is(err, unix.ESRCH) {
			slog.Debug("seccomp block-list: pidfd_send_signal ESRCH (target already exited)",
				"session_id", sessID, "pid", pid, "syscall", syscallName)
			return "killed"
		}
		slog.Warn("seccomp block-list: pidfd_send_signal failed",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
		return "denied"
	}
	return "killed"
}

// resolveSyscallName returns the human-readable syscall name for nr, or a
// sentinel "unknown(N)" when libseccomp doesn't recognize the number.
func resolveSyscallName(nr uint32) string {
	name, err := seccomp.ScmpSyscall(nr).GetName()
	if err != nil || name == "" {
		return fmt.Sprintf("unknown(%d)", nr)
	}
	return name
}

// buildSeccompBlockedEvent constructs the audit event for a block-list hit.
// Task 7 keys assertions off these Fields keys — they must remain stable.
// There is no types.Event.Metadata / types.Event.Syscall; all syscall metadata
// lives under Fields.
func buildSeccompBlockedEvent(
	sessID string,
	pid int,
	syscallName string,
	syscallNr uint32,
	action seccompkg.OnBlockAction,
	outcome string,
) types.Event {
	return types.Event{
		ID:        fmt.Sprintf("seccomp-%d-%d", pid, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "seccomp_blocked",
		SessionID: sessID,
		Source:    "seccomp",
		PID:       pid,
		Fields: map[string]any{
			"syscall":    syscallName,
			"syscall_nr": syscallNr,
			"action":     string(action),
			"outcome":    outcome,
			"arch":       runtime.GOARCH,
		},
	}
}
