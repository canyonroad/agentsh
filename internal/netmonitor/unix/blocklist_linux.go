//go:build linux && cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
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
	if err := seccomp.NotifIDValid(seccomp.ScmpFd(fd), req.ID); err != nil {
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
	pid := int(req.Pid)

	// 2. For log_and_kill, SIGKILL first so the outcome field reflects reality.
	outcome := "denied"
	if action == seccompkg.OnBlockLogAndKill {
		outcome = attemptKill(pid, sessID, syscallName)
	}

	// 3. Build + emit the audit event. Tests pass nil.
	if emit != nil {
		ev := buildSeccompBlockedEvent(sessID, pid, syscallName, syscallNr, action, outcome)
		// Use a fresh background context so AppendEvent isn't cancelled by
		// a notify-loop shutdown mid-handoff — consistent with ServeNotify.
		if err := emit.AppendEvent(context.Background(), ev); err != nil {
			slog.Warn("seccomp block-list: AppendEvent failed",
				"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
		}
		emit.Publish(ev)
	}

	// 4. Respond deny with EPERM. ENOENT after a successful kill is expected.
	_ = ctx // retained for future cancellation hooks; deny response is non-blocking.
	if err := NotifRespondDeny(fd, req.ID, int32(unix.EPERM)); err != nil {
		if isENOENT(err) {
			slog.Debug("seccomp block-list: deny response hit ENOENT (target already gone)",
				"session_id", sessID, "pid", pid, "syscall", syscallName)
			return
		}
		slog.Warn("seccomp block-list: deny response failed",
			"session_id", sessID, "pid", pid, "syscall", syscallName, "error", err)
	}
}

// attemptKill opens a pidfd for pid and SIGKILLs it. Uses the test seams
// pidfdOpenFn / pidfdSendSignalFn so unit tests can inject errno branches
// without spawning real processes. Returns "killed" on success (including
// ESRCH — the target already exited, which is equivalent for our purposes),
// and "denied" on any other error.
func attemptKill(pid int, sessID, syscallName string) string {
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
