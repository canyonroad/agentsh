//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Emitter matches the minimal event interface we need.
type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// ServeNotify runs the seccomp notify loop on the provided notify fd.
// It stops when the fd is closed or ctx is done.
func ServeNotify(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter) {
	if fd == nil || pol == nil || emit == nil {
		return
	}
	scmpFD := seccomp.ScmpFd(fd.Fd())
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if isEAGAIN(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
		ctxReq := ExtractContext(req)
		if !isUnixSocketSyscall(ctxReq.Syscall) {
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID})
			continue
		}
		allow := true
		errno := int32(unix.EACCES)
		path := ""
		abstract := false
		if raw, err := ReadSockaddr(ctxReq.PID, ctxReq.AddrPtr, ctxReq.AddrLen); err == nil {
			if p, abs, perr := ParseSockaddr(raw); perr == nil {
				path, abstract = p, abs
				op := syscallName(ctxReq.Syscall)
				dec := pol.CheckUnixSocket(path, op)
				allow = dec.EffectiveDecision == types.DecisionAllow
				if !allow {
					errno = int32(unix.EACCES)
					emitEvent(emit, sessID, dec, path, abstract, op)
				}
			}
		}
		resp := seccomp.ScmpNotifResp{ID: req.ID}
		if !allow {
			resp.Error = -errno
		}
		_ = seccomp.NotifRespond(scmpFD, &resp)
	}
}

func isUnixSocketSyscall(sc seccomp.ScmpSyscall) bool {
	switch sc {
	case seccomp.ScmpSyscall(unix.SYS_SOCKET), seccomp.ScmpSyscall(unix.SYS_CONNECT), seccomp.ScmpSyscall(unix.SYS_BIND), seccomp.ScmpSyscall(unix.SYS_LISTEN), seccomp.ScmpSyscall(unix.SYS_SENDTO):
		return true
	default:
		return false
	}
}

func syscallName(sc seccomp.ScmpSyscall) string {
	switch sc {
	case seccomp.ScmpSyscall(unix.SYS_SOCKET):
		return "socket"
	case seccomp.ScmpSyscall(unix.SYS_CONNECT):
		return "connect"
	case seccomp.ScmpSyscall(unix.SYS_BIND):
		return "bind"
	case seccomp.ScmpSyscall(unix.SYS_LISTEN):
		return "listen"
	case seccomp.ScmpSyscall(unix.SYS_SENDTO):
		return "sendto"
	default:
		return ""
	}
}

func isEAGAIN(err error) bool {
	if errno, ok := err.(unix.Errno); ok {
		return errno == unix.EAGAIN
	}
	return false
}

func emitEvent(emit Emitter, session string, dec policy.Decision, path string, abstract bool, op string) {
	ev := types.Event{
		ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "unix_socket_op",
		SessionID: session,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		Path:      path,
		Abstract:  abstract,
		Operation: op,
	}
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}

// ServeNotifyWithExecve runs the seccomp notify loop with execve interception support.
// It routes execve/execveat syscalls to the execveHandler and unix socket syscalls to the policy engine.
// It stops when the fd is closed or ctx is done.
func ServeNotifyWithExecve(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter, execveHandler *ExecveHandler) {
	if fd == nil || emit == nil {
		return
	}
	scmpFD := seccomp.ScmpFd(fd.Fd())
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if isEAGAIN(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}

		syscallNr := int32(req.Data.Syscall)

		// Route to appropriate handler
		if IsExecveSyscall(syscallNr) && execveHandler != nil {
			handleExecveNotification(scmpFD, req, execveHandler)
			continue
		}

		// Existing unix socket handling
		ctxReq := ExtractContext(req)
		if !isUnixSocketSyscall(ctxReq.Syscall) {
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID})
			continue
		}

		// Skip policy check if pol is nil - just allow
		if pol == nil {
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID})
			continue
		}

		allow := true
		errno := int32(unix.EACCES)
		path := ""
		abstract := false
		if raw, err := ReadSockaddr(ctxReq.PID, ctxReq.AddrPtr, ctxReq.AddrLen); err == nil {
			if p, abs, perr := ParseSockaddr(raw); perr == nil {
				path, abstract = p, abs
				op := syscallName(ctxReq.Syscall)
				dec := pol.CheckUnixSocket(path, op)
				allow = dec.EffectiveDecision == types.DecisionAllow
				if !allow {
					errno = int32(unix.EACCES)
					emitEvent(emit, sessID, dec, path, abstract, op)
				}
			}
		}
		resp := seccomp.ScmpNotifResp{ID: req.ID}
		if !allow {
			resp.Error = -errno
		}
		_ = seccomp.NotifRespond(scmpFD, &resp)
	}
}

// handleExecveNotification processes an execve/execveat notification.
// It reads the filename and argv from the tracee process, builds an ExecveContext,
// and calls the handler to make a decision.
func handleExecveNotification(fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *ExecveHandler) {
	// Extract syscall args
	args := SyscallArgs{
		Nr:   int32(req.Data.Syscall),
		Arg0: req.Data.Args[0],
		Arg1: req.Data.Args[1],
		Arg2: req.Data.Args[2],
		Arg3: req.Data.Args[3],
		Arg4: req.Data.Args[4],
		Arg5: req.Data.Args[5],
	}

	execveArgs := ExtractExecveArgs(args)
	pid := int(req.Pid)

	// Read filename from tracee
	cfg := ExecveReaderConfig{
		MaxArgc:      h.cfg.MaxArgc,
		MaxArgvBytes: h.cfg.MaxArgvBytes,
	}

	filename, err := readString(pid, execveArgs.FilenamePtr, 4096)
	if err != nil {
		// Can't read filename - deny (fail-secure)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	argv, truncated, err := ReadArgv(pid, execveArgs.ArgvPtr, cfg)
	if err != nil {
		// Can't read argv - deny (fail-secure)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Get parent PID
	parentPID := getParentPID(pid)

	ctx := ExecveContext{
		PID:       pid,
		ParentPID: parentPID,
		Filename:  filename,
		Argv:      argv,
		Truncated: truncated,
	}

	result := h.Handle(ctx)

	resp := seccomp.ScmpNotifResp{ID: req.ID}
	if !result.Allow {
		resp.Error = -result.Errno
	}
	_ = seccomp.NotifRespond(fd, &resp)
}

// getParentPID reads the parent PID from /proc/<pid>/stat.
// Returns 0 if the PID doesn't exist or the stat file can't be parsed.
func getParentPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Format: pid (comm) state ppid ...
	// Find the closing paren to handle comm with spaces/special chars
	str := string(data)
	closeParenIdx := strings.LastIndex(str, ")")
	if closeParenIdx == -1 || closeParenIdx+2 >= len(str) {
		return 0
	}
	fields := strings.Fields(str[closeParenIdx+2:])
	if len(fields) < 2 {
		return 0
	}
	// fields[0] is state, fields[1] is ppid
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}
