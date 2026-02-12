//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
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
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue})
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
		if allow {
			resp.Flags = seccomp.NotifRespFlagContinue
		} else {
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
func ServeNotifyWithExecve(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter, execveHandler *ExecveHandler, fileHandler *FileHandler) {
	if fd == nil || emit == nil {
		slog.Debug("ServeNotifyWithExecve: nil fd or emit", "fd_nil", fd == nil, "emit_nil", emit == nil)
		return
	}
	scmpFD := seccomp.ScmpFd(fd.Fd())
	slog.Debug("ServeNotifyWithExecve: starting notify loop", "session_id", sessID, "scmp_fd", scmpFD)
	notifCount := 0
	for {
		select {
		case <-ctx.Done():
			slog.Debug("ServeNotifyWithExecve: context done", "session_id", sessID, "total_notifications", notifCount)
			return
		default:
		}
		req, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if isEAGAIN(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			slog.Debug("ServeNotifyWithExecve: NotifReceive error (exiting)", "session_id", sessID, "error", err, "total_notifications", notifCount)
			return
		}
		notifCount++

		syscallNr := int32(req.Data.Syscall)
		slog.Debug("ServeNotifyWithExecve: received notification", "session_id", sessID, "syscall_nr", syscallNr, "pid", req.Pid, "count", notifCount)

		// Route to appropriate handler
		if IsExecveSyscall(syscallNr) && execveHandler != nil {
			slog.Debug("ServeNotifyWithExecve: routing to execve handler", "session_id", sessID, "pid", req.Pid)
			handleExecveNotification(ctx, scmpFD, req, execveHandler)
			continue
		}

		// Route file syscalls to file handler
		if isFileSyscall(syscallNr) && fileHandler != nil {
			slog.Debug("ServeNotifyWithExecve: routing to file handler", "session_id", sessID, "pid", req.Pid, "syscall", syscallNr)
			handleFileNotification(ctx, scmpFD, req, fileHandler, sessID)
			continue
		}

		// Existing unix socket handling
		ctxReq := ExtractContext(req)
		if !isUnixSocketSyscall(ctxReq.Syscall) {
			slog.Debug("ServeNotifyWithExecve: non-unix syscall, allowing", "session_id", sessID, "syscall", ctxReq.Syscall)
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue})
			continue
		}

		// Skip policy check if pol is nil - just allow
		if pol == nil {
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue})
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
		if allow {
			resp.Flags = seccomp.NotifRespFlagContinue
		} else {
			resp.Error = -errno
		}
		_ = seccomp.NotifRespond(scmpFD, &resp)
	}
}

// handleExecveNotification processes an execve/execveat notification.
// It reads the filename and argv from the tracee process, builds an ExecveContext,
// and calls the handler to make a decision.
func handleExecveNotification(goCtx context.Context, fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *ExecveHandler) {
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
		const AT_EMPTY_PATH = 0x1000
		// For execve, always fail-secure if we can't read the filename
		// For execveat with AT_EMPTY_PATH, we can resolve from fd
		if !execveArgs.IsExecveat || (execveArgs.Flags&AT_EMPTY_PATH == 0) {
			// Can't read filename - deny (fail-secure)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		// AT_EMPTY_PATH case: filename is ignored, will resolve from fd
		filename = ""
	}

	// Save original filename length before potential resolution by execveat.
	// The memory at filenamePtr only has space for the original string.
	originalFilenameLen := len(filename)

	// Handle execveat special cases: AT_EMPTY_PATH and relative paths
	if execveArgs.IsExecveat {
		filename, err = resolveExecveatPath(pid, execveArgs, filename)
		if err != nil {
			// Can't resolve path - deny (fail-secure)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
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

	ectx := ExecveContext{
		PID:       pid,
		ParentPID: parentPID,
		Filename:  filename,
		Argv:      argv,
		Truncated: truncated,
	}

	result := h.Handle(goCtx, ectx)

	switch result.Action {
	case ActionRedirect:
		if h.stubSymlinkPath == "" {
			slog.Error("redirect requested but no stub symlink configured, denying",
				"pid", pid, "cmd", ectx.Filename)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EPERM)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		if err := handleRedirect(int(fd), req.ID, ectx, execveArgs.FilenamePtr, h.stubSymlinkPath, originalFilenameLen); err != nil {
			slog.Error("redirect failed, denying", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EPERM)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		// handleRedirect succeeded — respond with CONTINUE to re-execute
		// the modified execve (filename now points to agentsh-stub symlink).
		resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
		_ = seccomp.NotifRespond(fd, &resp)
		return

	case ActionDeny:
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
		_ = seccomp.NotifRespond(fd, &resp)
		return

	default: // ActionContinue
		resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}
}

// handleFileNotification processes a file syscall notification.
// It reads the path from the tracee process, builds a FileRequest,
// and calls the file handler to make a decision.
func handleFileNotification(goCtx context.Context, fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *FileHandler, sessID string) {
	args := SyscallArgs{
		Nr:   int32(req.Data.Syscall),
		Arg0: req.Data.Args[0],
		Arg1: req.Data.Args[1],
		Arg2: req.Data.Args[2],
		Arg3: req.Data.Args[3],
		Arg4: req.Data.Args[4],
		Arg5: req.Data.Args[5],
	}

	pid := int(req.Pid)
	fileArgs := extractFileArgs(args)

	// Resolve primary path
	path, err := resolvePathAt(pid, fileArgs.Dirfd, fileArgs.PathPtr)
	if err != nil {
		slog.Debug("file handler: failed to resolve path, allowing", "pid", pid, "error", err)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Resolve second path for rename/link
	var path2 string
	if fileArgs.HasSecondPath {
		p2, err := resolvePathAt(pid, fileArgs.Dirfd2, fileArgs.PathPtr2)
		if err != nil {
			slog.Debug("file handler: failed to resolve second path, allowing", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		path2 = p2
	}

	operation := syscallToOperation(args.Nr, fileArgs.Flags)

	frequest := FileRequest{
		PID:       pid,
		Syscall:   args.Nr,
		Path:      path,
		Path2:     path2,
		Operation: operation,
		Flags:     fileArgs.Flags,
		Mode:      fileArgs.Mode,
		SessionID: sessID,
	}

	result := h.Handle(frequest)

	resp := seccomp.ScmpNotifResp{ID: req.ID}
	if result.Action == ActionDeny {
		resp.Error = -result.Errno
	} else {
		resp.Flags = seccomp.NotifRespFlagContinue
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

// resolveExecveatPath resolves the actual executable path for execveat syscalls.
// It handles AT_EMPTY_PATH (execute fd directly) and relative paths (relative to dirfd).
func resolveExecveatPath(pid int, args ExecveArgs, filename string) (string, error) {
	const AT_EMPTY_PATH = 0x1000

	// AT_EMPTY_PATH: pathname is empty and dirfd refers to the file to execute
	if args.Flags&AT_EMPTY_PATH != 0 {
		// Read the actual path from /proc/<pid>/fd/<dirfd>
		fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, args.Dirfd)
		resolved, err := os.Readlink(fdPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve AT_EMPTY_PATH: %w", err)
		}
		return resolved, nil
	}

	// If pathname is absolute, use it directly
	if len(filename) > 0 && filename[0] == '/' {
		return filename, nil
	}

	// Relative path: resolve relative to dirfd
	// AT_FDCWD (-100) means current working directory
	const AT_FDCWD = -100
	if args.Dirfd == AT_FDCWD {
		// Resolve relative to process's cwd
		cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
		cwd, err := os.Readlink(cwdPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve cwd: %w", err)
		}
		return cwd + "/" + filename, nil
	}

	// Resolve relative to dirfd
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, args.Dirfd)
	dirPath, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve dirfd: %w", err)
	}
	return dirPath + "/" + filename, nil
}
