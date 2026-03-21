//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

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
			if isENOENT(err) {
				// Target process was killed — non-fatal, continue serving
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

// isENOENT checks if the error is ENOENT (target process was killed/exited).
// This is non-fatal for seccomp notification handlers — the handler should
// continue processing notifications from other processes.
func isENOENT(err error) bool {
	if errno, ok := err.(unix.Errno); ok {
		return errno == unix.ENOENT
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
			if isENOENT(err) {
				// Target process was killed or notification cancelled — non-fatal.
				// Sleep briefly to avoid tight spin.
				time.Sleep(1 * time.Millisecond)
				continue
			}
			slog.Error("ServeNotifyWithExecve: NotifReceive error (exiting)", "session_id", sessID, "error", err, "total_notifications", notifCount)
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
			if fileHandler.EmulateOpen() {
				handleFileNotificationEmulated(ctx, scmpFD, req, fileHandler, sessID)
			} else {
				handleFileNotification(ctx, scmpFD, req, fileHandler, sessID)
			}
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

	// Canonicalize filename: resolve symlinks, /proc/self/root, etc.
	// This defeats path manipulation attacks (e.g., /proc/self/root/usr/bin/npx).
	rawFilename := filename
	if resolved, err := filepath.EvalSymlinks(filename); err == nil {
		filename = resolved
	}
	// rawFilename preserved for audit; filename is now canonical

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
		PID:         pid,
		ParentPID:   parentPID,
		Filename:    filename,
		RawFilename: rawFilename,
		Argv:        argv,
		Truncated:   truncated,
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
		if err := handleRedirect(int(fd), req.ID, ectx, execveArgs.FilenamePtr, h.stubSymlinkPath, originalFilenameLen, result.Redirect); err != nil {
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

	// For openat2, resolve actual flags from the open_how struct in tracee memory.
	if args.Nr == unix.SYS_OPENAT2 && fileArgs.HowPtr != 0 {
		howFlags, howMode, err := readOpenHow(pid, fileArgs.HowPtr)
		if err != nil {
			slog.Debug("file handler: failed to read open_how, allowing", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		fileArgs.Flags = uint32(howFlags)
		fileArgs.Mode = uint32(howMode)
	}

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

// handleFileNotificationEmulated processes a file syscall notification using
// AddFD emulation for open-family syscalls. For openat/openat2 (not O_TMPFILE,
// not RESOLVE_*), the supervisor opens the file via /proc/<pid>/root/<path>
// and injects the fd via SECCOMP_ADDFD_FLAG_SEND. For non-open syscalls and
// fallback cases, it uses CONTINUE with two-check NotifIDValid bracketing
// (spec section 4, steps 2 and 4).
func handleFileNotificationEmulated(goCtx context.Context, fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, h *FileHandler, sessID string) {
	args := SyscallArgs{
		Nr:   int32(req.Data.Syscall),
		Arg0: req.Data.Args[0], Arg1: req.Data.Args[1], Arg2: req.Data.Args[2],
		Arg3: req.Data.Args[3], Arg4: req.Data.Args[4], Arg5: req.Data.Args[5],
	}

	pid := int(req.Pid)
	notifFD := int(fd)
	fileArgs := extractFileArgs(args)

	// For openat2, resolve actual flags from the open_how struct.
	var resolveFlags uint64
	if args.Nr == unix.SYS_OPENAT2 {
		// openat2 requires a valid how_ptr and size >= 24 (OPEN_HOW_SIZE_VER0).
		// If how_ptr is 0 or size is too small, the kernel would return EFAULT/EINVAL.
		// Don't emulate — return the expected error directly.
		howSize := args.Arg3
		if fileArgs.HowPtr == 0 {
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EFAULT)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		if howSize < 24 {
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EINVAL)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		howFlags, howMode, err := readOpenHow(pid, fileArgs.HowPtr)
		if err != nil {
			// Can't read open_how — fall back to CONTINUE so the kernel handles it
			// with proper error semantics, rather than returning EACCES.
			slog.Debug("emulated file handler: failed to read open_how, falling back to CONTINUE", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		fileArgs.Flags = uint32(howFlags)
		fileArgs.Mode = uint32(howMode)
		var resolveErr error
		resolveFlags, resolveErr = readOpenHowResolve(pid, fileArgs.HowPtr)
		if resolveErr != nil {
			// Cannot read resolve flags — force CONTINUE fallback (never emulate
			// when resolve flags are unknown, as non-zero RESOLVE_* flags can't
			// be replicated from the supervisor).
			slog.Debug("emulated file handler: cannot read resolve flags, forcing CONTINUE", "pid", pid, "error", resolveErr)
			resolveFlags = 1 // non-zero forces shouldFallbackToContinue → true
		}
	}

	// Determine early if this will be a CONTINUE-path syscall (non-open,
	// fallback, or unsupported flags). Used to decide error handling below.
	forceContinue := !isOpenSyscall(args.Nr) || shouldFallbackToContinue(args.Nr, fileArgs.Flags, resolveFlags)

	// Resolve primary path.
	// In emulation mode (non-CONTINUE): fail-secure (deny on error).
	// In CONTINUE mode: fail-open (let kernel handle it) — the kernel will
	// validate the path itself.
	path, err := resolvePathAt(pid, fileArgs.Dirfd, fileArgs.PathPtr)
	if err != nil {
		if forceContinue {
			slog.Debug("emulated file handler: failed to resolve path in CONTINUE mode, allowing", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		slog.Debug("emulated file handler: failed to resolve path, denying", "pid", pid, "error", err)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Resolve second path for rename/link.
	var path2 string
	if fileArgs.HasSecondPath {
		p2, err := resolvePathAt(pid, fileArgs.Dirfd2, fileArgs.PathPtr2)
		if err != nil {
			if forceContinue {
				slog.Debug("emulated file handler: failed to resolve second path in CONTINUE mode, allowing", "pid", pid, "error", err)
				resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
				_ = seccomp.NotifRespond(fd, &resp)
				return
			}
			slog.Debug("emulated file handler: failed to resolve second path, denying", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EACCES)}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		path2 = p2
	}

	operation := syscallToOperation(args.Nr, fileArgs.Flags)

	// Resolve /proc/self/fd/N, /proc/<pid>/fd/N, /dev/fd/N aliases before
	// both policy evaluation AND emulation. Without this, emulateOpenat would
	// open /proc/<pid>/root/proc/self/fd/N in the supervisor's context.
	if resolved, wasProcFD := resolveProcFD(pid, path); wasProcFD {
		path = resolved
	}
	if path2 != "" {
		if resolved, wasProcFD := resolveProcFD(pid, path2); wasProcFD {
			path2 = resolved
		}
	}

	frequest := FileRequest{
		PID: pid, Syscall: args.Nr, Path: path, Path2: path2,
		Operation: operation, Flags: fileArgs.Flags, Mode: fileArgs.Mode, SessionID: sessID,
	}

	// For non-emulated syscalls (CONTINUE path), do first ID validation
	// before policy evaluation (spec section 4, step 2).
	if forceContinue {
		if err := NotifIDValid(notifFD, req.ID); err != nil {
			if err == unix.ENOENT {
				slog.Debug("emulated file handler: notification stale before policy check", "pid", pid)
				return // notification cancelled, no response needed
			}
			// Non-ENOENT error — send CONTINUE to avoid leaving the syscall hanging.
			slog.Warn("emulated file handler: NotifIDValid error, allowing", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
	}

	result := h.Handle(frequest)

	// Branch: is this an open syscall that we should emulate via AddFD?
	if !forceContinue {
		if result.Action == ActionDeny {
			resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		// Verify notification is still live before side-effecting supervisor open.
		// A stale notification means the tracee exited — don't create/truncate files.
		if err := NotifIDValid(notifFD, req.ID); err != nil {
			if err == unix.ENOENT {
				slog.Debug("emulated file handler: notification stale before emulation", "pid", pid)
				return
			}
			slog.Warn("emulated file handler: NotifIDValid error before emulation, allowing via CONTINUE", "pid", pid, "error", err)
			resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
			_ = seccomp.NotifRespond(fd, &resp)
			return
		}
		emulateOpenat(fd, req, pid, path, fileArgs.Flags, fileArgs.Mode)
		return
	}

	// CONTINUE path with ID validation bracketing.
	if result.Action == ActionDeny {
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -result.Errno}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Second ID validation check after policy evaluation (spec section 4, step 4).
	if err := NotifIDValid(notifFD, req.ID); err != nil {
		if err == unix.ENOENT {
			slog.Debug("emulated file handler: notification stale after policy check", "pid", pid)
			return // notification cancelled, no response needed
		}
		// Non-ENOENT error — send CONTINUE to avoid leaving the syscall hanging.
		slog.Warn("emulated file handler: NotifIDValid error after policy, allowing", "pid", pid, "error", err)
	}
	resp := seccomp.ScmpNotifResp{ID: req.ID, Flags: seccomp.NotifRespFlagContinue}
	_ = seccomp.NotifRespond(fd, &resp)
}

// emulateOpenat opens a file on behalf of the tracee via /proc/<pid>/root/<path>,
// then injects the resulting fd into the tracee using SECCOMP_ADDFD_FLAG_SEND.
// This atomically installs the fd and completes the notification, eliminating
// TOCTOU races between the policy check and the actual open.
func emulateOpenat(fd seccomp.ScmpFd, req *seccomp.ScmpNotifReq, pid int, path string, flags uint32, mode uint32) {
	procPath := fmt.Sprintf("/proc/%d/root%s", pid, path)

	openFlags := int(flags) & int(emulableFlagMask)

	// When O_CREAT is set, apply the tracee's umask to the mode so that
	// supervisor-created files have the same permissions the kernel would
	// produce. The umask is read from /proc/<pid>/status (Umask field).
	effectiveMode := mode
	if openFlags&unix.O_CREAT != 0 {
		if umask, err := readTraceeUmask(pid); err == nil {
			effectiveMode = mode &^ umask
		}
		// On error reading umask, use the raw mode — this is conservative
		// (may be slightly more permissive than intended, but the file is
		// inside the sandbox so the blast radius is contained).
	}

	supervisorFD, err := unix.Open(procPath, openFlags, effectiveMode)
	if err != nil {
		errno, ok := err.(unix.Errno)
		if !ok {
			errno = unix.EIO
		}
		slog.Debug("emulateOpenat: supervisor open failed", "pid", pid, "path", path, "error", err)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(errno)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}

	// Propagate O_CLOEXEC to the injected fd in the tracee — without this,
	// the fd could leak across exec boundaries.
	var addfdFlags uint32 = SECCOMP_ADDFD_FLAG_SEND
	var newfdFlags uint32
	if flags&unix.O_CLOEXEC != 0 {
		newfdFlags = unix.O_CLOEXEC
	}

	addReq := seccompNotifAddFD{
		id:         req.ID,
		flags:      addfdFlags,
		srcfd:      uint32(supervisorFD),
		newfd:      0,
		newfdFlags: newfdFlags,
	}
	_, _, addErrno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(ioctlNotifAddFD),
		uintptr(unsafe.Pointer(&addReq)),
	)
	_ = unix.Close(supervisorFD)
	if addErrno != 0 {
		slog.Error("emulateOpenat: AddFD failed", "pid", pid, "path", path, "error", addErrno)
		resp := seccomp.ScmpNotifResp{ID: req.ID, Error: -int32(unix.EIO)}
		_ = seccomp.NotifRespond(fd, &resp)
		return
	}
}

// readTraceeUmask reads the umask of a tracee process from /proc/<pid>/status.
// Returns the umask as a uint32 bitmask, or an error if it cannot be read.
func readTraceeUmask(pid int) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Umask:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("malformed Umask line")
			}
			val, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 8, 32)
			if err != nil {
				return 0, err
			}
			return uint32(val), nil
		}
	}
	return 0, fmt.Errorf("Umask not found in /proc/%d/status", pid)
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
