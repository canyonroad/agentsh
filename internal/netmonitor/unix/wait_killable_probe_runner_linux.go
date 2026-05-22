//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	// probeChildEnv carries a per-invocation random token written by
	// the parent and inspected by the child's init(). The gate is a
	// length filter (>=16 chars), not a cryptographic match: the parent
	// cannot share its in-process token with the child without writing
	// it via this same env var. The defence is therefore against
	// trivial sentinels like "1"/"true"/"yes" — a deliberate caller
	// who knows the contract and supplies any 16+ char value can still
	// invoke probe-child mode, which is acceptable (this is a private
	// internal contract, not a security boundary).
	probeChildEnv    = "AGENTSH_WAIT_KILLABLE_PROBE_CHILD"
	probeChildSockFD = "AGENTSH_WAIT_KILLABLE_PROBE_SOCK"
	probeBinaryPath  = "/bin/true"

	// probeChildStderrCap bounds how much child stderr we propagate back
	// to the parent on failure. Child diagnostics are short
	// fmt.Fprintf(os.Stderr, ...) lines; 4 KiB is ample headroom.
	probeChildStderrCap = 4096
)

// probeChildToken is the per-process random token the parent uses to
// authenticate probe-child invocations. It is generated lazily on first
// use in the parent and matched against probeChildEnv in the child's
// init(). A non-empty, well-formed token is required; the bare literal
// "1" is not accepted.
var (
	probeChildTokenOnce sync.Once
	probeChildToken     string
)

func ensureProbeChildToken() string {
	probeChildTokenOnce.Do(func() {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			// Fall back to a process-pid-derived token. Still
			// per-invocation in the sense that crashed neighbours
			// won't share it, and good enough since this is a
			// defence-in-depth measure (not a security boundary).
			probeChildToken = fmt.Sprintf("pid-%d-time-%d", os.Getpid(), time.Now().UnixNano())
			return
		}
		probeChildToken = hex.EncodeToString(b[:])
	})
	return probeChildToken
}

// init wires the production runner and detects probe-child mode. When
// invoked as a probe child the process never returns: it either execs
// /bin/true (success path) or os.Exit(70)s. Otherwise it just installs
// realRunProbeIteration over the placeholder from
// wait_killable_probe_linux.go.
//
// Child detection requires probeChildEnv to be set to a well-formed
// hex/identifier value (length >=16). A short value (e.g. "1") is
// rejected so a stray export in a developer shell does not turn
// arbitrary subprocesses into probe children.
func init() {
	if tok := os.Getenv(probeChildEnv); len(tok) >= 16 {
		runProbeChild()
		// runProbeChild never returns on success (it execs). If it does
		// return, treat as fatal child-side error so the rest of the
		// binary's init()s and main() never run.
		os.Exit(70)
	}
	runProbeIteration = realRunProbeIteration
}

func runProbeChild() {
	sockStr := os.Getenv(probeChildSockFD)
	sockFD, err := strconv.Atoi(sockStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: bad %s=%q: %v\n",
			probeChildSockFD, sockStr, err)
		return
	}

	prog, err := buildProbeFilterBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: build filter: %v\n", err)
		return
	}

	// loadRawFilter sets PR_SET_NO_NEW_PRIVS internally (see
	// seccomp_load_linux.go:121) before invoking seccomp(2), so a
	// non-root probe child can install the filter without CAP_SYS_ADMIN.
	notifyFD, err := loadRawFilter(prog, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: install filter: %v\n", err)
		return
	}

	// Hand notifyFD to the parent.
	if err := sendProbeFD(sockFD, notifyFD); err != nil {
		fmt.Fprintf(os.Stderr, "wait_killable probe child: send fd: %v\n", err)
		return
	}
	_ = unix.Close(notifyFD)
	_ = unix.Close(sockFD)

	// Exec /bin/true to fire the post-execve syscall storm under the
	// installed filter. Falls back to /bin/echo if /bin/true is missing.
	bin := probeBinaryPath
	if _, err := os.Stat(bin); err != nil {
		bin = "/bin/echo"
	}
	_ = syscall.Exec(bin, []string{bin}, []string{})
	fmt.Fprintf(os.Stderr, "wait_killable probe child: exec failed\n")
}

// buildProbeFilterBytes constructs the worst-case filter composition
// (socket family + file/metadata family + execve trap) as raw BPF bytes
// using the existing libseccomp + exportFilterBPF path. Filter is
// ActAllow by default so syscalls not in the rule set pass through
// unimpeded.
func buildProbeFilterBytes() ([]byte, error) {
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}
	defer filt.Release()

	trap := seccomp.ActNotify
	syscalls := []seccomp.ScmpSyscall{
		seccomp.ScmpSyscall(unix.SYS_SOCKET),
		seccomp.ScmpSyscall(unix.SYS_CONNECT),
		seccomp.ScmpSyscall(unix.SYS_BIND),
		seccomp.ScmpSyscall(unix.SYS_LISTEN),
		seccomp.ScmpSyscall(unix.SYS_SENDTO),
		seccomp.ScmpSyscall(unix.SYS_OPENAT),
		seccomp.ScmpSyscall(unix.SYS_STATX),
		seccomp.ScmpSyscall(unix.SYS_NEWFSTATAT),
		seccomp.ScmpSyscall(unix.SYS_FACCESSAT2),
		seccomp.ScmpSyscall(unix.SYS_READLINKAT),
	}
	for _, sc := range syscalls {
		if err := filt.AddRule(sc, trap); err != nil {
			return nil, fmt.Errorf("add probe rule %v: %w", sc, err)
		}
	}
	return exportFilterBPF(filt)
}

// sendProbeFD writes notifyFD over sockFD using SCM_RIGHTS.
func sendProbeFD(sockFD, notifyFD int) error {
	rights := unix.UnixRights(notifyFD)
	return unix.Sendmsg(sockFD, []byte{'F'}, rights, nil, 0)
}

// recvProbeFD reads one fd from sockFD over SCM_RIGHTS.
func recvProbeFD(sockFD int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, c := range cmsgs {
		fds, err := unix.ParseUnixRights(&c)
		if err == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errors.New("no fd received")
}

// realRunProbeIteration is the production runner installed in init().
func realRunProbeIteration(ctx context.Context) (IterationResult, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, fmt.Errorf("socketpair: %w", err)
	}
	parentSock, childSock := pair[0], pair[1]
	defer unix.Close(parentSock)

	// Wrap childSock immediately so the *os.File owns the fd: cmd.Start
	// dups it into the child as fd 3, and we close our end via
	// childFile.Close() (which clears the runtime finalizer). Calling
	// unix.Close(childSock) directly here would double-close once the
	// finalizer ran, potentially nuking an unrelated fd that took the
	// number after the first close.
	childFile := os.NewFile(uintptr(childSock), "probe-sock")
	// Defensive: if we never reach a normal close path, the deferred
	// Close still releases the fd exactly once. Close() on an already
	// closed *os.File is a no-op modulo a returned EBADF that we
	// deliberately ignore here.
	defer childFile.Close()

	binaryPath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("os.Executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	// Inherit the parent's environment so loader-related variables
	// (LD_LIBRARY_PATH, LD_PRELOAD, NixOS / Alpine / sanitizer
	// RPATH-substitution env) survive into the child. A wholesale
	// replacement would render the probe non-functional on those
	// hosts. probeChildEnv is appended last so a pre-existing
	// AGENTSH_WAIT_KILLABLE_PROBE_CHILD in the parent's environment
	// cannot override our per-invocation token.
	cmd.Env = append(os.Environ(),
		probeChildEnv+"="+ensureProbeChildToken(),
		probeChildSockFD+"=3", // ExtraFiles index 0 = fd 3
	)
	cmd.ExtraFiles = []*os.File{childFile}
	// Capture child stderr (bounded) so operators can see why a probe
	// child failed. Without this, classifyProbeExit returns a generic
	// wrapper error and the real cause (bad filter, EPERM, missing
	// /bin/true, etc.) is lost.
	stderrBuf := &boundedBuffer{cap: probeChildStderrCap}
	cmd.Stdout = nil
	cmd.Stderr = stderrBuf
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start probe child: %w", err)
	}
	// The fd was duped into the child; close our end. Closing via the
	// *os.File wrapper (not unix.Close) keeps ownership single-rooted.
	_ = childFile.Close()

	notifyFD, err := recvProbeFD(parentSock)
	if err != nil {
		_ = cmd.Process.Kill()
		// cmd.Wait() (not cmd.Process.Wait) drains os/exec's internal
		// stderr-copy goroutine before returning, so stderrBuf is
		// fully populated by the time we read it below.
		_ = cmd.Wait()
		return 0, fmt.Errorf("recv probe fd: %w (child stderr: %q)", err, stderrBuf.String())
	}
	// notifyFD ownership: closed below before we wait on `done`, so
	// the service goroutine's NotifReceive unblocks.

	// Service notifications until the child exits.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	serviceCtx, serviceCancel := context.WithCancel(ctx)
	serviceDone := make(chan struct{})
	go func() {
		defer close(serviceDone)
		serviceProbeNotifications(serviceCtx, notifyFD)
	}()

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()

	// finish performs the common cleanup of the service goroutine.
	// Closing notifyFD wakes any in-flight seccomp.NotifReceive (the
	// kernel returns EBADF/ENOENT), guaranteeing the goroutine exits
	// even though it spends most of its time blocked inside a syscall
	// that ignores serviceCancel.
	finish := func() {
		serviceCancel()
		_ = unix.Close(notifyFD)
		<-serviceDone
	}

	select {
	case waitErr := <-done:
		finish()
		// If the iteration was cancelled out from under us
		// (ctx.Done before child exit), cmd.Wait()'s ExitError will
		// show WIFSIGNALED because exec.CommandContext SIGKILLs the
		// child on ctx-cancel. Treating that as IterKilled would
		// silently flip the wait_killable decision to false because
		// shutdown happened to race the probe. Propagate the ctx
		// error instead.
		if cerr := ctx.Err(); cerr != nil {
			return 0, cerr
		}
		return classifyProbeExit(waitErr, stderrBuf.String())
	case <-timeout.C:
		_ = cmd.Process.Kill()
		<-done
		finish()
		return IterTimeout, nil
	}
}

// serviceProbeNotifications drains the notify fd and responds CONTINUE
// to every notification until ctx is cancelled or the fd errors.
//
// Termination: seccomp.NotifReceive blocks inside an ioctl that does
// NOT observe ctx. The goroutine is freed when the caller closes
// notifyFD (the kernel returns an error and we exit). The ctx select
// at the top of the loop only short-circuits the rare window between
// notifications where the goroutine has already returned from
// NotifReceive and is about to loop.
//
// Uses libseccomp-golang's seccomp.NotifReceive (the same call site as
// internal/netmonitor/unix/handler.go:41) for receive, and the existing
// NotifRespondContinue helper from addfd_linux.go for the response.
func serviceProbeNotifications(ctx context.Context, notifyFD int) {
	scmpFD := seccomp.ScmpFd(notifyFD)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		notif, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if !errors.Is(err, unix.EINTR) {
				slog.Debug("wait_killable probe: notify recv ended", "error", err)
			}
			return
		}
		if err := NotifRespondContinue(notifyFD, notif.ID); err != nil {
			slog.Debug("wait_killable probe: notify respond failed", "error", err)
			return
		}
	}
}

// classifyProbeExit maps cmd.Wait()'s result to an IterationResult.
// childStderr is the captured child stderr (bounded) and is included
// in the error return for the "unclassified" case so operators can
// see what the child actually printed before it died.
func classifyProbeExit(err error, childStderr string) (IterationResult, error) {
	if err == nil {
		return IterPass, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return IterKilled, nil
			}
			// cmd.Wait returns nil for status-0 exits, so an
			// ExitError here implies a non-zero exit; treat any
			// non-signaled failure as IterKilled (the child died
			// before reaching exec or /bin/true returned non-zero
			// — both indicate the iteration didn't cleanly survive
			// the post-execve syscall storm).
			return IterKilled, nil
		}
	}
	if childStderr != "" {
		return 0, fmt.Errorf("wait_killable probe: unclassified exit: %w (child stderr: %q)", err, childStderr)
	}
	return 0, fmt.Errorf("wait_killable probe: unclassified exit: %w", err)
}

// boundedBuffer is a write-only buffer that caps growth at `cap` bytes,
// silently dropping later writes. Used to bound child stderr so a
// pathological child can't blow up the parent's memory.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	cap int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.cap - b.buf.Len()
	if remaining <= 0 {
		return len(p), nil // pretend success; data is dropped
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
