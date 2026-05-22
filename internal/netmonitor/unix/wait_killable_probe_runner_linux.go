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
	// the parent and inspected by the child's init(). The gate also
	// requires probeChildArgvSentinel in argv[1]; both must match.
	// Together they prevent stray inherited env or a lone misconfigured
	// arg from hijacking the binary.
	probeChildEnv    = "AGENTSH_WAIT_KILLABLE_PROBE_CHILD"
	probeChildSockFD = "AGENTSH_WAIT_KILLABLE_PROBE_SOCK"
	probeBinaryPath  = "/bin/true"

	// probeChildArgvSentinel is the marker the parent injects as argv[1]
	// of the probe child. The child's init() requires this exact value
	// before honouring the env-var token. A version suffix lets us bump
	// the protocol later without colliding with old in-flight tests.
	probeChildArgvSentinel = "--agentsh-internal-wait-killable-probe-child-v1"

	// probeChildStderrCap bounds how much child stderr we propagate back
	// to the parent on failure. Child diagnostics are short
	// fmt.Fprintf(os.Stderr, ...) lines; 4 KiB is ample headroom.
	probeChildStderrCap = 4096

	// Exit codes used by the probe child. The parent's classifier
	// treats these specifically so a setup failure does not look like
	// a kernel-bug hit.
	probeExitSetupFailure = 71 // any runProbeChild early-return (bad env, filter build, install, fd send, etc.)
	probeExitFallback     = 70 // runProbeChild returned past the exec call without any explicit early-return (shouldn't happen)

	// probeRecvTimeout caps how long the parent waits for the child to
	// send its notify fd before giving up. The child only blocks
	// internally on libseccomp filter compilation and the seccomp(2)
	// syscall, neither of which should ever exceed sub-second; 2s is
	// generous headroom for slow CI VMs.
	probeRecvTimeout = 2 * time.Second
)

// probeChildToken is the per-process random token the parent uses to
// authenticate probe-child invocations.
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

// buildProbeChildArgv returns the argv the parent must use when
// re-execing itself as a probe child. Centralised so the two ends of
// the contract — parent construction here vs. child detection in
// isProbeChildInvocation — never decouple. If you change the shape,
// update both call sites in this file.
func buildProbeChildArgv(binaryPath string) []string {
	return []string{binaryPath, probeChildArgvSentinel}
}

// isProbeChildInvocation reports whether the current process was
// launched as a probe child. The gate is a two-factor check:
//
//   - argv[1] must equal probeChildArgvSentinel (a stable internal marker)
//   - the probeChildEnv variable must be set to a value of length >= 16
//
// Either alone would be too permissive: a stray env export in a
// developer shell could hijack arbitrary subprocesses (env-only), and
// argv[0]/argv[1] inspection alone would miss the actual cross-check
// the parent uses (argv-only). Requiring both narrows the gate to
// invocations the parent itself constructed (see buildProbeChildArgv).
func isProbeChildInvocation() bool {
	if len(os.Args) < 2 || os.Args[1] != probeChildArgvSentinel {
		return false
	}
	if tok := os.Getenv(probeChildEnv); len(tok) >= 16 {
		return true
	}
	return false
}

// init wires the production runner and detects probe-child mode. When
// invoked as a probe child the process never returns: it either execs
// /bin/true (success path) or exits with a setup-failure status.
// Otherwise it installs realRunProbeIteration over the placeholder
// from wait_killable_probe_linux.go.
func init() {
	if isProbeChildInvocation() {
		runProbeChild()
		// runProbeChild never returns on success (it execs); any
		// return is a setup failure that the parent decodes via
		// probeExitSetupFailure.
		os.Exit(probeExitFallback)
	}
	runProbeIteration = realRunProbeIteration
}

// childSetupFailure prints msg to stderr and exits with the
// setup-failure status the parent's classifier recognises.
func childSetupFailure(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wait_killable probe child: "+format+"\n", args...)
	os.Exit(probeExitSetupFailure)
}

func runProbeChild() {
	sockStr := os.Getenv(probeChildSockFD)
	sockFD, err := strconv.Atoi(sockStr)
	if err != nil {
		childSetupFailure("bad %s=%q: %v", probeChildSockFD, sockStr, err)
	}

	prog, err := buildProbeFilterBytes()
	if err != nil {
		childSetupFailure("build filter: %v", err)
	}

	// loadRawFilter sets PR_SET_NO_NEW_PRIVS internally (see
	// seccomp_load_linux.go:121) before invoking seccomp(2), so a
	// non-root probe child can install the filter without CAP_SYS_ADMIN.
	notifyFD, err := loadRawFilter(prog, true)
	if err != nil {
		childSetupFailure("install filter: %v", err)
	}

	// Hand notifyFD to the parent.
	if err := sendProbeFD(sockFD, notifyFD); err != nil {
		childSetupFailure("send fd: %v", err)
	}
	_ = unix.Close(notifyFD)
	_ = unix.Close(sockFD)

	// Exec /bin/true to fire the post-execve syscall storm under the
	// installed filter. Try /bin/true first; if Exec itself fails (not
	// just a stat-miss — also covers e.g. /bin/true existing but being
	// non-executable), fall back to /bin/echo. Only after both fail do
	// we treat this as a setup failure.
	candidates := []string{probeBinaryPath, "/bin/echo"}
	var lastErr error
	for _, bin := range candidates {
		if _, statErr := os.Stat(bin); statErr != nil {
			lastErr = statErr
			continue
		}
		// syscall.Exec only returns on failure.
		lastErr = syscall.Exec(bin, []string{bin}, []string{})
	}
	childSetupFailure("exec failed: %v", lastErr)
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

	// Apply a recv timeout to parentSock so a hung child (stuck inside
	// loadRawFilter or before reaching sendProbeFD) cannot wedge the
	// parent. Set BEFORE cmd.Start so the guard is in place from the
	// instant the child can begin executing — there's no race window
	// where a wedged child could outrace SO_RCVTIMEO application.
	// The per-iteration 1-second timer below only arms after
	// recvProbeFD returns, so without this the failure mode would be
	// "parent hangs forever". SO_RCVTIMEO causes Recvmsg to return
	// EAGAIN/EWOULDBLOCK when the timeout fires.
	tv := unix.NsecToTimeval(probeRecvTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(parentSock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		// Non-fatal: log and continue. Worst case we lose the
		// guard but keep the rest of the iteration.
		slog.Debug("wait_killable probe: SO_RCVTIMEO failed", "error", err)
	}

	// Wrap childSock immediately so the *os.File owns the fd: cmd.Start
	// dups it into the child as fd 3, and we close our end via
	// childFile.Close() (which clears the runtime finalizer). Calling
	// unix.Close(childSock) directly would double-close once the
	// finalizer ran, potentially nuking an unrelated fd.
	//
	// We do NOT defer childFile.Close(): the recvProbeFD path requires
	// the parent's copy of the child socket to be CLOSED so the kernel
	// can signal EOF if the child dies before sending. We close
	// explicitly immediately after cmd.Start() succeeds and rely on a
	// `closed` guard for the failure paths.
	childFile := os.NewFile(uintptr(childSock), "probe-sock")
	childFileClosed := false
	closeChild := func() {
		if !childFileClosed {
			_ = childFile.Close()
			childFileClosed = true
		}
	}
	defer closeChild()

	binaryPath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("os.Executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	// argv[1] sentinel + per-invocation random env token form a
	// two-factor gate for probe-child mode (see isProbeChildInvocation).
	cmd.Args = buildProbeChildArgv(binaryPath)
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
	// The fd was duped into the child; close our end immediately so
	// the kernel can signal EOF on parentSock if the child dies
	// before reaching sendProbeFD. Without this, recvProbeFD would
	// block indefinitely on an early child crash because we'd still
	// be a writer on the socketpair.
	closeChild()

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
// in the error returns for the setup-failure and unclassified cases.
//
// Exit-status decoding:
//   - nil error                  → IterPass
//   - WIFSIGNALED                → IterKilled (kernel bug suspect)
//   - WIFEXITED status=71        → error (probe child setup failed before
//     reaching exec; the kernel was never exercised, so reporting
//     IterKilled would silently disable wait_killable on broken hosts)
//   - WIFEXITED status=70        → error (runProbeChild returned past
//     the exec call; shouldn't happen but treat as setup failure)
//   - WIFEXITED other non-zero   → IterKilled (post-exec child exited
//     non-zero, e.g. /bin/true returned 1 because the syscall storm
//     was disrupted — counts as a kernel-bug hit)
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
			if ws.Exited() {
				switch ws.ExitStatus() {
				case probeExitSetupFailure, probeExitFallback:
					return 0, fmt.Errorf("wait_killable probe: child setup failed (exit %d, stderr: %q)", ws.ExitStatus(), childStderr)
				}
			}
			// Non-signaled exit that did not match a known
			// setup-failure code. In the current design the child
			// only exits via childSetupFailure (status 71), the
			// init() fallback (status 70), or by exec'ing
			// /bin/true|echo (status 0 on success → caught by
			// `err == nil` above). So this branch in practice
			// catches /bin/true returning non-zero (which would
			// be unusual but possible if the post-execve syscall
			// storm disrupted it) or /bin/echo returning non-zero.
			// Treat as a kernel-bug-style failure.
			//
			// NOTE: any future addition of a non-setup-failure
			// os.Exit path in the child MUST update the switch
			// above; the compiler cannot enforce this.
			if childStderr != "" {
				slog.Debug("wait_killable probe: child exited non-zero", "stderr", childStderr)
			}
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
