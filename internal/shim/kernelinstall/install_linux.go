//go:build linux

package kernelinstall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/envinject"
	"github.com/agentsh/agentsh/internal/wrapenv"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

const wrapInitTimeout = 10 * time.Second

var notifySetupStatusTimeout = 30 * time.Second

// signalSockFDKey is the env var that the CLI injects for the signal filter
// socketpair fd.  The shim does NOT replicate the signal-filter second
// socketpair (documented limitation: signal-filter is not supported in
// shim mode), so we strip this key from WrapperEnv to avoid confusing the
// wrapper binary.
const signalSockFDKey = "AGENTSH_SIGNAL_SOCK_FD"

// argv0EnvKey is the env var the shim injects so unixwrap preserves the
// caller's original invocation name as argv[0] when execve'ing the real
// shell. Stripped from inherited env so a stale value from a re-entrant
// invocation (or operator-set value) cannot leak through and contradict
// the InstallParams.Argv0=="" "no override" contract — only the value we
// append in runRelay is honored.
const argv0EnvKey = "AGENTSH_UNIXWRAP_ARGV0"

// seccompFilterCount returns the number of seccomp filters already
// installed on the calling process, parsed from /proc/self/status's
// `Seccomp_filters:` line. Returns 0 on any read/parse error.
//
// Indirection via package var lets tests simulate the
// inherited-filter state without forking a real child with a live
// filter (which would also pollute the Go test runner's seccomp state
// and break unrelated tests). Production calls
// readKernelSeccompFilterCount, which is the only path that reads
// /proc.
var seccompFilterCount = readKernelSeccompFilterCount

// readKernelSeccompFilterCount reads /proc/self/status and returns the
// integer value of the Seccomp_filters: line (added in kernel 4.10).
// The kernel reports this field unconditionally when seccomp is
// compiled in — non-zero means at least one filter is already attached
// to this task or inherited via execve. We treat any read or parse
// failure as zero (best-effort): the gate is a defense-in-depth check,
// not a security boundary.
func readKernelSeccompFilterCount() int {
	const key = "Seccomp_filters:"
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, raw := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(raw, key) {
			continue
		}
		v := strings.TrimSpace(raw[len(key):])
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// Install is the all-in-one entry point that the shim calls before launching
// the user's command.  It:
//
//  1. Returns ResultSkip immediately when Mode == ModeOff.
//  2. Returns ResultSkip when the calling process already has a seccomp
//     filter inherited (any Mode), because trying to install another
//     filter on top of an inherited one fails on some kernels/runtimes
//     (issue #282 EFAULT on Runloop kernel 6.18.5: nested
//     `agentsh-shell-shim` invocation inside a process tree where
//     `agentsh-unixwrap` already installed F1). The inherited filter is
//     unforgeable evidence that policy enforcement is already active —
//     re-installing would be redundant at best, and on hostile kernels
//     the second `seccomp(SECCOMP_SET_MODE_FILTER, ...)` call rejects
//     the program with EFAULT and breaks every wrapped exec. ModeOn
//     "fail-closed" is satisfied here because we ARE filtered, just not
//     by us.
//  3. Calls wrap-init via the agentsh server to get a wrapper binary + socket.
//  4. On failure, fails closed (ModeOn) or skips (ModeAuto).
//  5. Runs the socketpair relay: mirrors internal/cli/wrap_linux.go
//     platformSetupWrap, minus the signal-filter second socketpair.
//  6. Returns ResultExec carrying the exit code from the wrapper process.
func Install(p InstallParams) (Result, error) {
	// Step 1: mode gate
	if p.Mode == ModeOff {
		return Result{Action: ResultSkip, Reason: "mode=off"}, nil
	}

	// Step 2: inherited-filter gate (#282). Unforgeable: the kernel
	// itself reports the live filter chain count via /proc/self/status,
	// regardless of any caller-controlled env var.
	if n := seccompFilterCount(); n > 0 {
		return Result{
			Action: ResultSkip,
			Reason: fmt.Sprintf("already filtered (Seccomp_filters=%d, inherited from parent)", n),
		}, nil
	}

	// Step 3: call wrap-init
	resp, err := callWrapInit(p)
	if err != nil {
		reason := fmt.Sprintf("wrap-init failed: %v", err)
		if p.Mode == ModeOn {
			return Result{Action: ResultFailClosed, Reason: reason}, nil
		}
		// ModeAuto: fall through silently
		slog.Debug("kernelinstall: wrap-init error, skipping (mode=auto)", "error", err)
		return Result{Action: ResultSkip, Reason: reason}, nil
	}

	// Step 4: check response completeness
	if resp.WrapperBinary == "" || resp.NotifySocket == "" {
		reason := "wrap-init returned empty WrapperBinary or NotifySocket"
		if p.Mode == ModeOn {
			return Result{Action: ResultFailClosed, Reason: reason}, nil
		}
		return Result{Action: ResultSkip, Reason: reason}, nil
	}

	// Step 5–6: socketpair relay
	return runRelay(p, resp)
}

// callWrapInit contacts the agentsh server and returns its WrapInitResponse.
func callWrapInit(p InstallParams) (types.WrapInitResponse, error) {
	c, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL:   p.ServerBaseURL,
		APIKey:        p.APIKey,
		ClientTimeout: wrapInitTimeout,
	})
	if err != nil {
		return types.WrapInitResponse{}, fmt.Errorf("build client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), wrapInitTimeout)
	defer cancel()

	req := types.WrapInitRequest{
		AgentCommand: p.RealShell,
		AgentArgs:    p.ShellArgs,
		CallerUID:    p.CallerUID,
		Mode:         "shim",
	}
	return c.WrapInit(ctx, p.SessionID, req)
}

// runRelay creates the notify socketpair, launches the wrapper binary, then
// receives the seccomp notify fd from the wrapper and forwards it to the
// server's Unix socket.  This mirrors platformSetupWrap in
// internal/cli/wrap_linux.go, with the signal-filter second socketpair
// intentionally omitted (documented shim-mode limitation).
func runRelay(p InstallParams, resp types.WrapInitResponse) (Result, error) {
	wrapperBin := resp.WrapperBinary
	notifySocket := resp.NotifySocket

	// Create AF_UNIX SOCK_SEQPACKET socketpair.
	// fds[0] = parent end (we read the notify fd from the wrapper here)
	// fds[1] = child end (inherited by the wrapper as fd 3)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return Result{}, fmt.Errorf("socketpair: %w", err)
	}

	parentFile := os.NewFile(uintptr(fds[0]), "notify-parent")
	childFile := os.NewFile(uintptr(fds[1]), "notify-child")

	// Clear CLOEXEC on the child fd so it survives exec into the wrapper.
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fds[1]), unix.F_SETFD, 0); errno != 0 {
		parentFile.Close()
		childFile.Close()
		return Result{}, fmt.Errorf("fcntl clear cloexec: %w", errno)
	}

	// Build the wrapper child environment: caller env (shim-internal markers
	// stripped) with sandbox.env_inject overlaid, then the internal AGENTSH_*
	// markers (notify fd, argv0 override, wrapper config). See
	// assembleWrapperEnv for the env_inject override and AGENTSH_SIGNAL_SOCK_FD
	// stripping rationale (issue #374).
	env := assembleWrapperEnv(wrapenv.Filter(filterShimInternalEnv(p.Env), resp.EnvPolicy), p.Argv0, resp.WrapperEnv, resp.EnvInject)

	// Build wrapper argv: wrapperBin -- realShell shellArgs...
	// argv[0] is the wrapper binary's basename (conventional).
	wrapperArgs := make([]string, 0, 2+len(p.ShellArgs))
	wrapperArgs = append(wrapperArgs, "--")
	wrapperArgs = append(wrapperArgs, p.RealShell)
	wrapperArgs = append(wrapperArgs, p.ShellArgs...)

	cmd := exec.Command(wrapperBin, wrapperArgs...)
	cmd.Args[0] = filepath.Base(wrapperBin)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// ExtraFiles[0] becomes fd 3 in the child (0=stdin,1=stdout,2=stderr,3=ExtraFiles[0])
	cmd.ExtraFiles = []*os.File{childFile}

	if err := cmd.Start(); err != nil {
		parentFile.Close()
		childFile.Close()
		return Result{}, fmt.Errorf("start wrapper: %w", err)
	}

	// The wrapper owns childFile now; close our copy in the parent.
	childFile.Close()

	// Receive the seccomp notify fd from the wrapper via SCM_RIGHTS.
	notifyFD, recvErr := recvNotifyFD(parentFile)
	if recvErr != nil {
		// Wrapper may have exited before sending the fd (e.g. setup failure).
		// Wait for it, propagate its exit code.
		exitCode := waitWrapper(cmd)
		parentFile.Close()
		return Result{
			Action:          ResultExec,
			ExecPath:        wrapperBin,
			ExecArgs:        cmd.Args,
			ExecEnv:         env,
			WrapperExitCode: exitCode,
			Reason:          fmt.Sprintf("recvmsg failed (wrapper exit %d): %v", exitCode, recvErr),
		}, nil
	}

	// Forward the notify fd to the server's Unix listener socket.
	// IMPORTANT: if forwarding fails, do NOT send the ACK.  Sending the ACK
	// would let the wrapper execve the user's command with no live policy
	// handler — a silent enforcement bypass.  Instead close the parent fd so
	// the wrapper's waitForACK read returns EOF/error, causing the wrapper to
	// exit with a fatal log.  Then wait for the wrapper and return
	// ResultFailClosed so the shim aborts rather than running the command.
	if fwdErr := forwardNotifyFDWithPID(notifySocket, notifyFD, cmd.Process.Pid); fwdErr != nil {
		unix.Close(notifyFD)
		slog.Error("kernelinstall: failed to forward notify fd — closing parent fd to abort wrapper", "error", fwdErr)
		// Close parentFile: wrapper's waitForACK will see EOF/EBADF and fatal.
		parentFile.Close()
		exitCode := waitWrapper(cmd)
		_ = exitCode // wrapper exited due to our close; use ResultFailClosed
		return Result{
			Action: ResultFailClosed,
			Reason: fmt.Sprintf("forward notify fd failed: %v", fwdErr),
		}, nil
	}
	unix.Close(notifyFD)

	// Send ACK byte (0x01) to the wrapper so it knows the handler is ready
	// before it executes the user's command.  This prevents a race where the
	// wrapper execs before the server's seccomp notify handler is up.
	if _, err := parentFile.Write([]byte{1}); err != nil {
		slog.Debug("kernelinstall: ACK write failed (wrapper may have exited)", "error", err)
	}
	parentFile.Close()

	// Wait for the wrapper to finish.
	exitCode := waitWrapper(cmd)

	return Result{
		Action:          ResultExec,
		ExecPath:        wrapperBin,
		ExecArgs:        cmd.Args,
		ExecEnv:         env,
		WrapperExitCode: exitCode,
	}, nil
}

// waitWrapper calls cmd.Wait and extracts the exit code.
func waitWrapper(cmd *exec.Cmd) int {
	err := cmd.Wait()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}

// recvNotifyFD receives a file descriptor from a Unix socket using SCM_RIGHTS.
// Mirrors internal/cli/wrap_linux.go recvNotifyFD.
func recvNotifyFD(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return -1, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse control message: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no fd in control message")
}

// forwardNotifyFDWithPID connects to the server's Unix listener socket, sends
// the notify fd plus wrapper PID metadata, and waits for server setup status.
func forwardNotifyFDWithPID(socketPath string, notifyFD int, wrapperPID int) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	if err := wraphandoff.SendNotifyFD(unixConn, notifyFD, wraphandoff.Metadata{WrapperPID: wrapperPID}); err != nil {
		return err
	}
	if err := unixConn.SetReadDeadline(time.Now().Add(notifySetupStatusTimeout)); err != nil {
		return fmt.Errorf("set notify setup status deadline: %w", err)
	}
	if err := wraphandoff.ReadStatus(unixConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("timed out waiting for notify setup status after %s: %w", notifySetupStatusTimeout, err)
		}
		return fmt.Errorf("read notify setup status: %w", err)
	}
	return nil
}

// filterSignalSockFD returns a copy of env with AGENTSH_SIGNAL_SOCK_FD
// entries removed.  Used by tests that need to verify the strip behavior
// without going through the full relay.
func filterSignalSockFD(env []string) []string {
	out := make([]string, 0, len(env))
	prefix := signalSockFDKey + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// filterShimInternalEnv returns a copy of env with all internal env vars
// (AGENTSH_SIGNAL_SOCK_FD, AGENTSH_UNIXWRAP_ARGV0) removed. The signal
// fd is stripped because shim mode does not replicate the signal-filter
// socketpair, so a stale value would point the wrapper at a non-existent
// fd. The argv0 override is stripped because we always append the
// authoritative value (or omit it entirely when InstallParams.Argv0 is
// empty); a stale inherited value from a re-entrant invocation would
// otherwise silently win on Argv0=="" and contradict the documented
// "empty falls back to the resolved real path" contract.
// assembleWrapperEnv builds the environment for the agentsh-unixwrap child.
// base is the caller environment with shim-internal markers already stripped
// (filterShimInternalEnv). envInject overlays operator-configured
// sandbox.env_inject values with override semantics — injected values win over
// inherited ones, matching the server-spawned exec path (issue #374). The
// internal AGENTSH_* markers (notify fd, argv0 override, wrapper config) are
// appended afterward and remain authoritative. AGENTSH_SIGNAL_SOCK_FD from
// wrapperEnv is dropped: shim mode does not replicate the signal-filter
// socketpair, so the wrapper must not try to open that fd.
func assembleWrapperEnv(base []string, argv0 string, wrapperEnv, envInject map[string]string) []string {
	// Copy so appends never alias the caller's backing array (Apply may
	// return base unchanged when envInject is empty).
	env := append([]string(nil), envinject.Apply(base, envInject)...)
	env = append(env, "AGENTSH_NOTIFY_SOCK_FD=3")
	// Plumb the original invocation name (e.g. "/bin/sh") through to the
	// wrapper so it can override argv[0] when execve'ing the real shell.
	// On Alpine, /bin/sh.real is a busybox binary; without this override,
	// busybox derives applet name "sh.real" → "applet not found" → exit
	// 127. The wrapper falls back to its os.Args[2] (the real shell path)
	// when this is empty, which is correct on non-busybox systems.
	if argv0 != "" {
		env = append(env, fmt.Sprintf("%s=%s", argv0EnvKey, argv0))
	}
	for k, v := range wrapperEnv {
		if k == signalSockFDKey {
			slog.Debug("kernelinstall: stripping signal sock fd from wrapper env (shim mode limitation)")
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

func filterShimInternalEnv(env []string) []string {
	out := make([]string, 0, len(env))
	signalPrefix := signalSockFDKey + "="
	argv0Prefix := argv0EnvKey + "="
	for _, e := range env {
		if strings.HasPrefix(e, signalPrefix) || strings.HasPrefix(e, argv0Prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
