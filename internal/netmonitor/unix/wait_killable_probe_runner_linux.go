//go:build linux && cgo
// +build linux,cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	probeChildEnv    = "AGENTSH_WAIT_KILLABLE_PROBE_CHILD"
	probeChildSockFD = "AGENTSH_WAIT_KILLABLE_PROBE_SOCK"
	probeBinaryPath  = "/bin/true"
)

// init wires the production runner and detects probe-child mode. When
// invoked as a probe child the process never returns: it either execs
// /bin/true (success path) or os.Exit(70)s. Otherwise it just installs
// realRunProbeIteration over the placeholder from
// wait_killable_probe_linux.go.
func init() {
	if os.Getenv(probeChildEnv) == "1" {
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

	binaryPath, err := os.Executable()
	if err != nil {
		unix.Close(childSock)
		return 0, fmt.Errorf("os.Executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = []string{
		probeChildEnv + "=1",
		probeChildSockFD + "=3", // ExtraFiles index 0 = fd 3
	}
	cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(childSock), "probe-sock")}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		unix.Close(childSock)
		return 0, fmt.Errorf("start probe child: %w", err)
	}
	// The fd was duped into the child; close our end.
	_ = unix.Close(childSock)

	notifyFD, err := recvProbeFD(parentSock)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("recv probe fd: %w", err)
	}
	defer unix.Close(notifyFD)

	// Service notifications until the child exits.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	serviceCtx, serviceCancel := context.WithCancel(ctx)
	defer serviceCancel()
	go serviceProbeNotifications(serviceCtx, notifyFD)

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()

	select {
	case err := <-done:
		serviceCancel()
		return classifyProbeExit(err)
	case <-timeout.C:
		serviceCancel()
		_ = cmd.Process.Kill()
		<-done
		return IterTimeout, nil
	}
}

// serviceProbeNotifications drains the notify fd and responds CONTINUE
// to every notification until ctx is cancelled or the fd errors.
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
func classifyProbeExit(err error) (IterationResult, error) {
	if err == nil {
		return IterPass, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return IterKilled, nil
			}
			if ws.Exited() && ws.ExitStatus() == 0 {
				return IterPass, nil
			}
			return IterKilled, nil
		}
	}
	return 0, fmt.Errorf("wait_killable probe: unclassified exit: %w", err)
}
