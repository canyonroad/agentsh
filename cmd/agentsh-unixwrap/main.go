//go:build linux && cgo
// +build linux,cgo

// agentsh-unixwrap: installs seccomp user-notify for AF_UNIX sockets, sends notify fd
// to the server over an inherited socketpair (SCM_RIGHTS), then execs the target command.
// Usage: agentsh-unixwrap -- <command> [args...]
// Requires env AGENTSH_NOTIFY_SOCK_FD set to the fd number of the socketpair to the server.
// If seccomp user-notify is unsupported, exits 0 with a message (server should treat as monitor-only).

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/agentsh/agentsh/internal/landlock"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/internal/signal"
	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 3 || os.Args[1] != "--" {
		log.Fatalf("usage: %s -- <command> [args...]", os.Args[0])
	}

	sockFD, err := notifySockFD()
	if err != nil {
		log.Fatalf("notify fd: %v", err)
	}

	// Load config from environment.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Authorize the server process to read our memory via ProcessVMReadv.
	// Under Yama ptrace_scope=1 (Ubuntu/Debian default), only ancestor
	// processes can use ProcessVMReadv. In the wrap path the server is NOT
	// our ancestor, so this prctl authorizes it specifically.
	// On kernels without Yama, PR_SET_PTRACER returns EINVAL — but it's
	// also unnecessary because standard Unix DAC governs ptrace.
	//
	// yamaActive is computed once and reused for setupPtracerPreload below
	// so we don't double-stat the sysctl path. The non-Yama path returns
	// silently — emitting a "skipping PR_SET_PTRACER" log here would add
	// noise on every wrapper invocation on most distros (issue #281).
	yamaActive := isYamaActive()
	if cfg.ServerPID > 0 && yamaActive {
		if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(cfg.ServerPID), 0, 0, 0); err != nil {
			log.Printf("PR_SET_PTRACER(%d): %v (Yama active, ProcessVMReadv may fail)", cfg.ServerPID, err)
		}
	}

	// Resolve syscall names to numbers.
	blockedNrs, skipped := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	// Pre-resolve the command path BEFORE installing the seccomp filter.
	// resolveCommandPath calls exec.LookPath which stats the candidate
	// (newfstatat) and may probe with faccessat2(X_OK). When
	// InterceptMetadata is enabled the to-be-installed seccomp filter
	// traps both syscalls via SECCOMP_RET_USER_NOTIF; the file-monitor
	// handler then asks the policy engine and DENIES paths the policy
	// has no rule for — including /bin/bash.real (the shim's renamed
	// real shell), surfacing as
	//   resolve command "/bin/bash.real": exec: ... permission denied
	// (#283 bug B). Resolving here, before the filter is installed,
	// keeps the path-resolution syscalls outside the notify scope.
	// syscall.Exec at the end is a single execve — that's governed
	// by the kernel's execve check independently and is filter-gated
	// only when cfg.ExecveEnabled is true.
	//
	// applyArgv0Override is also moved up so the argv slice is fully
	// computed before any filter setup happens; it only reads an env
	// var and reshuffles strings, no filesystem I/O, but co-locating
	// keeps the "all the exec arguments are ready" boundary clear.
	cmd := os.Args[2]
	cmdPath, err := resolveCommandPath(cmd)
	if err != nil {
		log.Fatalf("resolve command %q: %v", cmd, err)
	}
	args := applyArgv0Override(os.Args[2:], os.Getenv("AGENTSH_UNIXWRAP_ARGV0"))

	// Build filter config.
	onBlock, _ := seccompkg.ParseOnBlock(cfg.OnBlock)
	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled:  cfg.UnixSocketEnabled,
		ExecveEnabled:      cfg.ExecveEnabled,
		FileMonitorEnabled: cfg.FileMonitorEnabled,
		InterceptMetadata:  cfg.InterceptMetadata,
		WriteOnlyOpens:     cfg.WriteOnlyOpens,
		BlockIOUring:       cfg.BlockIOUring,
		BlockedSyscalls:    blockedNrs,
		BlockedFamilies:    cfg.BlockedFamilies,
		SocketRules:        cfg.SocketRules,
		OnBlockAction:      onBlock,
	}

	// Install seccomp filter.
	filt, err := unixmon.InstallFilterWithConfig(filterCfg)
	if errors.Is(err, unixmon.ErrUnsupported) {
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("install seccomp filter: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()

	// Probe that SECCOMP_IOCTL_NOTIF_RECV works on the notify fd.
	// Some container runtimes (e.g., AppArmor's containers-default profile)
	// allow filter installation but block the notification ioctl, causing all
	// intercepted syscalls to fail once the command is exec'd. Detect this
	// early and fail with a clear error instead of silently breaking.
	if notifFD >= 0 {
		if err := unixmon.ProbeNotifReceive(notifFD); err != nil {
			if cfg.FileMonitorEnabled || cfg.ExecveEnabled {
				// These features trap critical syscalls (openat, execve).
				// Without a working notification handler, the command cannot
				// function at all — fail fast with a clear error.
				filt.Close()
				log.Fatalf("seccomp notify handler cannot operate: %v\n"+
					"The seccomp filter was installed but the notification receive ioctl is\n"+
					"blocked (likely by AppArmor or container security policy). Without a\n"+
					"working notification handler, all intercepted syscalls will fail.\n"+
					"Fix: set 'sandbox.seccomp.file_monitor.enabled: false' in your config,\n"+
					"or adjust the container's security profile to allow seccomp notify ioctls.", err)
			}
			// Only unix_sockets / metadata monitoring is enabled. The intercepted
			// syscalls (socket, connect, bind, etc.) are not critical for most
			// commands. Warn and proceed — socket monitoring will be degraded but
			// the command can still run.
			log.Printf("WARNING: seccomp notify probe failed (%v); unix socket monitoring degraded", err)
		}
	}

	// Send notify fd to server over socketpair and wait for ACK (only if we
	// actually have a notify fd to send). When all seccomp features are disabled
	// the filter returns fd=-1 and there is nothing to hand off.
	if notifFD >= 0 {
		if err := sendFD(sockFD, notifFD); err != nil {
			log.Fatalf("send fd: %v", err)
		}

		// Wait for ACK from the server confirming it has received the notify fd
		// and started the handler. This prevents a race where we exec before the
		// handler is ready to process seccomp notifications.
		if err := waitForACK(func(b []byte) (int, error) { return unix.Read(sockFD, b) }); err != nil {
			log.Fatalf("ACK handshake failed: %v", err)
		}
	}

	// Install signal filter if enabled and we have a signal socket
	sigSockFD, _ := signalSockFD()
	if cfg.SignalFilterEnabled && sigSockFD >= 0 {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err := signal.InstallSignalFilter(sigCfg)
		if err != nil {
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(sigSockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
		_ = unix.Close(sigSockFD)
	}

	// Apply Landlock filesystem restrictions before exec.
	if cfg.LandlockEnabled && cfg.LandlockABI > 0 {
		if err := applyLandlock(cfg); err != nil {
			log.Printf("landlock: %v (continuing without)", err)
		}
	}

	// Ptrace sync handshake: when the server will attach ptrace after our
	// seccomp setup, we signal READY and wait for GO before exec. This
	// prevents ptrace from interfering with seccomp filter installation.
	// Only runs when notifFD >= 0 (seccomp is active) and AGENTSH_PTRACE_SYNC=1.
	if notifFD >= 0 && os.Getenv("AGENTSH_PTRACE_SYNC") == "1" {
		if _, err := unix.Write(sockFD, []byte{'R'}); err != nil {
			log.Fatalf("send READY byte: %v", err)
		}
		// Set 30s receive timeout to prevent hanging if server crashes.
		_ = unix.SetsockoptTimeval(sockFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
		// Wait for GO byte, retrying on EINTR. Validate the byte value.
		goBuf := make([]byte, 1)
		if err := waitForACK(func(b []byte) (int, error) {
			n, err := unix.Read(sockFD, b)
			if n == 1 {
				goBuf[0] = b[0]
			}
			return n, err
		}); err != nil {
			log.Fatalf("wait for GO byte (30s timeout): %v", err)
		}
		if goBuf[0] != 'G' {
			log.Fatalf("unexpected GO byte: got 0x%02x, expected 'G'", goBuf[0])
		}
	}

	// Close notify socket - done with all handshakes
	_ = unix.Close(sockFD)

	// Set up LD_PRELOAD for the ptracer library so that child processes
	// call PR_SET_PTRACER(server_pid). Without this, ProcessVMReadv fails
	// for children under Yama ptrace_scope=1, breaking seccomp path resolution.
	// Only needed when seccomp notify is active (notifFD >= 0) AND Yama is
	// active — on non-Yama kernels the LD_PRELOAD is irrelevant and would
	// only emit confusing "ptracer: lib not found" noise (issue #281).
	if notifFD >= 0 {
		setupPtracerPreload(cfg.ServerPID, yamaActive)
	}

	// Block SIGURG on this OS thread to prevent Go's ~10ms async preemption
	// from interrupting seccomp_do_user_notification during execve.
	// Only needed when seccomp user-notify is active — without a filter,
	// there is no notification wait to protect.
	//
	// Note: the blocked SIGURG mask is inherited across execve. For most
	// programs this is harmless (SIGURG is rarely used). For wrapped Go
	// binaries, async preemption degrades to cooperative preemption — a
	// minor performance trade-off vs. the 0% success rate caused by the
	// ERESTARTSYS loop this prevents. On kernel 6.0+ the SetWaitKill flag
	// (Layer 1) handles this at the kernel level without signal mask changes.
	if notifFD >= 0 {
		runtime.LockOSThread()
		blockSIGURG()
	}

	// Exec the real command. cmdPath and args were pre-resolved at the
	// top of main(), before the seccomp filter was installed, so
	// resolveCommandPath's exec.LookPath probes (newfstatat /
	// faccessat2 — see #283 bug B) do not get intercepted by the
	// file-monitor notify handler.
	if err := syscall.Exec(cmdPath, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}

// applyArgv0Override returns the argv slice to pass to syscall.Exec,
// substituting argv[0] with override when override is non-empty (after
// trimming whitespace). The shim sets AGENTSH_UNIXWRAP_ARGV0 so
// busybox-multicall binaries (Alpine /bin/sh, BusyBox /bin/bash on some
// systems) see the original invocation name (e.g. "/bin/sh") instead of
// the renamed "/bin/sh.real" — busybox uses argv[0] basename to pick
// its applet, and "sh.real" is not a known applet, so without the
// override the exec exits 127 with "applet not found". An empty or
// whitespace-only value preserves the previous behaviour (argv[0]
// = the resolved real path).
//
// Returns rawArgs unchanged when len(rawArgs) == 0; the call site
// guards via the `len(os.Args) < 3` check, but the explicit zero-arg
// guard makes the helper safe against future re-use.
func applyArgv0Override(rawArgs []string, override string) []string {
	if len(rawArgs) == 0 {
		return rawArgs
	}
	if override = strings.TrimSpace(override); override == "" {
		return rawArgs
	}
	out := make([]string, len(rawArgs))
	out[0] = override
	copy(out[1:], rawArgs[1:])
	return out
}

func notifySockFD() (int, error) {
	val := os.Getenv("AGENTSH_NOTIFY_SOCK_FD")
	if val == "" {
		return 0, fmt.Errorf("AGENTSH_NOTIFY_SOCK_FD not set")
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid AGENTSH_NOTIFY_SOCK_FD=%q", val)
	}
	return n, nil
}

func signalSockFD() (int, error) {
	val := os.Getenv("AGENTSH_SIGNAL_SOCK_FD")
	if val == "" {
		return -1, nil // Signal socket not configured
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return -1, fmt.Errorf("invalid AGENTSH_SIGNAL_SOCK_FD=%q", val)
	}
	return n, nil
}

func sendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	// dummy payload
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

// waitForACK blocks until a single ACK byte is received via the provided read
// function. It retries on EINTR (signal interruption) and fails on any other
// error or unexpected byte count. The readFn abstraction enables deterministic
// testing of the EINTR retry path.
func waitForACK(readFn func([]byte) (int, error)) error {
	buf := make([]byte, 1)
	for {
		n, err := readFn(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		if n != 1 {
			return fmt.Errorf("expected 1 ACK byte, got %d (server may have closed connection)", n)
		}
		return nil
	}
}

// blockSIGURG blocks SIGURG on the current OS thread via rt_sigprocmask.
// Go's runtime sends SIGURG every ~10ms for goroutine preemption. When execve
// is trapped by seccomp user-notify, the kernel waits in
// wait_for_completion_interruptible(), which is woken by ANY signal. SIGURG
// causes ERESTARTSYS → stale notification ID → infinite retry loop.
//
// Must be called after runtime.LockOSThread() to ensure the mask change
// applies to the thread that will call syscall.Exec().
func blockSIGURG() {
	var set [1]uint64
	set[0] = 1 << (unix.SIGURG - 1)
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_BLOCK),
		uintptr(unsafe.Pointer(&set[0])),
		0, // oldset = nil
		8, // sizeof(sigset_t)
		0, 0,
	)
	if errno != 0 {
		log.Printf("warning: blockSIGURG: rt_sigprocmask: %v", errno)
	}
}

func applyLandlock(cfg *WrapperConfig) error {
	builder := landlock.NewRulesetBuilder(cfg.LandlockABI)

	if cfg.Workspace != "" {
		builder.SetWorkspace(cfg.Workspace)
	}

	// Allow network by default — agentsh proxy handles network policy.
	// Without this, Landlock ABI v4+ blocks ALL TCP connections.
	builder.SetNetworkAccess(cfg.AllowNetwork, cfg.AllowBind)

	for _, p := range cfg.AllowExecute {
		_ = builder.AddExecutePath(p)
	}
	for _, p := range cfg.AllowRead {
		_ = builder.AddReadPath(p)
	}
	for _, p := range cfg.AllowWrite {
		_ = builder.AddWritePath(p)
	}
	for _, p := range cfg.DenyPaths {
		builder.AddDenyPath(p)
	}

	rulesetFd, err := builder.Build()
	if err != nil {
		return fmt.Errorf("build ruleset: %w", err)
	}
	defer unix.Close(rulesetFd)

	if err := landlock.Enforce(rulesetFd); err != nil {
		return fmt.Errorf("enforce: %w", err)
	}

	log.Printf("landlock: restrictions applied (abi=%d, workspace=%s)", cfg.LandlockABI, cfg.Workspace)
	return nil
}
