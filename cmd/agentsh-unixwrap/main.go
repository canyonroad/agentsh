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
	"os/exec"
	"strconv"
	"syscall"

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

	// Resolve syscall names to numbers.
	blockedNrs, skipped := seccompkg.ResolveSyscalls(cfg.BlockedSyscalls)
	if len(skipped) > 0 {
		log.Printf("warning: skipped unknown syscalls: %v", skipped)
	}

	// Build filter config.
	filterCfg := unixmon.FilterConfig{
		UnixSocketEnabled: cfg.UnixSocketEnabled,
		ExecveEnabled:     cfg.ExecveEnabled,
		BlockedSyscalls:   blockedNrs,
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

	// Send notify fd to server over socketpair (only if we have one).
	if notifFD >= 0 {
		if err := sendFD(sockFD, notifFD); err != nil {
			log.Fatalf("send fd: %v", err)
		}
	}

	// Close notify socket - we're done with it
	_ = unix.Close(sockFD)

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
	// Landlock enforces kernel-level filesystem access control that works even for root.
	if cfg.LandlockEnabled && cfg.LandlockABI > 0 {
		if err := applyLandlock(cfg); err != nil {
			log.Printf("landlock: %v (continuing without)", err)
		}
	}

	// Exec the real command.
	cmd := os.Args[2]
	// syscall.Exec requires an absolute path — resolve via PATH lookup.
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
	args := os.Args[2:]
	if err := syscall.Exec(cmdPath, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
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
