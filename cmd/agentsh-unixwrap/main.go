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
	"strconv"
	"syscall"

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

	// Install signal filter if enabled.
	var sigFilter *signal.SignalFilter
	if cfg.SignalFilterEnabled {
		sigCfg := signal.DefaultSignalFilterConfig()
		sigFilter, err = signal.InstallSignalFilter(sigCfg)
		if err != nil {
			// Signal filter is optional - log and continue
			log.Printf("signal filter: %v (continuing without)", err)
		} else {
			defer sigFilter.Close()
			// Send signal notify fd to server
			sigFD := sigFilter.NotifFD()
			if sigFD >= 0 {
				if err := sendFD(sockFD, sigFD); err != nil {
					log.Fatalf("send signal fd: %v", err)
				}
			}
		}
	}

	_ = unix.Close(sockFD)

	// Exec the real command.
	cmd := os.Args[2]
	args := os.Args[2:]
	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
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

func sendFD(sock int, fd int) error {
	rights := unix.UnixRights(fd)
	// dummy payload
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}
