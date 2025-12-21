// agentsh-unixwrap: installs seccomp user-notify for AF_UNIX sockets, sends notify fd
// to the server over an inherited socketpair (SCM_RIGHTS), then execs the target command.
// Usage: agentsh-unixwrap -- <command> [args...]
// Requires env AGENTSH_NOTIFY_SOCK_FD set to the fd number of the socketpair to the server.
// If seccomp user-notify is unsupported, exits 0 with a message (server should treat as monitor-only).

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
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

	// Install seccomp filter.
	filt, err := unixmon.InstallOrWarn()
	if err == unixmon.ErrUnsupported {
		log.Printf("seccomp user-notify unsupported; exiting 0 for monitor-only")
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("install seccomp filter: %v", err)
	}
	defer filt.Close()

	notifFD := filt.NotifFD()

	// Send notify fd to server over socketpair.
	if err := sendFD(sockFD, notifFD); err != nil {
		log.Fatalf("send fd: %v", err)
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
