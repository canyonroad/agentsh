//go:build linux

package ptrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
)

// parseSockaddr parses a raw sockaddr buffer into family, address, and port.
func parseSockaddr(buf []byte) (family int, address string, port int, err error) {
	if len(buf) < 2 {
		return 0, "", 0, fmt.Errorf("sockaddr too short: %d bytes", len(buf))
	}

	family = int(binary.NativeEndian.Uint16(buf[0:2]))

	switch family {
	case unix.AF_UNSPEC:
		// AF_UNSPEC is used with connect() to "disconnect" datagram sockets.
		return family, "", 0, nil

	case unix.AF_INET:
		if len(buf) < 8 {
			return family, "", 0, fmt.Errorf("sockaddr_in too short: %d bytes", len(buf))
		}
		port = int(binary.BigEndian.Uint16(buf[2:4]))
		ip := net.IP(buf[4:8])
		return family, ip.String(), port, nil

	case unix.AF_INET6:
		if len(buf) < 24 {
			return family, "", 0, fmt.Errorf("sockaddr_in6 too short: %d bytes", len(buf))
		}
		port = int(binary.BigEndian.Uint16(buf[2:4]))
		ip := net.IP(buf[8:24])
		addr := ip.String()
		// Include scope_id for link-local addresses if present.
		if len(buf) >= 28 {
			scopeID := binary.NativeEndian.Uint32(buf[24:28])
			if scopeID != 0 {
				addr = fmt.Sprintf("%s%%%d", addr, scopeID)
			}
		}
		return family, addr, port, nil

	case unix.AF_UNIX:
		if len(buf) <= 2 {
			return family, "", 0, nil
		}
		pathBytes := buf[2:]
		if pathBytes[0] == 0 {
			// Abstract socket: all bytes after the leading NUL are the name,
			// including any embedded or trailing NUL bytes.
			name := string(pathBytes[1:])
			return family, "@" + name, 0, nil
		}
		if idx := bytes.IndexByte(pathBytes, 0); idx >= 0 {
			pathBytes = pathBytes[:idx]
		}
		return family, string(pathBytes), 0, nil

	default:
		// Unknown family — pass to handler with family only and let policy decide.
		return family, "", 0, nil
	}
}

// handleNetwork intercepts network syscalls for policy evaluation.
func (t *Tracer) handleNetwork(ctx context.Context, tid int, regs Regs) {
	if t.cfg.NetworkHandler == nil || !t.cfg.TraceNetwork {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()

	// Only evaluate policy for connect and bind
	if nr != unix.SYS_CONNECT && nr != unix.SYS_BIND {
		t.allowSyscall(tid)
		return
	}

	// Args: sockfd(arg0), addr(arg1), addrlen(arg2)
	addrPtr := regs.Arg(1)
	rawLen := regs.Arg(2)

	if rawLen == 0 || rawLen > 128 {
		slog.Warn("handleNetwork: addrlen out of range, denying", "tid", tid, "addrlen", rawLen)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	addrLen := int(rawLen)

	buf := make([]byte, addrLen)
	if err := t.readBytes(tid, addrPtr, buf); err != nil {
		slog.Warn("handleNetwork: cannot read sockaddr, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	family, address, port, err := parseSockaddr(buf)
	if err != nil {
		slog.Warn("handleNetwork: cannot parse sockaddr, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	var operation string
	if nr == unix.SYS_CONNECT {
		operation = "connect"
	} else {
		operation = "bind"
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	result := t.cfg.NetworkHandler.HandleNetwork(ctx, NetworkContext{
		PID:       tgid,
		SessionID: sessionID,
		Syscall:   nr,
		Family:    family,
		Address:   address,
		Port:      port,
		Operation: operation,
	})

	// Dispatch based on Action field (new path) or Allow field (legacy path).
	action := result.Action
	if action == "" {
		if result.Allow {
			action = "allow"
		} else {
			action = "deny"
		}
	}

	switch action {
	case "allow", "continue":
		t.allowSyscall(tid)
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	case "redirect":
		t.redirectConnect(ctx, tid, regs, result)
	default:
		slog.Warn("handleNetwork: unknown action, denying", "tid", tid, "action", action)
		t.denySyscall(tid, int(unix.EACCES))
	}
}
