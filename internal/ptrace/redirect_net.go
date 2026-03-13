//go:build linux

package ptrace

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
)

// redirectConnect redirects a connect() syscall to a different address/port
// by overwriting the sockaddr in tracee memory.
func (t *Tracer) redirectConnect(ctx context.Context, tid int, regs Regs, result NetworkResult) {
	if result.RedirectAddr == "" && result.RedirectPort == 0 {
		slog.Warn("redirectConnect: no redirect target, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	if result.RedirectPort < 0 || result.RedirectPort > 65535 {
		slog.Warn("redirectConnect: invalid redirect port, denying",
			"tid", tid, "port", result.RedirectPort)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	addrPtr := regs.Arg(1)
	addrLen := int(regs.Arg(2))
	if addrLen == 0 || addrLen > 128 {
		slog.Warn("redirectConnect: invalid addrlen, denying", "tid", tid, "addrlen", addrLen)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	buf := make([]byte, addrLen)
	if err := t.readBytes(tid, addrPtr, buf); err != nil {
		slog.Warn("redirectConnect: read sockaddr failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	if len(buf) < 2 {
		slog.Warn("redirectConnect: sockaddr too short, denying", "tid", tid)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	family := int(binary.NativeEndian.Uint16(buf[0:2]))

	// Parse redirect address — must be a literal IP. DNS resolution in the
	// ptrace stop path would block the tracer loop and stall all tracees.
	var redirectIP net.IP
	if result.RedirectAddr != "" {
		redirectIP = net.ParseIP(result.RedirectAddr)
		if redirectIP == nil {
			slog.Warn("redirectConnect: redirect addr is not a literal IP, denying",
				"tid", tid, "addr", result.RedirectAddr)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}
	}

	var newBuf []byte

	switch family {
	case unix.AF_INET:
		if len(buf) < 8 {
			slog.Warn("redirectConnect: sockaddr_in too short", "tid", tid)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}
		newBuf = make([]byte, len(buf))
		copy(newBuf, buf)
		if result.RedirectPort > 0 {
			binary.BigEndian.PutUint16(newBuf[2:4], uint16(result.RedirectPort))
		}
		if redirectIP != nil {
			ip4 := redirectIP.To4()
			if ip4 == nil {
				slog.Warn("redirectConnect: IPv6 redirect for IPv4 socket, denying", "tid", tid)
				t.denySyscall(tid, int(unix.EACCES))
				return
			}
			copy(newBuf[4:8], ip4)
		}

	case unix.AF_INET6:
		if len(buf) < 28 {
			slog.Warn("redirectConnect: sockaddr_in6 too short", "tid", tid)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}
		newBuf = make([]byte, len(buf))
		copy(newBuf, buf)
		if result.RedirectPort > 0 {
			binary.BigEndian.PutUint16(newBuf[2:4], uint16(result.RedirectPort))
		}
		if redirectIP != nil {
			ip16 := redirectIP.To16()
			if ip16 == nil {
				slog.Warn("redirectConnect: cannot convert redirect addr to IPv6", "tid", tid)
				t.denySyscall(tid, int(unix.EACCES))
				return
			}
			copy(newBuf[8:24], ip16)
		}

	default:
		slog.Warn("redirectConnect: unsupported address family", "tid", tid, "family", family)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	if err := t.writeBytes(tid, addrPtr, newBuf); err != nil {
		slog.Warn("redirectConnect: write sockaddr failed, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	if result.RedirectPort > 0 || redirectIP != nil {
		_, origAddress, origPort, _ := parseSockaddr(buf)
		_, newAddress, newPort, _ := parseSockaddr(newBuf)
		origAddr := fmt.Sprintf("%s:%d", origAddress, origPort)
		newAddr := fmt.Sprintf("%s:%d", newAddress, newPort)
		slog.Info("redirectConnect: rewritten", "tid", tid, "from", origAddr, "to", newAddr)
	}

	t.allowSyscall(tid)
}
