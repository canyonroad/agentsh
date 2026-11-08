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
func (t *Tracer) handleNetwork(ctx context.Context, tid int, sc *SyscallContext) {
	if t.cfg.NetworkHandler == nil || !t.cfg.TraceNetwork {
		t.allowSyscall(tid)
		return
	}

	nr := sc.Info.Nr
	args := sc.Info.Args

	// Sendto DNS redirect: if sendto targets port 53, rewrite destination to proxy
	if t.dnsProxy != nil && nr == unix.SYS_SENDTO {
		destAddrPtr := args[4]      // sendto arg4 = dest_addr
		destAddrLen := int(args[5]) // sendto arg5 = addrlen
		if destAddrPtr != 0 && destAddrLen > 0 && destAddrLen <= 128 {
			destBuf := make([]byte, destAddrLen)
			if err := t.readBytes(tid, destAddrPtr, destBuf); err == nil {
				destFamily, destAddr, destPort, err := parseSockaddr(destBuf)
				if err == nil && destPort == 53 &&
					(destFamily == unix.AF_INET || destFamily == unix.AF_INET6) &&
					((destFamily == unix.AF_INET && destAddrLen >= 16) ||
						(destFamily == unix.AF_INET6 && destAddrLen >= 28)) {

					var newDest []byte
					if destFamily == unix.AF_INET {
						newDest = buildSockaddrIn4(net.ParseIP("127.0.0.1").To4(), t.dnsProxy.port4)
					} else if t.dnsProxy.port6 > 0 {
						newDest = buildSockaddrIn6(net.ParseIP("::1"), t.dnsProxy.port6)
						regs, err := sc.Regs()
						if err == nil {
							regs.SetArg(5, 28) // update addrlen
							t.setRegs(tid, regs)
						}
					}
					if newDest != nil {
						if err := t.writeBytes(tid, destAddrPtr, newDest); err == nil {
							// Record redirect info for DNS proxy session attribution
							t.mu.Lock()
							state := t.tracees[tid]
							if state != nil {
								fd := int(int32(args[0]))
								t.fds.recordDNSRedirect(state.TGID, fd, state.TGID, state.SessionID, fmt.Sprintf("%s:%d", destAddr, destPort))
							}
							t.mu.Unlock()
							t.allowSyscall(tid)
							return
						}
					}
					// No IPv6 proxy or write failed — fall through to normal handling
				}
			}
		}
	}

	// Datagram sends on an unconnected socket never call connect(), so the
	// destination is only visible on sendto/sendmsg/sendmmsg.
	if nr == unix.SYS_SENDTO || nr == unix.SYS_SENDMSG || nr == unix.SYS_SENDMMSG {
		t.handleSend(ctx, tid, nr, args)
		return
	}

	// Only evaluate policy for connect and bind
	if nr != unix.SYS_CONNECT && nr != unix.SYS_BIND {
		t.allowSyscall(tid)
		return
	}

	// Args: sockfd(arg0), addr(arg1), addrlen(arg2)
	addrPtr := args[1]
	rawLen := args[2]

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

	// DNS redirect: if connecting to port 53, redirect to local DNS proxy
	if t.dnsProxy != nil && port == 53 &&
		(family == unix.AF_INET || family == unix.AF_INET6) &&
		nr == unix.SYS_CONNECT {

		t.mu.Lock()
		state := t.tracees[tid]
		var tgid int
		var sessionID string
		if state != nil {
			tgid = state.TGID
			sessionID = state.SessionID
		}
		t.mu.Unlock()

		fd := int(int32(args[0]))
		originalResolver := fmt.Sprintf("%s:%d", address, port)

		// Rewrite sockaddr to point to DNS proxy, preserving address family
		if family == unix.AF_INET && addrLen < 16 {
			t.allowSyscall(tid)
			return
		}
		if family == unix.AF_INET6 && addrLen < 28 {
			t.allowSyscall(tid)
			return
		}
		var newSockaddr []byte
		if family == unix.AF_INET {
			newSockaddr = buildSockaddrIn4(net.ParseIP("127.0.0.1").To4(), t.dnsProxy.port4)
		} else if t.dnsProxy.port6 > 0 {
			newSockaddr = buildSockaddrIn6(net.ParseIP("::1"), t.dnsProxy.port6)
			// Update addrlen register for larger sockaddr_in6
			regs, err := sc.Regs()
			if err == nil {
				regs.SetArg(2, 28)
				if err := t.setRegs(tid, regs); err != nil {
					slog.Warn("handleNetwork: DNS redirect setRegs failed", "tid", tid, "error", err)
				}
			}
		} else {
			// No IPv6 proxy — let DNS connect proceed unmodified
			t.allowSyscall(tid)
			return
		}
		if err := t.writeBytes(tid, addrPtr, newSockaddr); err != nil {
			slog.Warn("handleNetwork: DNS redirect write failed", "tid", tid, "error", err)
			t.denySyscall(tid, int(unix.EACCES))
			return
		}

		// Record redirect info keyed by TGID+fd for proxy PID attribution
		t.fds.recordDNSRedirect(tgid, fd, tgid, sessionID, originalResolver)

		t.mu.Lock()
		if s := t.tracees[tid]; s != nil {
			s.NeedExitStop = false
		}
		t.mu.Unlock()
		t.metrics.IncExitStopSkipped()
		t.allowSyscall(tid)
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
		if nr == unix.SYS_CONNECT && port != 443 && port != 853 {
			t.mu.Lock()
			if s := t.tracees[tid]; s != nil {
				s.NeedExitStop = false
			}
			t.mu.Unlock()
			t.metrics.IncExitStopSkipped()
		}
		t.allowSyscall(tid)
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	case "redirect":
		// Redirect is only supported for connect; deny bind-redirect to
		// avoid unintentionally mutating bind behavior.
		if nr == unix.SYS_CONNECT {
			regs, err := sc.Regs()
			if err != nil {
				slog.Warn("handleNetwork: cannot load regs for redirect, denying", "tid", tid, "error", err)
				t.denySyscall(tid, int(unix.EACCES))
				return
			}
			t.redirectConnect(ctx, tid, regs, result)
		} else {
			slog.Warn("handleNetwork: redirect not supported for this syscall, denying",
				"tid", tid, "operation", operation)
			t.denySyscall(tid, int(unix.EACCES))
		}
	default:
		slog.Warn("handleNetwork: unknown action, denying", "tid", tid, "action", action)
		t.denySyscall(tid, int(unix.EACCES))
	}
}

// handleSend evaluates the destination of a datagram send. A send on a
// connected socket has no name (msg_name NULL / addrlen 0): connect() already
// evaluated it, so it is allowed.
func (t *Tracer) handleSend(ctx context.Context, tid int, nr int, args [6]uint64) {
	namePtr, nameLen, ok := t.sendSockaddr(tid, nr, args)
	if !ok {
		t.allowSyscall(tid)
		return
	}
	if nameLen < 2 || nameLen > 128 {
		slog.Warn("handleSend: addrlen out of range, denying", "tid", tid, "addrlen", nameLen)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	buf := make([]byte, nameLen)
	if err := t.readBytes(tid, namePtr, buf); err != nil {
		slog.Warn("handleSend: cannot read sockaddr, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}
	family, address, port, err := parseSockaddr(buf)
	if err != nil {
		slog.Warn("handleSend: cannot parse sockaddr, denying", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
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

	operation := "sendto"
	if nr != unix.SYS_SENDTO {
		operation = "sendmsg"
	}
	result := t.cfg.NetworkHandler.HandleNetwork(ctx, NetworkContext{
		PID:       tgid,
		SessionID: sessionID,
		Syscall:   nr,
		Family:    family,
		Address:   address,
		Port:      port,
		Operation: operation,
	})
	allow := result.Allow || result.Action == "allow" || result.Action == "continue"
	if !allow {
		errno := int(result.Errno)
		if errno == 0 {
			errno = int(unix.EACCES)
		}
		t.denySyscall(tid, errno)
		return
	}
	t.allowSyscall(tid)
}

// sendSockaddr returns the destination sockaddr of a send syscall. ok is false
// for a connected-socket send, which carries no destination.
func (t *Tracer) sendSockaddr(tid, nr int, args [6]uint64) (uint64, int, bool) {
	switch nr {
	case unix.SYS_SENDTO:
		// sendto(sockfd, buf, len, flags, dest_addr, addrlen)
		if args[4] == 0 || args[5] == 0 {
			return 0, 0, false
		}
		return args[4], int(args[5]), true
	default:
		// sendmsg(sockfd, msg, flags) / sendmmsg(sockfd, msgvec, vlen, flags):
		// struct msghdr { void *msg_name; socklen_t msg_namelen; ... } and
		// struct mmsghdr starts with the same msghdr.
		var hdr [12]byte
		if err := t.readBytes(tid, args[1], hdr[:]); err != nil {
			return 0, 0, false
		}
		namePtr := binary.NativeEndian.Uint64(hdr[0:8])
		nameLen := int(binary.NativeEndian.Uint32(hdr[8:12]))
		if namePtr == 0 || nameLen == 0 {
			return 0, 0, false
		}
		return namePtr, nameLen, true
	}
}

// buildSockaddrIn4 builds a raw sockaddr_in for IPv4.
func buildSockaddrIn4(ip net.IP, port int) []byte {
	buf := make([]byte, 16) // sizeof(sockaddr_in)
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[4:8], ip.To4())
	return buf
}

// buildSockaddrIn6 builds a raw sockaddr_in6 for IPv6.
func buildSockaddrIn6(ip net.IP, port int) []byte {
	buf := make([]byte, 28) // sizeof(sockaddr_in6)
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[8:24], ip.To16())
	return buf
}
