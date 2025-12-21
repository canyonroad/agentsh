//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Emitter matches the minimal event interface we need.
type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

// ServeNotify runs the seccomp notify loop on the provided notify fd.
// It stops when the fd is closed or ctx is done.
func ServeNotify(ctx context.Context, fd *os.File, sessID string, pol *policy.Engine, emit Emitter) {
	if fd == nil || pol == nil || emit == nil {
		return
	}
	scmpFD := seccomp.ScmpFd(fd.Fd())
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := seccomp.NotifReceive(scmpFD)
		if err != nil {
			if isEAGAIN(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
		ctxReq := ExtractContext(req)
		if !isUnixSocketSyscall(ctxReq.Syscall) {
			_ = seccomp.NotifRespond(scmpFD, &seccomp.ScmpNotifResp{ID: req.ID})
			continue
		}
		allow := true
		errno := int32(unix.EACCES)
		path := ""
		abstract := false
		if raw, err := ReadSockaddr(ctxReq.PID, ctxReq.AddrPtr, ctxReq.AddrLen); err == nil {
			if p, abs, perr := ParseSockaddr(raw); perr == nil {
				path, abstract = p, abs
				op := syscallName(ctxReq.Syscall)
				dec := pol.CheckUnixSocket(path, op)
				allow = dec.EffectiveDecision == types.DecisionAllow
				if !allow {
					errno = int32(unix.EACCES)
					emitEvent(emit, sessID, dec, path, abstract, op)
				}
			}
		}
		resp := seccomp.ScmpNotifResp{ID: req.ID}
		if !allow {
			resp.Error = -errno
		}
		_ = seccomp.NotifRespond(scmpFD, &resp)
	}
}

func isUnixSocketSyscall(sc seccomp.ScmpSyscall) bool {
	switch sc {
	case seccomp.ScmpSyscall(unix.SYS_SOCKET), seccomp.ScmpSyscall(unix.SYS_CONNECT), seccomp.ScmpSyscall(unix.SYS_BIND), seccomp.ScmpSyscall(unix.SYS_LISTEN), seccomp.ScmpSyscall(unix.SYS_SENDTO):
		return true
	default:
		return false
	}
}

func syscallName(sc seccomp.ScmpSyscall) string {
	switch sc {
	case seccomp.ScmpSyscall(unix.SYS_SOCKET):
		return "socket"
	case seccomp.ScmpSyscall(unix.SYS_CONNECT):
		return "connect"
	case seccomp.ScmpSyscall(unix.SYS_BIND):
		return "bind"
	case seccomp.ScmpSyscall(unix.SYS_LISTEN):
		return "listen"
	case seccomp.ScmpSyscall(unix.SYS_SENDTO):
		return "sendto"
	default:
		return ""
	}
}

func isEAGAIN(err error) bool {
	if errno, ok := err.(unix.Errno); ok {
		return errno == unix.EAGAIN
	}
	return false
}

func emitEvent(emit Emitter, session string, dec policy.Decision, path string, abstract bool, op string) {
	ev := types.Event{
		ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "unix_socket_op",
		SessionID: session,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		Path:      path,
		Abstract:  abstract,
		Operation: op,
	}
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}
