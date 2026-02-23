//go:build linux
// +build linux

package netmonitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type TransparentTCP struct {
	sessionID string
	sess      *session.Session
	dnsCache  *DNSCache
	policy    *policy.Engine
	approvals *approvals.Manager
	emit      Emitter

	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter) (*TransparentTCP, int, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, 0, err
	}
	t := &TransparentTCP{
		sessionID: sessionID,
		sess:      sess,
		dnsCache:  dnsCache,
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
		ln:        ln,
		done:      make(chan struct{}),
	}
	t.wg.Add(1)
	go t.acceptLoop()
	return t, ln.Addr().(*net.TCPAddr).Port, nil
}

func (t *TransparentTCP) Close() error {
	close(t.done)
	err := t.ln.Close()
	t.wg.Wait()
	return err
}

func (t *TransparentTCP) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				continue
			}
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			_ = t.handle(conn)
		}()
	}
}

func (t *TransparentTCP) handle(conn net.Conn) error {
	defer conn.Close()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	dstIP, dstPort, err := originalDst(tcp)
	if err != nil {
		return nil
	}
	remote := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))

	commandID := ""
	if t.sess != nil {
		commandID = t.sess.CurrentCommandID()
	}

	domain := dstIP.String()
	if t.dnsCache != nil {
		if d, ok := t.dnsCache.LookupByIP(dstIP, time.Now().UTC()); ok && d != "" {
			domain = d
		}
	}
	dec := t.policyDecision(domain, dstIP, dstPort)
	dec = t.maybeApprove(context.Background(), commandID, dec, "network", remote)
	connectEv := t.netEvent("net_connect", commandID, domain, remote, dstPort, dec, nil)
	_ = t.emit.AppendEvent(context.Background(), connectEv)
	t.emit.Publish(connectEv)

	if dec.EffectiveDecision == types.DecisionDeny {
		return nil
	}

	emitMCPConnectionIfMatched(context.Background(), t.sess, t.emit, t.sessionID, commandID, domain, remote, dstPort)

	up, err := net.DialTimeout("tcp", remote, 20*time.Second)
	if err != nil {
		return nil
	}
	defer up.Close()

	var upBytes, downBytes int64
	errCh := make(chan error, 2)
	go func() {
		n, e := io.Copy(up, conn)
		upBytes = n
		errCh <- e
	}()
	go func() {
		n, e := io.Copy(conn, up)
		downBytes = n
		errCh <- e
	}()
	<-errCh
	<-errCh

	closeEv := t.netEvent("net_close", commandID, domain, remote, dstPort, dec, map[string]any{"bytes_sent": upBytes, "bytes_received": downBytes})
	_ = t.emit.AppendEvent(context.Background(), closeEv)
	t.emit.Publish(closeEv)
	return nil
}

func (t *TransparentTCP) policyDecision(domain string, ip net.IP, port int) policy.Decision {
	if t.policy == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return t.policy.CheckNetworkIP(domain, ip, port)
}

func (t *TransparentTCP) maybeApprove(ctx context.Context, commandID string, dec policy.Decision, kind string, target string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if t.approvals == nil {
		return dec
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: t.sessionID,
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
	}
	res, err := t.approvals.RequestApproval(ctx, req)
	if dec.Approval != nil {
		dec.Approval.ID = req.ID
	}
	if err != nil || !res.Approved {
		dec.EffectiveDecision = types.DecisionDeny
	} else {
		dec.EffectiveDecision = types.DecisionAllow
	}
	return dec
}

func (t *TransparentTCP) netEvent(evType string, commandID string, domain string, remote string, port int, dec policy.Decision, fields map[string]any) types.Event {
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: t.sessionID,
		CommandID: commandID,
		Domain:    domain,
		Remote:    remote,
		Fields:    fields,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
		},
	}
	return ev
}

func originalDst(c *net.TCPConn) (net.IP, int, error) {
	f, err := c.File()
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fd := int(f.Fd())

	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, 0, errno
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return ip, port, nil
}
