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
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/agentsh/agentsh/internal/approvals"
	dbevents "github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/tor"
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
	dbBypass  atomic.Pointer[dbevents.BypassEmitter]

	torGW atomic.Pointer[torGatewayConfig]

	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*TransparentTCP, int, error) {
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
	if len(dbBypass) > 0 {
		t.SetDBBypassEmitter(dbBypass[0])
	}
	t.wg.Add(1)
	go t.acceptLoop()
	return t, ln.Addr().(*net.TCPAddr).Port, nil
}

func (t *TransparentTCP) SetDBBypassEmitter(em *dbevents.BypassEmitter) {
	if t == nil {
		return
	}
	t.dbBypass.Store(em)
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
	engine := t.policyEngine()

	if cfg, ok := t.torGatewayFor(dstPort); ok {
		return handleTorSocks(conn, cfg.upstream, cfg.pol, t.emit, t.sessionID, commandID)
	}

	domain := dstIP.String()
	if t.dnsCache != nil {
		if d, ok := t.dnsCache.LookupByIP(dstIP, time.Now().UTC()); ok && d != "" {
			domain = d
		}
	}

	redirectHostPort := net.JoinHostPort(domain, fmt.Sprintf("%d", dstPort))
	var redirectResult *policy.ConnectRedirectResult
	if engine != nil {
		result := engine.EvaluateConnectRedirect(redirectHostPort)
		if result.Matched {
			redirectResult = result
			if result.Visibility != "silent" {
				emitConnectRedirectEvent(context.Background(), t.emit, t.sessionID, commandID, domain, redirectHostPort, dstPort, result)
			}
		}
	}

	dec := t.checkConnectNetwork(context.Background(), commandID, domain, redirectHostPort, dstIP, dstPort, redirectResult)
	if dec.Tor != nil && t.emit != nil {
		tev := tor.BuildControlEvent(t.sessionID, commandID, 0, tor.Verdict{
			Vector: dec.Tor.Vector, Mode: dec.Tor.Mode, Decision: dec.Tor.Decision, Target: dec.Tor.Target,
		})
		_ = t.emit.AppendEvent(context.Background(), tev)
		t.emit.Publish(tev)
	}
	eventFields := map[string]any{}
	if redirectResult != nil {
		if redirectResult.RedirectTo != "" {
			eventFields["redirect_to"] = redirectResult.RedirectTo
		}
		if redirectResult.RedirectToUnix != "" {
			eventFields["redirect_to_unix"] = redirectResult.RedirectToUnix
		}
		eventFields["redirect_tls"] = redirectResult.TLSMode
		if redirectResult.SNI != "" {
			eventFields["redirect_sni"] = redirectResult.SNI
		}
	}
	connectEv := t.netEvent("net_connect", commandID, domain, remote, dstPort, dec, eventFields)
	_ = t.emit.AppendEvent(context.Background(), connectEv)
	t.emit.Publish(connectEv)

	if dec.EffectiveDecision == types.DecisionDeny {
		t.emitDBBypassAttempt(context.Background(), commandID, 0, dec.Rule, dec.Message)
		return nil
	}

	emitMCPConnectionIfMatched(context.Background(), t.sess, t.emit, t.sessionID, commandID, domain, remote, dstPort)

	dialTarget := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: remote,
		OriginalPort:     fmt.Sprintf("%d", dstPort),
		Redirect:         redirectResult,
	})
	up, err := net.DialTimeout(dialTarget.Network, dialTarget.Address, 20*time.Second)
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
	engine := t.policyEngine()
	if engine == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return engine.CheckNetworkIP(domain, ip, port)
}

func (t *TransparentTCP) checkConnectNetwork(ctx context.Context, commandID string, domain string, hostPort string, ip net.IP, port int, redirect *policy.ConnectRedirectResult) policy.Decision {
	dec := t.policyDecision(domain, ip, port)
	if allowUnixRedirectForDBUnavoidability(t.policyEngine(), dec, redirect) {
		return allowConnectRedirectDecision(redirect)
	}
	dec = t.maybeApprove(ctx, commandID, dec, "network", hostPort)
	return dec
}

func (t *TransparentTCP) policyEngine() *policy.Engine {
	if t == nil {
		return nil
	}
	if t.sess != nil {
		if engine := t.sess.PolicyEngine(); engine != nil {
			return engine
		}
	}
	return t.policy
}

func (t *TransparentTCP) emitDBBypassAttempt(ctx context.Context, commandID string, pid int, ruleName string, reason string) {
	if t == nil {
		return
	}
	em := t.dbBypass.Load()
	if em == nil {
		return
	}
	em.EmitIfDBUnavoidabilityDeny(ctx, dbevents.BypassAttempt{
		Engine:          t.policyEngine(),
		SessionID:       t.sessionID,
		CommandID:       commandID,
		ProcessID:       pid,
		ProcessIdentity: dbBypassProcessIdentity(t.sessionID, commandID),
		RuleName:        ruleName,
		Reason:          reason,
	})
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
			ThreatFeed:        dec.ThreatFeed,
			ThreatMatch:       dec.ThreatMatch,
			ThreatAction:      dec.ThreatAction,
		},
	}
	return ev
}

type torGatewayConfig struct {
	pol        TorGatewayPolicy
	upstream   string
	socksPorts map[int]struct{}
}

// SetTorGateway enables (or, with nil/empty args, disables) Phase 2 onion
// gateway routing for connections whose original destination is a Tor SOCKS
// port. Safe to call concurrently.
func (t *TransparentTCP) SetTorGateway(pol TorGatewayPolicy, upstream string, socksPorts []int) {
	if t == nil {
		return
	}
	if pol == nil || upstream == "" || len(socksPorts) == 0 {
		t.torGW.Store(nil)
		return
	}
	ports := make(map[int]struct{}, len(socksPorts))
	for _, p := range socksPorts {
		ports[p] = struct{}{}
	}
	t.torGW.Store(&torGatewayConfig{pol: pol, upstream: upstream, socksPorts: ports})
}

// torGatewayFor returns the gateway config when it is active and port is a
// configured Tor SOCKS port.
func (t *TransparentTCP) torGatewayFor(port int) (*torGatewayConfig, bool) {
	cfg := t.torGW.Load()
	if cfg == nil || !cfg.pol.GatewayActive() {
		return nil, false
	}
	if _, ok := cfg.socksPorts[port]; !ok {
		return nil, false
	}
	return cfg, true
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
