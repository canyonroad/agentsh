package netmonitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type DNSInterceptor struct {
	sessionID string
	sess      *session.Session
	dnsCache  *DNSCache
	policy    *policy.Engine
	approvals *approvals.Manager
	emit      Emitter

	pc   net.PacketConn
	wg   sync.WaitGroup
	done chan struct{}

	upstream string
}

func StartDNS(listenAddr string, upstream string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter) (*DNSInterceptor, int, error) {
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, 0, err
	}
	d := &DNSInterceptor{
		sessionID: sessionID,
		sess:      sess,
		dnsCache:  dnsCache,
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
		pc:        pc,
		done:      make(chan struct{}),
		upstream:  upstream,
	}
	d.wg.Add(1)
	go d.loop()
	return d, pc.LocalAddr().(*net.UDPAddr).Port, nil
}

func (d *DNSInterceptor) Close() error {
	close(d.done)
	err := d.pc.Close()
	d.wg.Wait()
	return err
}

func (d *DNSInterceptor) loop() {
	defer d.wg.Done()
	buf := make([]byte, 4096)
	for {
		_ = d.pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := d.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
				continue
			}
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		d.wg.Add(1)
		go func(a net.Addr, msg []byte) {
			defer d.wg.Done()
			_ = d.handle(a, msg)
		}(addr, q)
	}
}

func (d *DNSInterceptor) handle(clientAddr net.Addr, query []byte) error {
	domain := parseDNSDomain(query)
	commandID := ""
	if d.sess != nil {
		commandID = d.sess.CurrentCommandID()
	}

	// Use timeout context for DNS handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dec := d.policyDecision(ctx, domain, 53)
	// Default deny policies are typically intended for outbound TCP/UDP connects, not DNS lookups.
	// If the only match is default-deny, treat DNS as monitor-only unless the policy explicitly matches port 53.
	if dec.PolicyDecision == types.DecisionDeny && dec.Rule == "default-deny-network" {
		dec = policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow, Rule: "dns-monitor-only"}
	}
	dec = d.maybeApprove(ctx, commandID, dec, "dns", domain)

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "dns_query",
		SessionID: d.sessionID,
		CommandID: commandID,
		Domain:    domain,
		Fields: map[string]any{
			"upstream": d.upstream,
		},
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
			Approval:          dec.Approval,
		},
	}
	if d.emit != nil {
		_ = d.emit.AppendEvent(context.Background(), ev)
		d.emit.Publish(ev)
	}

	if dec.EffectiveDecision == types.DecisionDeny {
		if resp := dnsRefusedResponse(query); resp != nil {
			_, _ = d.pc.WriteTo(resp, clientAddr)
		}
		return nil
	}

	upConn, err := net.Dial("udp", d.upstream)
	if err != nil {
		return err
	}
	defer upConn.Close()
	_ = upConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upConn.Write(query); err != nil {
		return err
	}
	resp := make([]byte, 4096)
	n, err := upConn.Read(resp)
	if err != nil {
		return err
	}
	if d.dnsCache != nil && domain != "" {
		ips := parseDNSAnswerIPs(resp[:n])
		if len(ips) > 0 {
			d.dnsCache.Record(strings.ToLower(domain), ips, time.Now().UTC())
		}
	}
	_, _ = d.pc.WriteTo(resp[:n], clientAddr)
	return nil
}

func (d *DNSInterceptor) policyDecision(ctx context.Context, domain string, port int) policy.Decision {
	if d.policy == nil {
		return policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	}
	return d.policy.CheckNetworkCtx(ctx, domain, port)
}

func (d *DNSInterceptor) maybeApprove(ctx context.Context, commandID string, dec policy.Decision, kind string, target string) policy.Decision {
	if dec.PolicyDecision != types.DecisionApprove || dec.EffectiveDecision != types.DecisionApprove {
		return dec
	}
	if d.approvals == nil {
		return dec
	}
	req := approvals.Request{
		ID:        "approval-" + uuid.NewString(),
		SessionID: d.sessionID,
		CommandID: commandID,
		Kind:      kind,
		Target:    target,
		Rule:      dec.Rule,
		Message:   dec.Message,
	}
	res, err := d.approvals.RequestApproval(ctx, req)
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

func dnsRefusedResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)

	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 1 << 15 // QR=1
	flags &^= 0x000F // clear rcode
	flags |= 5       // REFUSED
	binary.BigEndian.PutUint16(resp[2:4], flags)

	// ANCOUNT/NSCOUNT/ARCOUNT = 0, keep QDCOUNT + question section intact.
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func parseDNSDomain(msg []byte) string {
	// Minimal DNS QNAME parser. Best-effort, logs on failure.
	if len(msg) < 12 {
		fmt.Fprintf(os.Stderr, "dns: parse failed, message too short (%d bytes)\n", len(msg))
		return ""
	}
	i := 12
	var out string
	for {
		if i >= len(msg) {
			fmt.Fprintf(os.Stderr, "dns: parse failed, unexpected end at offset %d\n", i)
			return ""
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		// compression not handled
		if l&0xC0 != 0 {
			fmt.Fprintf(os.Stderr, "dns: parse failed, compression pointer at offset %d not supported\n", i-1)
			return ""
		}
		if i+l > len(msg) {
			fmt.Fprintf(os.Stderr, "dns: parse failed, label extends beyond message at offset %d\n", i)
			return ""
		}
		if out != "" {
			out += "."
		}
		out += string(msg[i : i+l])
		i += l
	}
	if out == "" {
		return ""
	}
	return out
}

func (d *DNSInterceptor) String() string {
	return fmt.Sprintf("dns(%s)", d.pc.LocalAddr().String())
}
