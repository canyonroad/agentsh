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
	"github.com/agentsh/agentsh/internal/netmonitor/redirect"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type DNSInterceptor struct {
	sessionID      string
	sess           *session.Session
	dnsCache       *DNSCache
	policy         *policy.Engine
	approvals      *approvals.Manager
	emit           Emitter
	correlationMap *redirect.CorrelationMap

	pc   net.PacketConn
	wg   sync.WaitGroup
	done chan struct{}

	upstream string
}

func StartDNS(listenAddr string, upstream string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine *policy.Engine, approvalsMgr *approvals.Manager, emit Emitter, correlationMap *redirect.CorrelationMap) (*DNSInterceptor, int, error) {
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, 0, err
	}
	d := &DNSInterceptor{
		sessionID:      sessionID,
		sess:           sess,
		dnsCache:       dnsCache,
		policy:         engine,
		approvals:      approvalsMgr,
		emit:           emit,
		correlationMap: correlationMap,
		pc:             pc,
		done:           make(chan struct{}),
		upstream:       upstream,
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

	// Check for DNS redirect rules first
	if domain != "" && d.policy != nil {
		redirectResult := d.policy.EvaluateDnsRedirect(domain)
		if redirectResult.Matched {
			return d.handleDNSRedirect(ctx, clientAddr, query, domain, commandID, redirectResult)
		}
	}

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

// handleDNSRedirect processes a DNS query that matches a redirect rule.
// It returns a synthetic DNS response with the redirect IP instead of querying upstream.
func (d *DNSInterceptor) handleDNSRedirect(ctx context.Context, clientAddr net.Addr, query []byte, domain, commandID string, result *policy.DnsRedirectResult) error {
	redirectIP := net.ParseIP(result.ResolveTo)
	if redirectIP == nil {
		// Invalid IP in redirect rule, fall through to normal resolution
		return nil
	}

	// Build synthetic DNS response
	resp := buildDNSRedirectResponse(query, redirectIP)
	if resp == nil {
		return nil
	}

	// Update correlation map with the redirect
	if d.correlationMap != nil {
		d.correlationMap.AddResolution(strings.ToLower(domain), []net.IP{redirectIP})
	}

	// Update DNS cache with the redirected IP
	if d.dnsCache != nil {
		d.dnsCache.Record(strings.ToLower(domain), []net.IP{redirectIP}, time.Now().UTC())
	}

	// Emit DNS redirect event if visibility is not silent
	if result.Visibility != "silent" && d.emit != nil {
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "dns_redirect",
			SessionID: d.sessionID,
			CommandID: commandID,
			Domain:    domain,
			Fields: map[string]any{
				"original_host": domain,
				"resolved_to":   result.ResolveTo,
				"rule":          result.Rule,
				"visibility":    result.Visibility,
			},
		}
		_ = d.emit.AppendEvent(ctx, ev)
		d.emit.Publish(ev)
	}

	// Send the synthetic response
	_, _ = d.pc.WriteTo(resp, clientAddr)
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

// buildDNSRedirectResponse creates a synthetic DNS response with the given IP.
// It copies the query header and question, then adds an A record answer.
func buildDNSRedirectResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}

	// Find the end of the question section
	qnameEnd := 12
	for {
		if qnameEnd >= len(query) {
			return nil
		}
		l := int(query[qnameEnd])
		if l == 0 {
			qnameEnd++ // skip the null terminator
			break
		}
		if l&0xC0 != 0 {
			// Compression pointer - skip 2 bytes
			qnameEnd += 2
			break
		}
		qnameEnd += 1 + l
	}
	// Add QTYPE (2) + QCLASS (2)
	questionEnd := qnameEnd + 4
	if questionEnd > len(query) {
		return nil
	}

	// Check if this is an A record query (type 1, class 1)
	qtype := binary.BigEndian.Uint16(query[qnameEnd : qnameEnd+2])
	if qtype != 1 {
		// Not an A record query, don't redirect
		return nil
	}

	// Get IPv4 address (use To4 to ensure 4-byte representation)
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil
	}

	// Build response: header + question + answer
	// Answer: NAME (pointer to offset 12) + TYPE (A=1) + CLASS (IN=1) + TTL + RDLENGTH + RDATA
	answerLen := 2 + 2 + 2 + 4 + 2 + 4 // pointer + type + class + ttl + rdlen + rdata
	resp := make([]byte, questionEnd+answerLen)

	// Copy header and question
	copy(resp, query[:questionEnd])

	// Set response flags: QR=1, AA=1, RD=1, RA=1, RCODE=0 (no error)
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 1 << 15 // QR=1 (response)
	flags |= 1 << 10 // AA=1 (authoritative)
	flags |= 1 << 8  // RD=1 (recursion desired, copy from query)
	flags |= 1 << 7  // RA=1 (recursion available)
	flags &^= 0x000F // clear RCODE (success)
	binary.BigEndian.PutUint16(resp[2:4], flags)

	// Set counts: QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	binary.BigEndian.PutUint16(resp[4:6], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], 1)  // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT

	// Build answer section
	answerStart := questionEnd
	// NAME: compression pointer to offset 12 (0xC00C)
	resp[answerStart] = 0xC0
	resp[answerStart+1] = 0x0C
	// TYPE: A (1)
	binary.BigEndian.PutUint16(resp[answerStart+2:answerStart+4], 1)
	// CLASS: IN (1)
	binary.BigEndian.PutUint16(resp[answerStart+4:answerStart+6], 1)
	// TTL: 60 seconds
	binary.BigEndian.PutUint32(resp[answerStart+6:answerStart+10], 60)
	// RDLENGTH: 4 (IPv4 address)
	binary.BigEndian.PutUint16(resp[answerStart+10:answerStart+12], 4)
	// RDATA: IPv4 address
	copy(resp[answerStart+12:answerStart+16], ipv4)

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
