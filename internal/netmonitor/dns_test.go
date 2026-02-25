package netmonitor

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type captureEmitter struct {
	events []types.Event
}

func (c *captureEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	c.events = append(c.events, ev)
	return nil
}
func (c *captureEmitter) Publish(ev types.Event) {}

func TestDNSInterceptor_DenyDoesNotForwardAndRefuses(t *testing.T) {
	up := startUDPUpstream(t)
	defer up.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer clientPC.Close()

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer serverPC.Close()

	receivedUpstream := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = up.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, e := up.ReadFrom(buf)
		if e == nil {
			q := make([]byte, n)
			copy(q, buf[:n])
			receivedUpstream <- q
		}
	}()

	pol := &policy.Policy{
		Version: 1,
		Name:    "test",
		NetworkRules: []policy.NetworkRule{
			{Name: "deny-example", Domains: []string{"example.com"}, Ports: []int{53}, Decision: "deny"},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}

	em := &captureEmitter{}
	d := &DNSInterceptor{
		sessionID: "session-test",
		pc:        serverPC,
		upstream:  up.LocalAddr().String(),
		emit:      em,
		policy:    engine,
	}

	query := makeDNSQuery(t, "example.com", 0xBEEF)
	if err := d.handle(clientPC.LocalAddr(), query); err != nil {
		t.Fatal(err)
	}

	select {
	case <-receivedUpstream:
		t.Fatalf("unexpected upstream forward for denied domain")
	case <-time.After(250 * time.Millisecond):
		// ok
	}

	_ = clientPC.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := buf[:n]
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0xBEEF {
		t.Fatalf("response id mismatch: got 0x%x", got)
	}
	if len(resp) < 12 {
		t.Fatalf("response too short: %d", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&(1<<15) == 0 {
		t.Fatalf("expected QR=1 response, flags=0x%x", flags)
	}
	rcode := flags & 0x000F
	if rcode != 5 { // REFUSED
		t.Fatalf("expected REFUSED (rcode=5), got rcode=%d flags=0x%x", rcode, flags)
	}

	if len(em.events) == 0 {
		t.Fatalf("expected dns_query event")
	}
	last := em.events[len(em.events)-1]
	if last.Type != "dns_query" {
		t.Fatalf("expected dns_query event, got %q", last.Type)
	}
	if last.Policy == nil || last.Policy.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("expected deny effective decision, got %+v", last.Policy)
	}
}

func startUDPUpstream(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	// If anything forwards to the upstream, respond with a minimal "NOERROR" reply so tests can detect the difference.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			resp := make([]byte, len(q))
			copy(resp, q)
			if len(resp) >= 4 {
				flags := binary.BigEndian.Uint16(resp[2:4])
				flags |= 1 << 15 // QR=1
				flags &^= 0x000F // rcode=0
				binary.BigEndian.PutUint16(resp[2:4], flags)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc
}

func makeDNSQuery(t *testing.T, domain string, id uint16) []byte {
	t.Helper()
	labels := splitLabels(domain)
	// 12-byte header + qname + null + qtype + qclass
	qnameLen := 1
	for _, l := range labels {
		qnameLen += 1 + len(l)
	}
	msg := make([]byte, 12+qnameLen+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	off := 12
	for _, l := range labels {
		if len(l) > 63 {
			t.Fatalf("label too long: %q", l)
		}
		msg[off] = byte(len(l))
		off++
		copy(msg[off:], l)
		off += len(l)
	}
	msg[off] = 0
	off++
	binary.BigEndian.PutUint16(msg[off:off+2], 1) // A
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1)
	return msg
}

func splitLabels(domain string) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				out = append(out, []byte(domain[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

func TestDNSInterceptor_ThreatMetadataInEvent(t *testing.T) {
	up := startUDPUpstream(t)
	defer up.Close()

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer serverPC.Close()

	// Policy with threat feed that matches evil.com in audit mode.
	pol := &policy.Policy{
		Version: 1,
		Name:    "test",
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"*"}, Ports: []int{53}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetThreatStore(&stubThreatChecker{
		feedName: "urlhaus",
		matched:  "evil.com",
	}, "audit")

	em := &captureEmitter{}
	d := &DNSInterceptor{
		sessionID: "session-test",
		pc:        serverPC,
		upstream:  up.LocalAddr().String(),
		emit:      em,
		policy:    engine,
	}

	query := makeDNSQuery(t, "evil.com", 0xABCD)
	_ = d.handle(serverPC.LocalAddr(), query)

	if len(em.events) == 0 {
		t.Fatal("expected dns_query event")
	}
	ev := em.events[0]
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.ThreatFeed != "urlhaus" {
		t.Errorf("expected ThreatFeed %q, got %q", "urlhaus", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatMatch != "evil.com" {
		t.Errorf("expected ThreatMatch %q, got %q", "evil.com", ev.Policy.ThreatMatch)
	}
	if ev.Policy.ThreatAction != "audit" {
		t.Errorf("expected ThreatAction %q, got %q", "audit", ev.Policy.ThreatAction)
	}
}

func TestDNSInterceptor_MonitorOnlyPreservesThreatMetadata(t *testing.T) {
	up := startUDPUpstream(t)
	defer up.Close()

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("udp listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer serverPC.Close()

	// Policy with a rule that doesn't match evil.com — evil.com will fall through
	// to default-deny-network, which DNS rewrites to monitor-only.
	pol := &policy.Policy{
		Version: 1,
		Name:    "test",
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-safe", Domains: []string{"safe.com"}, Ports: []int{53}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetThreatStore(&stubThreatChecker{
		feedName: "phishtank",
		matched:  "evil.com",
	}, "audit")

	em := &captureEmitter{}
	d := &DNSInterceptor{
		sessionID: "session-test",
		pc:        serverPC,
		upstream:  up.LocalAddr().String(),
		emit:      em,
		policy:    engine,
	}

	query := makeDNSQuery(t, "evil.com", 0x1234)
	_ = d.handle(serverPC.LocalAddr(), query)

	if len(em.events) == 0 {
		t.Fatal("expected dns_query event")
	}
	ev := em.events[0]
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	// Rule should be rewritten to dns-monitor-only but threat fields preserved.
	if ev.Policy.Rule != "dns-monitor-only" {
		t.Errorf("expected Rule %q, got %q", "dns-monitor-only", ev.Policy.Rule)
	}
	if ev.Policy.ThreatFeed != "phishtank" {
		t.Errorf("expected ThreatFeed %q, got %q", "phishtank", ev.Policy.ThreatFeed)
	}
	if ev.Policy.ThreatMatch != "evil.com" {
		t.Errorf("expected ThreatMatch %q, got %q", "evil.com", ev.Policy.ThreatMatch)
	}
	if ev.Policy.ThreatAction != "audit" {
		t.Errorf("expected ThreatAction %q, got %q", "audit", ev.Policy.ThreatAction)
	}
}

// stubThreatChecker implements policy.ThreatChecker for testing.
type stubThreatChecker struct {
	feedName string
	matched  string
}

func (s *stubThreatChecker) Check(domain string) (policy.ThreatCheckResult, bool) {
	if domain == s.matched {
		return policy.ThreatCheckResult{
			FeedName:      s.feedName,
			MatchedDomain: s.matched,
		}, true
	}
	return policy.ThreatCheckResult{}, false
}
