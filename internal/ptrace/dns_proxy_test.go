//go:build linux

package ptrace

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mockDNSNetworkHandler implements NetworkHandler for DNS proxy tests.
type mockDNSNetworkHandler struct {
	result NetworkResult
}

func (m *mockDNSNetworkHandler) HandleNetwork(_ context.Context, nc NetworkContext) NetworkResult {
	return m.result
}

func buildDNSQuery(t *testing.T, domain string, qtype dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0xABCD,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	return buf
}

func TestDNSProxy_Allow(t *testing.T) {
	// Start a fake upstream DNS that returns a canned A record
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	go func() {
		buf := make([]byte, 512)
		n, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			return
		}
		msg.Header.Response = true
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
			},
		}
		resp, _ := msg.Pack()
		upstream.WriteTo(resp, addr)
	}()

	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{
		Allow:             true,
		RedirectUpstream:  upstream.LocalAddr().String(),
	}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	// Send query to proxy
	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if !msg.Header.Response {
		t.Fatal("expected response flag set")
	}
	if len(msg.Answers) == 0 {
		t.Fatal("expected at least one answer")
	}
}

func TestDNSProxy_Deny(t *testing.T) {
	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{Allow: false}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "blocked.example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if msg.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN, got %v", msg.Header.RCode)
	}
}

func TestDNSProxy_SyntheticRecords(t *testing.T) {
	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{
		Allow: false,
		Records: []DNSRecord{
			{Type: 1, Value: "10.0.0.1", TTL: 60},
		},
	}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "api.example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	aRecord, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatal("expected A record")
	}
	if aRecord.A != [4]byte{10, 0, 0, 1} {
		t.Fatalf("expected 10.0.0.1, got %v", aRecord.A)
	}
}

func TestDNSProxy_AllowFallbackUpstream(t *testing.T) {
	// Start a fake upstream DNS that returns a canned A record
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	go func() {
		buf := make([]byte, 512)
		n, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			return
		}
		msg.Header.Response = true
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.AResource{A: [4]byte{140, 82, 112, 4}},
			},
		}
		resp, _ := msg.Pack()
		upstream.WriteTo(resp, addr)
	}()

	ft := newFdTracker()
	// Allow with no RedirectUpstream — exercises the fallback path
	handler := &mockDNSNetworkHandler{result: NetworkResult{Allow: true}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}
	// Manually set upstream resolvers (simulates resolv.conf parsing)
	proxy.upstreamResolvers = []string{upstream.LocalAddr().String()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "github.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if len(msg.Answers) == 0 {
		t.Fatal("expected at least one answer from upstream fallback")
	}
	aRecord, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatal("expected A record")
	}
	if aRecord.A != [4]byte{140, 82, 112, 4} {
		t.Fatalf("expected 140.82.112.4, got %v", aRecord.A)
	}
}

func TestParseResolvConf(t *testing.T) {
	tmp := t.TempDir() + "/resolv.conf"
	content := "# comment\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 2001:4860:4860::8888\nsearch example.com\n"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := parseResolvConf(tmp)
	want := []string{"8.8.8.8:53", "8.8.4.4:53", "[2001:4860:4860::8888]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resolver[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseResolvConf_Missing(t *testing.T) {
	got := parseResolvConf("/nonexistent/resolv.conf")
	if got != nil {
		t.Fatalf("expected nil for missing file, got %v", got)
	}
}
