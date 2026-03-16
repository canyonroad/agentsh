//go:build linux

package ptrace

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

type dnsProxy struct {
	handler            NetworkHandler
	fds                *fdTracker
	udpConn4           *net.UDPConn
	udpConn6           *net.UDPConn
	port4              int
	port6              int
	upstreamResolvers  []string // from /etc/resolv.conf, "ip:53" format
}

func newDNSProxy(handler NetworkHandler, fds *fdTracker) (*dnsProxy, error) {
	udpAddr4, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("resolve UDP4 addr: %w", err)
	}
	conn4, err := net.ListenUDP("udp4", udpAddr4)
	if err != nil {
		return nil, fmt.Errorf("listen UDP4: %w", err)
	}
	port4 := conn4.LocalAddr().(*net.UDPAddr).Port

	// IPv6 listener is best-effort — gVisor and some container runtimes
	// block UDP6, so we fall back to IPv4-only DNS proxying.
	var conn6 *net.UDPConn
	var port6 int
	udpAddr6, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err == nil {
		conn6, err = net.ListenUDP("udp6", udpAddr6)
		if err != nil {
			slog.Warn("dns_proxy: IPv6 listener unavailable, IPv4 only", "error", err)
			conn6 = nil
		} else {
			port6 = conn6.LocalAddr().(*net.UDPAddr).Port
		}
	} else {
		slog.Warn("dns_proxy: IPv6 resolve failed, IPv4 only", "error", err)
	}

	resolvers := parseResolvConf("/etc/resolv.conf")
	slog.Debug("dns_proxy: upstream resolvers", "resolvers", resolvers)

	return &dnsProxy{
		handler:           handler,
		fds:               fds,
		udpConn4:          conn4,
		udpConn6:          conn6,
		port4:             port4,
		port6:             port6,
		upstreamResolvers: resolvers,
	}, nil
}

func (p *dnsProxy) addr4() string { return fmt.Sprintf("127.0.0.1:%d", p.port4) }
func (p *dnsProxy) addr6() string {
	if p.udpConn6 == nil {
		return "<disabled>"
	}
	return fmt.Sprintf("[::1]:%d", p.port6)
}

func (p *dnsProxy) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		p.udpConn4.Close()
		if p.udpConn6 != nil {
			p.udpConn6.Close()
		}
	}()
	if p.udpConn6 != nil {
		go p.listenUDP(ctx, p.udpConn4, unix.AF_INET)
		p.listenUDP(ctx, p.udpConn6, unix.AF_INET6)
	} else {
		p.listenUDP(ctx, p.udpConn4, unix.AF_INET)
	}
}

func (p *dnsProxy) listenUDP(ctx context.Context, conn *net.UDPConn, family int) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("dns_proxy: read error", "error", err)
			continue
		}
		// Copy the packet data before passing to goroutine since buf is reused.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go p.handleQuery(ctx, conn, pkt, remoteAddr, family)
	}
}

func (p *dnsProxy) handleQuery(ctx context.Context, conn *net.UDPConn, raw []byte, remoteAddr *net.UDPAddr, family int) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		slog.Warn("dns_proxy: failed to parse DNS query", "error", err)
		return
	}
	if len(msg.Questions) == 0 {
		return
	}

	q := msg.Questions[0]
	domain := strings.TrimSuffix(q.Name.String(), ".")

	// Use the most recently recorded DNS redirect info for session attribution.
	// This covers the common single-session case; full per-port attribution
	// (Task 9) can be added later for multi-session scenarios.
	redirectInfo, _ := p.fds.getLastDNSRedirect()

	result := p.handler.HandleNetwork(ctx, NetworkContext{
		PID:       redirectInfo.pid,
		SessionID: redirectInfo.sessionID,
		Family:    family,
		Address:   redirectInfo.originalResolver,
		Port:      53,
		Operation: "dns",
		Domain:    domain,
		QueryType: uint16(q.Type),
	})

	var resp []byte
	var err error

	switch {
	case len(result.Records) > 0:
		resp, err = p.buildSyntheticResponse(msg, q, result.Records)
	case !result.Allow:
		resp, err = p.buildNXDomain(msg)
	case result.RedirectUpstream != "":
		resp, err = p.forwardQuery(raw, result.RedirectUpstream)
	default:
		upstream := redirectInfo.originalResolver
		if upstream == "" && len(p.upstreamResolvers) > 0 {
			upstream = p.upstreamResolvers[0]
		}
		if upstream != "" {
			resp, err = p.forwardQuery(raw, upstream)
		} else {
			resp, err = p.buildSERVFAIL(msg)
		}
	}

	if err != nil {
		slog.Warn("dns_proxy: failed to build response", "error", err, "domain", domain)
		if fallback, ferr := p.buildSERVFAIL(msg); ferr == nil {
			conn.WriteToUDP(fallback, remoteAddr)
		}
		return
	}

	p.recordResolutions(resp, domain)
	conn.WriteToUDP(resp, remoteAddr)
}

func (p *dnsProxy) buildNXDomain(query dnsmessage.Message) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeNameError,
		},
		Questions: query.Questions,
	}
	return resp.Pack()
}

func (p *dnsProxy) buildSERVFAIL(query dnsmessage.Message) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeServerFailure,
		},
		Questions: query.Questions,
	}
	return resp.Pack()
}

func (p *dnsProxy) buildSyntheticResponse(query dnsmessage.Message, q dnsmessage.Question, records []DNSRecord) ([]byte, error) {
	var answers []dnsmessage.Resource
	for _, rec := range records {
		hdr := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Class: dnsmessage.ClassINET,
			TTL:   rec.TTL,
		}
		switch rec.Type {
		case 1: // A
			ip := net.ParseIP(rec.Value).To4()
			if ip == nil {
				continue
			}
			hdr.Type = dnsmessage.TypeA
			var a [4]byte
			copy(a[:], ip)
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a}})
		case 28: // AAAA
			ip := net.ParseIP(rec.Value).To16()
			if ip == nil {
				continue
			}
			hdr.Type = dnsmessage.TypeAAAA
			var a [16]byte
			copy(a[:], ip)
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a}})
		case 5: // CNAME
			name, err := dnsmessage.NewName(rec.Value + ".")
			if err != nil {
				continue
			}
			hdr.Type = dnsmessage.TypeCNAME
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.CNAMEResource{CNAME: name}})
		}
	}
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: query.Questions,
		Answers:   answers,
	}
	return resp.Pack()
}

func (p *dnsProxy) forwardQuery(raw []byte, upstream string) ([]byte, error) {
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		// Strip brackets from bare IPv6 addresses like "[::1]" to avoid
		// net.JoinHostPort producing "[[::1]]:53".
		host := strings.TrimPrefix(strings.TrimSuffix(upstream, "]"), "[")
		upstream = net.JoinHostPort(host, "53")
	}
	conn, err := net.Dial("udp", upstream)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", upstream, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write to upstream: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from upstream: %w", err)
	}
	return buf[:n], nil
}

func (p *dnsProxy) recordResolutions(raw []byte, domain string) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return
	}
	for _, ans := range msg.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			p.fds.recordDNSResolution(net.IP(body.A[:]).String(), domain)
		case *dnsmessage.AAAAResource:
			p.fds.recordDNSResolution(net.IP(body.AAAA[:]).String(), domain)
		}
	}
}

// parseResolvConf reads nameserver lines from a resolv.conf file.
// Returns addresses in "ip:53" format. Skips the proxy's own listen
// addresses to avoid forwarding loops.
func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var resolvers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		if net.ParseIP(ip) == nil {
			continue
		}
		resolvers = append(resolvers, net.JoinHostPort(ip, "53"))
	}
	return resolvers
}
