//go:build linux

package ptrace

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

type dnsProxy struct {
	handler  NetworkHandler
	fds      *fdTracker
	udpConn4 *net.UDPConn
	udpConn6 *net.UDPConn
	port4    int
	port6    int
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

	udpAddr6, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		conn4.Close()
		return nil, fmt.Errorf("resolve UDP6 addr: %w", err)
	}
	conn6, err := net.ListenUDP("udp6", udpAddr6)
	if err != nil {
		conn4.Close()
		return nil, fmt.Errorf("listen UDP6: %w", err)
	}
	port6 := conn6.LocalAddr().(*net.UDPAddr).Port

	return &dnsProxy{
		handler:  handler,
		fds:      fds,
		udpConn4: conn4,
		udpConn6: conn6,
		port4:    port4,
		port6:    port6,
	}, nil
}

func (p *dnsProxy) addr4() string { return fmt.Sprintf("127.0.0.1:%d", p.port4) }
func (p *dnsProxy) addr6() string { return fmt.Sprintf("[::1]:%d", p.port6) }

func (p *dnsProxy) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		p.udpConn4.Close()
		p.udpConn6.Close()
	}()
	go p.listenUDP(ctx, p.udpConn4, unix.AF_INET)
	p.listenUDP(ctx, p.udpConn6, unix.AF_INET6)
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

	// TODO(Task 9): Wire proper TGID+fd attribution from the redirected
	// UDP socket so PID, SessionID, and originalResolver are populated.
	redirectInfo := dnsRedirectInfo{}

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
		if redirectInfo.originalResolver != "" {
			resp, err = p.forwardQuery(raw, redirectInfo.originalResolver)
		} else {
			resp, err = p.buildSERVFAIL(msg) // No resolver known yet (Task 9 wires attribution)
		}
	}

	if err != nil {
		slog.Warn("dns_proxy: failed to build response", "error", err, "domain", domain)
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
