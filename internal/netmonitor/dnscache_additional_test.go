package netmonitor

import (
	"net"
	"testing"
	"time"
)

func TestDNSCacheRecordAndExpiry(t *testing.T) {
	c := NewDNSCache(10 * time.Millisecond)
	now := time.Now().UTC()
	ip := net.ParseIP("1.2.3.4")
	c.Record("example.com", []net.IP{ip}, now)

	if dom, ok := c.LookupByIP(ip, now); !ok || dom != "example.com" {
		t.Fatalf("expected hit, got %q ok=%v", dom, ok)
	}

	time.Sleep(15 * time.Millisecond)
	if _, ok := c.LookupByIP(ip, time.Now().UTC()); ok {
		t.Fatalf("expected cache entry to expire")
	}
}

func TestParseDNSAnswerIPs(t *testing.T) {
	// Build minimal DNS response with one A record 1.2.3.4.
	msg := make([]byte, 12)
	msg[4], msg[5] = 0, 1 // QDCOUNT
	msg[6], msg[7] = 0, 1 // ANCOUNT
	// Question: 3www7example3com0 type A class IN
	msg = append(msg, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	msg = append(msg, 0, 1, 0, 1) // type A, class IN
	// Answer name as pointer to offset 12 (0xc00c)
	msg = append(msg, 0xc0, 0x0c)
	msg = append(msg, 0, 1, 0, 1)  // type A, class IN
	msg = append(msg, 0, 0, 0, 30) // TTL
	msg = append(msg, 0, 4)        // RDLENGTH
	msg = append(msg, 1, 2, 3, 4)  // RDATA

	ips := parseDNSAnswerIPs(msg)
	if len(ips) != 1 || ips[0].String() != "1.2.3.4" {
		t.Fatalf("unexpected parsed IPs: %+v", ips)
	}
}

func TestSkipDNSNameHandlesCompressionAndBounds(t *testing.T) {
	msg := []byte{1, 'a', 0} // label length 1, then 'a', then 0 terminator
	if i, ok := skipDNSName(msg, 0); !ok || i != 3 {
		t.Fatalf("expected ok advance to 3, got ok=%v i=%d", ok, i)
	}
	// compression pointer
	msg = []byte{0xc0, 0x00}
	if i, ok := skipDNSName(msg, 0); !ok || i != 2 {
		t.Fatalf("expected compression advance, got ok=%v i=%d", ok, i)
	}
	// out of bounds
	if _, ok := skipDNSName([]byte{3, 'a'}, 0); ok {
		t.Fatalf("expected failure on short name")
	}
}
