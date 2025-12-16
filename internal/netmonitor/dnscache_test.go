package netmonitor

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseDNSAnswerIPs_PointerName(t *testing.T) {
	// Minimal DNS response:
	// - 1 question: example.com A
	// - 1 answer: NAME = pointer to question, TYPE=A, RDATA=93.184.216.34
	qname := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xBEEF) // id
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // standard response, noerror
	binary.BigEndian.PutUint16(header[4:6], 1)      // qdcount
	binary.BigEndian.PutUint16(header[6:8], 1)      // ancount
	// nscount/arcount = 0

	question := append([]byte{}, qname...)
	question = append(question, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN

	answer := []byte{
		0xC0, 0x0C, // NAME pointer to 0x000c (start of qname)
		0x00, 0x01, // TYPE=A
		0x00, 0x01, // CLASS=IN
		0x00, 0x00, 0x00, 0x3C, // TTL=60
		0x00, 0x04, // RDLEN=4
		93, 184, 216, 34, // RDATA
	}

	msg := append(header, append(question, answer...)...)
	ips := parseDNSAnswerIPs(msg)
	if len(ips) != 1 {
		t.Fatalf("expected 1 ip, got %v", ips)
	}
	if got := ips[0].String(); got != "93.184.216.34" {
		t.Fatalf("unexpected ip: %s", got)
	}
}

func TestDNSCache_LookupByIP(t *testing.T) {
	c := NewDNSCache(5 * time.Minute)
	c.Record("example.com", []net.IP{net.ParseIP("93.184.216.34")}, time.Unix(1000, 0).UTC())

	if d, ok := c.LookupByIP(net.ParseIP("93.184.216.34"), time.Unix(1001, 0).UTC()); !ok || d != "example.com" {
		t.Fatalf("expected hit for ip -> example.com, got %q ok=%v", d, ok)
	}
	if d, ok := c.LookupByIP(net.ParseIP("1.1.1.1"), time.Unix(1001, 0).UTC()); ok {
		t.Fatalf("expected miss, got %q", d)
	}
}
