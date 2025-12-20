package netmonitor

import (
	"encoding/binary"
	"testing"
)

func TestParseDNSDomain(t *testing.T) {
	// Build minimal DNS query for example.com
	msg := make([]byte, 12)
	name := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg = append(msg, name...)
	if got := parseDNSDomain(msg); got != "example.com" {
		t.Fatalf("parseDNSDomain = %q, want example.com", got)
	}
}

func TestParseDNSDomainRejectsCompression(t *testing.T) {
	msg := make([]byte, 12)
	msg = append(msg, 0xC0, 0x0C) // compression pointer
	if got := parseDNSDomain(msg); got != "" {
		t.Fatalf("expected empty on compression, got %q", got)
	}
}

func TestDNSRefusedResponse(t *testing.T) {
	query := make([]byte, 12)
	// ID 0x1234, flags 0x0100 (standard query), QDCOUNT=1
	binary.BigEndian.PutUint16(query[0:2], 0x1234)
	binary.BigEndian.PutUint16(query[4:6], 1)
	resp := dnsRefusedResponse(query)
	if resp == nil {
		t.Fatalf("expected response")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 || flags&0x000F != 5 {
		t.Fatalf("unexpected flags %#x", flags)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 0 {
		t.Fatalf("ANCOUNT expected 0, got %d", got)
	}
}
