//go:build linux

package ptrace

import (
	"crypto/tls"
	"net"
	"testing"
)

// buildClientHello generates a real TLS ClientHello with the given SNI.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		done <- buf[:n]
		serverConn.Close()
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	go func() {
		tlsConn.Handshake() //nolint:errcheck
		tlsConn.Close()
	}()

	hello := <-done
	clientConn.Close()
	return hello
}

func TestParseSNI(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	sni, offset, length, err := parseSNI(hello)
	if err != nil {
		t.Fatalf("parseSNI failed: %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("expected SNI 'example.com', got %q", sni)
	}
	if offset <= 0 || length != len("example.com") {
		t.Fatalf("unexpected offset=%d length=%d", offset, length)
	}
}

func TestParseSNI_NoSNI(t *testing.T) {
	// Not a TLS record
	_, _, _, err := parseSNI([]byte("GET / HTTP/1.1\r\n"))
	if err == nil {
		t.Fatal("expected error for non-TLS data")
	}
}

func TestParseSNI_TooShort(t *testing.T) {
	_, _, _, err := parseSNI([]byte{0x16, 0x03, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestRewriteSNI_SameLength(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	original := make([]byte, len(hello))
	copy(original, hello)

	rewritten, err := rewriteSNI(hello, "example.org")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "example.org" {
		t.Fatalf("expected rewritten SNI 'example.org', got %q", sni)
	}
	if len(rewritten) != len(original) {
		t.Fatalf("expected same length %d, got %d", len(original), len(rewritten))
	}
}

func TestRewriteSNI_Shorter(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	rewritten, err := rewriteSNI(hello, "ex.co")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "ex.co" {
		t.Fatalf("expected rewritten SNI 'ex.co', got %q", sni)
	}
	if len(rewritten) >= len(hello) {
		t.Fatalf("expected shorter record, got %d >= %d", len(rewritten), len(hello))
	}
}

func TestRewriteSNI_Longer(t *testing.T) {
	hello := buildClientHello(t, "ex.co")
	rewritten, err := rewriteSNI(hello, "very-long-subdomain.example.com")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "very-long-subdomain.example.com" {
		t.Fatalf("expected rewritten SNI, got %q", sni)
	}
	if len(rewritten) <= len(hello) {
		t.Fatalf("expected longer record, got %d <= %d", len(rewritten), len(hello))
	}
}

func TestIsClientHello(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	if !isClientHello(hello) {
		t.Fatal("expected isClientHello=true for valid ClientHello")
	}
	if isClientHello([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("expected isClientHello=false for HTTP request")
	}
	if isClientHello(nil) {
		t.Fatal("expected isClientHello=false for nil")
	}
}
