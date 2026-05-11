//go:build linux

package postgres

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// recordClientHello captures the first record of a tls handshake by acting
// as a one-shot Server that just reads the ClientHello bytes.
func recordClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	captured := make(chan []byte, 1)
	go func() {
		_ = a.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 4096)
		n, _ := a.Read(buf)
		captured <- buf[:n]
		a.Close()
	}()

	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	tlsConn := tls.Client(b, cfg)
	_ = tlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_ = tlsConn.Handshake()
	return <-captured
}

func TestExtractSNI_Present(t *testing.T) {
	bytes := recordClientHello(t, "db.example.com")
	got, err := extractSNI(bytes)
	if err != nil {
		t.Fatalf("extractSNI: %v", err)
	}
	if got != "db.example.com" {
		t.Errorf("extractSNI = %q, want db.example.com", got)
	}
}

func TestExtractSNI_TinyBufReturnsEmpty(t *testing.T) {
	got, err := extractSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff})
	if err != nil {
		t.Fatalf("extractSNI: %v", err)
	}
	if got != "" {
		t.Errorf("extractSNI on tiny buf = %q, want empty", got)
	}
}

func TestExtractSNI_NonHandshakeReturnsEmpty(t *testing.T) {
	got, _ := extractSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x00})
	if got != "" {
		t.Errorf("extractSNI on app-data record = %q, want empty", got)
	}
}
