package mcpclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateTLSFingerprint_Format(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{"valid sha256", "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", false},
		{"empty is ok", "", false},
		{"missing prefix", "a1b2c3d4e5f6", true},
		{"wrong prefix", "md5:abc123", true},
		{"wrong hex length", "sha256:tooshort", true},
		{"invalid hex chars", "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSFingerprint(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTLSFingerprint(%q) error = %v, wantErr %v", tt.fingerprint, err, tt.wantErr)
			}
		})
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	// Compute expected SPKI fingerprint
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fingerprint := "sha256:" + hex.EncodeToString(spkiHash[:])

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return tlsCert, fingerprint
}

func TestVerifyTLSFingerprint_Match(t *testing.T) {
	tlsCert, expectedFP := generateSelfSignedCert(t)

	// Start a TLS server
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Keep connection open until test completes handshake
		buf := make([]byte, 1)
		conn.Read(buf)
		conn.Close()
	}()

	// Connect and verify fingerprint matches
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := VerifyTLSFingerprint(conn, expectedFP); err != nil {
		t.Errorf("expected match, got error: %v", err)
	}
}

func TestVerifyTLSFingerprint_Mismatch(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		conn.Read(buf)
		conn.Close()
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wrongFP := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err = VerifyTLSFingerprint(conn, wrongFP)
	if err == nil {
		t.Error("expected mismatch error, got nil")
	}
}

func TestVerifyTLSFingerprint_UppercaseMatch(t *testing.T) {
	tlsCert, expectedFP := generateSelfSignedCert(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		conn.Read(buf)
		conn.Close()
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Use uppercase hex — should still match after normalization
	upperFP := "sha256:" + strings.ToUpper(expectedFP[7:])

	if err := VerifyTLSFingerprint(conn, upperFP); err != nil {
		t.Errorf("uppercase fingerprint should match after normalization, got: %v", err)
	}
}
