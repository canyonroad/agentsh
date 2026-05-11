//go:build linux

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// genSelfSignedServer builds a one-shot tls.Config a fake upstream server
// can use to TLS-handshake against test clients. Returns the cert bytes so
// the test can install them into a custom RootCAs pool.
func genSelfSignedServer(t *testing.T, host string) (*tls.Config, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(der)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leafCert,
	}
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) // exercise PEM path for completeness
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}, leafCert
}

// startTLSFakeUpstream returns the listener address. Each connection accepts,
// completes a TLS handshake, reads one byte, writes one byte, closes.
func startTLSFakeUpstream(t *testing.T, srvCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{'X'})
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startPlainFakeUpstream is the plaintext counterpart of startTLSFakeUpstream.
func startPlainFakeUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{'X'})
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDialUpstream_TerminateReissue_VerifiesAgainstSystemRoots(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "localhost")
	addr := startTLSFakeUpstream(t, srvCfg)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{'P'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("read = %q, want 'X'", buf[0])
	}
}

func TestDialUpstream_TerminateReissue_RejectsUnknownCA(t *testing.T) {
	srvCfg, _ := genSelfSignedServer(t, "localhost")
	addr := startTLSFakeUpstream(t, srvCfg)

	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			// Empty RootCAs ≈ system roots; the fake cert is not present.
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := dialUpstream(ctx, svc, cfg)
	if err == nil {
		t.Fatal("dialUpstream with unknown CA: want error, got nil")
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("error %q does not mention tls/x509", err)
	}
}

func TestDialUpstream_PlaintextUpstream_DoesNotTLS(t *testing.T) {
	addr := startPlainFakeUpstream(t)
	cfg := Config{}
	svc := Service{Upstream: addr, TLSMode: "terminate_plaintext_upstream"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream plaintext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{'P'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("read = %q, want 'X'", buf[0])
	}
}

func TestDialUpstream_ServerNameFromUpstreamHost(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "db.test.example.com")
	addr := startTLSFakeUpstream(t, srvCfg)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	_ = port

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "db.test.example.com",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
}

var _ = strconv.Itoa
