package server

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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

func TestServer_UnixSocketServesHealth(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte("version: 1\nname: default\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "agentsh.sock")

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.HTTP.ReadTimeout = "1s"
	cfg.Server.HTTP.WriteTimeout = "1s"
	cfg.Server.HTTP.MaxRequestSize = "1MB"
	cfg.Server.UnixSocket.Enabled = true
	cfg.Server.UnixSocket.Path = sock
	cfg.Server.UnixSocket.Permissions = "0660"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"

	s, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{}
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/health", nil)
	waitForHTTP200WithClient(t, client, req, 2*time.Second)
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not exit after cancel")
	}
}

func TestServer_TLSServesHealth(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte("version: 1\nname: default\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := writeSelfSignedKeypair(certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.HTTP.ReadTimeout = "1s"
	cfg.Server.HTTP.WriteTimeout = "1s"
	cfg.Server.HTTP.MaxRequestSize = "1MB"
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = certFile
	cfg.Server.TLS.KeyFile = keyFile
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"

	s, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	addr := s.httpLn.Addr().String()
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/health", nil)
	waitForHTTP200WithClient(t, client, req, 2*time.Second)
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not exit after cancel")
	}
}

func waitForHTTP200WithClient(t *testing.T, c *http.Client, req *http.Request, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", req.URL.String())
		}
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeSelfSignedKeypair(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "agentsh-test",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}
