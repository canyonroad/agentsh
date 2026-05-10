package tlsleaf

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreate_FirstCallGenerates(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (first): %v", err)
	}
	if ca == nil {
		t.Fatal("CA is nil")
	}
	keyPath := filepath.Join(dir, "db-ca.key")
	crtPath := filepath.Join(dir, "db-ca.crt")
	keyFI, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyFI.Mode()&0o777 != 0o600 {
		t.Errorf("key perms = %#o, want 0600", keyFI.Mode()&0o777)
	}
	crtFI, err := os.Stat(crtPath)
	if err != nil {
		t.Fatalf("stat crt: %v", err)
	}
	if crtFI.Mode()&0o777 != 0o644 {
		t.Errorf("crt perms = %#o, want 0644", crtFI.Mode()&0o777)
	}
	if ca.Cert().Subject.CommonName != "AgentSH DB Proxy CA" {
		t.Errorf("CN = %q, want \"AgentSH DB Proxy CA\"", ca.Cert().Subject.CommonName)
	}
	if !ca.Cert().IsCA {
		t.Error("CA cert IsCA = false; want true")
	}
}

func TestLoadOrCreate_SecondCallLoads(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (first): %v", err)
	}
	second, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (second): %v", err)
	}
	if !first.Cert().Equal(second.Cert()) {
		t.Fatal("second LoadOrCreate produced a different certificate; expected reuse")
	}
}

func TestLoadOrCreate_RejectsNonCAExistingCert(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db-ca.crt"), []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("write garbage cert: %v", err)
	}
	if _, err := LoadOrCreate(dir, time.Now); err == nil {
		t.Fatal("LoadOrCreate over corrupted cert: want error, got nil")
	}
}

func TestCA_VerifyOptions(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	if pool.Equal(x509.NewCertPool()) {
		t.Fatal("pool with CA equals empty pool; CertPool not exposing CA correctly")
	}
}
