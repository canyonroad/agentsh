package tlsleaf

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestIssueLeaf_SignedByCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	leaf, err := ca.IssueLeaf("db.internal")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if len(leaf.Certificate) == 0 {
		t.Fatal("leaf has empty certificate chain")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "db.internal"}); err != nil {
		t.Fatalf("verify leaf against CA: %v", err)
	}
}

func TestIssueLeaf_SAN(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	leaf, _ := ca.IssueLeaf("db.example.com")
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "db.example.com" {
		t.Errorf("DNSNames = %v, want [db.example.com]", parsed.DNSNames)
	}
}

func TestIssueLeaf_CacheReturnsSameCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	a, _ := ca.IssueLeaf("host-a")
	b, _ := ca.IssueLeaf("host-a")
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Error("cache miss: different bytes for same hostname")
	}
}

func TestIssueLeaf_DifferentHostsDifferentCerts(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreate(dir, time.Now)
	a, _ := ca.IssueLeaf("host-a")
	b, _ := ca.IssueLeaf("host-b")
	if string(a.Certificate[0]) == string(b.Certificate[0]) {
		t.Error("different hostnames produced identical certificates")
	}
}
