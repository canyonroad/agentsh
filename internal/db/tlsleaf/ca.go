// Package tlsleaf provides a lazily-generated self-signed CA and per-hostname
// leaf issuer for the AgentSH DB proxy's TLS termination path. The CA is
// persisted under a caller-provided StateDir; leaves are issued on demand and
// cached in-process. Operators copy the CA cert into client trust stores
// (sslrootcert) so downstream PostgreSQL clients accept proxied connections.
//
// The package is platform-agnostic; tests run on every supported OS.
package tlsleaf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caKeyFile  = "db-ca.key"
	caCertFile = "db-ca.crt"
	caCN       = "AgentSH DB Proxy CA"
	caKeyBits  = 4096
	caValidFor = 10 * 365 * 24 * time.Hour
)

// CA is the AgentSH-DB self-signed certificate authority. Construct via
// LoadOrCreate. Methods are safe for concurrent use.
type CA struct {
	mu    sync.Mutex
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	clk   func() time.Time
	cache *leafCache
}

// LoadOrCreate loads the CA from stateDir if both files are present, or
// generates a fresh CA on first call and persists it (key 0600, cert 0644).
// stateDir must already exist; the parent of any sub-path is not created.
func LoadOrCreate(stateDir string, clock func() time.Time) (*CA, error) {
	if clock == nil {
		clock = time.Now
	}
	fi, err := os.Stat(stateDir)
	if err != nil {
		return nil, fmt.Errorf("tlsleaf: stat %q: %w", stateDir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("tlsleaf: %q is not a directory", stateDir)
	}
	keyPath := filepath.Join(stateDir, caKeyFile)
	crtPath := filepath.Join(stateDir, caCertFile)

	keyBytes, keyErr := os.ReadFile(keyPath)
	crtBytes, crtErr := os.ReadFile(crtPath)
	keyExists := keyErr == nil
	crtExists := crtErr == nil

	if keyExists && crtExists {
		ca, err := loadCA(keyBytes, crtBytes)
		if err != nil {
			return nil, fmt.Errorf("tlsleaf: load existing CA: %w", err)
		}
		ca.clk = clock
		return ca, nil
	}
	if keyExists != crtExists {
		return nil, fmt.Errorf("tlsleaf: incomplete CA on disk (have key=%v, cert=%v); refusing to regenerate", keyExists, crtExists)
	}
	return generateAndPersist(stateDir, clock)
}

func loadCA(keyPEM, crtPEM []byte) (*CA, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("malformed key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	crtBlock, _ := pem.Decode(crtPEM)
	if crtBlock == nil || crtBlock.Type != "CERTIFICATE" {
		return nil, errors.New("malformed cert PEM")
	}
	cert, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("persisted cert is not a CA")
	}
	return &CA{cert: cert, key: key}, nil
}

func generateAndPersist(stateDir string, clock func() time.Time) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, caKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(caValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse self-signed: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyPath := filepath.Join(stateDir, caKeyFile)
	crtPath := filepath.Join(stateDir, caCertFile)
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("write cert: %w", err)
	}
	return &CA{cert: cert, key: key, clk: clock}, nil
}

// Cert returns the CA certificate. Safe for concurrent use; callers must
// not mutate the returned value.
func (c *CA) Cert() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

// Key returns the CA private key. Test-internal use only; production code
// uses IssueLeaf instead.
func (c *CA) Key() *rsa.PrivateKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.key
}

// Now returns the configured clock's notion of "now". Used by leaf.go.
func (c *CA) Now() time.Time {
	c.mu.Lock()
	clk := c.clk
	c.mu.Unlock()
	if clk == nil {
		return time.Now()
	}
	return clk()
}

func serial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(fmt.Sprintf("tlsleaf: serial: %v", err))
	}
	return n
}
