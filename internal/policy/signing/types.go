package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// SigFile represents a detached signature file (.sig) in JSON format.
type SigFile struct {
	Version   int      `json:"version"`
	Algorithm string   `json:"algorithm"`
	KeyID     string   `json:"key_id"`
	Signer    string   `json:"signer,omitempty"`
	SignedAt  string   `json:"signed_at"`
	Signature string   `json:"signature"`
	CertChain []string `json:"cert_chain"`
}

// Validate checks that the sig file conforms to the v1 schema.
func (s *SigFile) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported version: %d", s.Version)
	}
	if s.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm: %s", s.Algorithm)
	}
	if s.KeyID == "" {
		return fmt.Errorf("missing key_id")
	}
	if s.Signature == "" {
		return fmt.Errorf("missing signature")
	}
	if s.SignedAt == "" {
		return fmt.Errorf("missing signed_at")
	}
	if len(s.CertChain) > 0 {
		return fmt.Errorf("unsupported_cert_chain: v1 does not support certificate chains")
	}
	return nil
}

// PublicKeyFile represents a public key in the trust store.
type PublicKeyFile struct {
	KeyID        string `json:"key_id"`
	Algorithm    string `json:"algorithm"`
	PublicKey    string `json:"public_key"`
	Label        string `json:"label,omitempty"`
	TrustedSince string `json:"trusted_since,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

// IsExpired returns true if the key has an expiry time that has passed.
func (k *PublicKeyFile) IsExpired() bool {
	if k.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, k.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

// PrivateKeyFile represents a private signing key.
type PrivateKeyFile struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"`
	Label      string `json:"label,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// KeyID computes the deterministic key identifier from an Ed25519 public key.
// Returns the full hex-encoded SHA256 hash (64 chars).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(h[:])
}
