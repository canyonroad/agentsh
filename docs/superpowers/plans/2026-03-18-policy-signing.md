# Policy File Signing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Ed25519 detached signature support for agentsh policy files with configurable verification modes.

**Architecture:** New `internal/policy/signing` package containing all signing logic (types, keygen, sign, verify, trust store). Integration hooks into `Manager.Get()` and `DefaultPolicyLoader.Load()` for verification at load time. Three new CLI subcommands under `agentsh policy`.

**Tech Stack:** Go stdlib only — `crypto/ed25519`, `crypto/sha256`, `encoding/json`

**Spec:** `docs/superpowers/specs/2026-03-18-policy-signing-design.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `internal/policy/signing/types.go` | Data structures: `SigFile`, `PublicKeyFile`, `PrivateKeyFile`, `KeyID` derivation |
| `internal/policy/signing/types_test.go` | Type validation and KeyID derivation tests |
| `internal/policy/signing/keygen.go` | `GenerateKeypair()` — produces Ed25519 keypair, writes key files |
| `internal/policy/signing/keygen_test.go` | Keygen tests |
| `internal/policy/signing/sign.go` | `Sign()` — signs policy bytes; `SignFile()` — signs a file on disk |
| `internal/policy/signing/sign_test.go` | Signing tests |
| `internal/policy/signing/truststore.go` | `TrustStore` — loads `*.json` keys from dir, looks up by key_id, permission checks |
| `internal/policy/signing/truststore_test.go` | Trust store loading, lookup, expiry, permission tests |
| `internal/policy/signing/verify.go` | `Verify()` — verifies signature; `VerifyPolicy()` — full pipeline (load sig, trust store, verify) |
| `internal/policy/signing/verify_test.go` | Verification tests (valid, tampered, wrong key, expired, missing sig, schema validation) |

### Modified files

| File | Change |
|------|--------|
| `internal/config/config.go` | Add `SigningConfig` struct and `Signing` field to `PoliciesConfig` |
| `internal/policy/manager.go` | Add signature verification to `Get()` between hash check and YAML parse |
| `internal/policy/manager_test.go` | Add tests for signing verification in Manager |
| `internal/cli/policy_cmd.go` | Add `keygen`, `sign`, `verify` subcommands |
| `internal/api/app.go` | Pass signing config to `DefaultPolicyLoader`, add verification to `Load()` |
| `internal/api/core.go` | Add verification to inline policy loading path |

---

## Task 1: Core Types

**Files:**
- Create: `internal/policy/signing/types.go`
- Create: `internal/policy/signing/types_test.go`

- [ ] **Step 1: Write failing tests for types and KeyID derivation**

```go
// internal/policy/signing/types_test.go
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestKeyID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := KeyID(pub)
	if len(kid) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(kid))
	}
	// Deterministic
	if kid != KeyID(pub) {
		t.Fatal("expected deterministic key ID")
	}
}

func TestSigFileValidate(t *testing.T) {
	tests := []struct {
		name    string
		sig     SigFile
		wantErr string
	}{
		{"valid", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, ""},
		{"bad version", SigFile{Version: 2, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "unsupported version"},
		{"bad algorithm", SigFile{Version: 1, Algorithm: "rsa", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "unsupported algorithm"},
		{"missing key_id", SigFile{Version: 1, Algorithm: "ed25519", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "missing key_id"},
		{"missing signature", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z"}, "missing signature"},
		{"missing signed_at", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", Signature: "AAAA"}, "missing signed_at"},
		{"non-empty cert_chain", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA", CertChain: []string{"x"}}, "unsupported_cert_chain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/signing/ -v -run 'TestKeyID|TestSigFileValidate'`
Expected: FAIL — package does not exist

- [ ] **Step 3: Write types implementation**

```go
// internal/policy/signing/types.go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/signing/ -v -run 'TestKeyID|TestSigFileValidate'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/signing/types.go internal/policy/signing/types_test.go
git commit -m "feat(signing): add core types — SigFile, PublicKeyFile, PrivateKeyFile, KeyID"
```

---

## Task 2: Key Generation

**Files:**
- Create: `internal/policy/signing/keygen.go`
- Create: `internal/policy/signing/keygen_test.go`

- [ ] **Step 1: Write failing tests for keygen**

```go
// internal/policy/signing/keygen_test.go
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	dir := t.TempDir()
	kid, err := GenerateKeypair(dir, "test-signer")
	if err != nil {
		t.Fatal(err)
	}
	if len(kid) != 64 {
		t.Fatalf("expected 64 hex char key_id, got %d", len(kid))
	}

	// Check private key file
	privData, err := os.ReadFile(filepath.Join(dir, "private.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var priv PrivateKeyFile
	if err := json.Unmarshal(privData, &priv); err != nil {
		t.Fatal(err)
	}
	if priv.KeyID != kid {
		t.Fatalf("key_id mismatch: %s != %s", priv.KeyID, kid)
	}
	if priv.Algorithm != "ed25519" {
		t.Fatalf("expected ed25519, got %s", priv.Algorithm)
	}
	privKeyBytes, err := base64.StdEncoding.DecodeString(priv.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d byte private key, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
	}

	// Check public key file
	pubData, err := os.ReadFile(filepath.Join(dir, "public.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pub PublicKeyFile
	if err := json.Unmarshal(pubData, &pub); err != nil {
		t.Fatal(err)
	}
	if pub.KeyID != kid {
		t.Fatalf("key_id mismatch: %s != %s", pub.KeyID, kid)
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		t.Fatalf("expected %d byte public key, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	// Verify private key file permissions
	info, err := os.Stat(filepath.Join(dir, "private.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestGenerateKeypair_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	priv, err := LoadPrivateKey(filepath.Join(dir, "private.key.json"))
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello world")
	sig := ed25519.Sign(priv, msg)

	pubData, err := os.ReadFile(filepath.Join(dir, "public.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pubFile PublicKeyFile
	if err := json.Unmarshal(pubData, &pubFile); err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(pubFile.PublicKey)
	pub := ed25519.PublicKey(pubBytes)

	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("generated keypair does not round-trip")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/signing/ -v -run 'TestGenerateKeypair'`
Expected: FAIL — `GenerateKeypair` and `LoadPrivateKey` undefined

- [ ] **Step 3: Write keygen implementation**

```go
// internal/policy/signing/keygen.go
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GenerateKeypair creates an Ed25519 keypair and writes both key files to dir.
// Returns the key_id. The private key is written with mode 0600.
func GenerateKeypair(dir, label string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	kid := KeyID(pub)
	now := time.Now().UTC().Format(time.RFC3339)

	privFile := PrivateKeyFile{
		KeyID:      kid,
		Algorithm:  "ed25519",
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		Label:      label,
		CreatedAt:  now,
	}
	privJSON, err := json.MarshalIndent(privFile, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.key.json"), privJSON, 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	pubFile := PublicKeyFile{
		KeyID:        kid,
		Algorithm:    "ed25519",
		PublicKey:    base64.StdEncoding.EncodeToString(pub),
		Label:        label,
		TrustedSince: now,
	}
	pubJSON, err := json.MarshalIndent(pubFile, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public.key.json"), pubJSON, 0o644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return kid, nil
}

// LoadPrivateKey reads an Ed25519 private key from a JSON key file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	var kf PrivateKeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if kf.Algorithm != "ed25519" {
		return nil, fmt.Errorf("unsupported algorithm: %s", kf.Algorithm)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(keyBytes))
	}
	return ed25519.PrivateKey(keyBytes), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/signing/ -v -run 'TestGenerateKeypair'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/signing/keygen.go internal/policy/signing/keygen_test.go
git commit -m "feat(signing): add Ed25519 keypair generation"
```

---

## Task 3: Signing

**Files:**
- Create: `internal/policy/signing/sign.go`
- Create: `internal/policy/signing/sign_test.go`

- [ ] **Step 1: Write failing tests for signing**

```go
// internal/policy/signing/sign_test.go
package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSign(t *testing.T) {
	dir := t.TempDir()
	kid, err := GenerateKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	priv, err := LoadPrivateKey(filepath.Join(dir, "private.key.json"))
	if err != nil {
		t.Fatal(err)
	}

	policyBytes := []byte("version: 1\nname: test\n")
	sig, err := Sign(policyBytes, priv, "test-signer")
	if err != nil {
		t.Fatal(err)
	}

	if sig.Version != 1 {
		t.Fatalf("expected version 1, got %d", sig.Version)
	}
	if sig.Algorithm != "ed25519" {
		t.Fatalf("expected ed25519, got %s", sig.Algorithm)
	}
	if sig.KeyID != kid {
		t.Fatalf("key_id mismatch")
	}
	if sig.Signer != "test-signer" {
		t.Fatalf("expected signer test-signer, got %s", sig.Signer)
	}
	if sig.Signature == "" {
		t.Fatal("empty signature")
	}
	if sig.SignedAt == "" {
		t.Fatal("empty signed_at")
	}
	if err := sig.Validate(); err != nil {
		t.Fatalf("sig validation: %v", err)
	}
}

func TestSignFile(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	privPath := filepath.Join(dir, "private.key.json")
	if err := SignFile(policyPath, privPath, "", ""); err != nil {
		t.Fatal(err)
	}

	// Check .sig file was created
	sigPath := policyPath + ".sig"
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("sig file not created: %v", err)
	}
	var sig SigFile
	if err := json.Unmarshal(sigData, &sig); err != nil {
		t.Fatalf("parse sig: %v", err)
	}
	if err := sig.Validate(); err != nil {
		t.Fatalf("sig validation: %v", err)
	}
}

func TestSignFile_CustomOutput(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	customSig := filepath.Join(dir, "custom.sig")
	if err := SignFile(policyPath, filepath.Join(dir, "private.key.json"), customSig, "custom-signer"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(customSig); err != nil {
		t.Fatalf("custom sig not created: %v", err)
	}
	// Default location should not exist
	if _, err := os.Stat(policyPath + ".sig"); err == nil {
		t.Fatal("default sig should not exist when custom output specified")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/signing/ -v -run 'TestSign'`
Expected: FAIL — `Sign` and `SignFile` undefined

- [ ] **Step 3: Write signing implementation**

```go
// internal/policy/signing/sign.go
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Sign creates a SigFile from raw policy bytes and an Ed25519 private key.
func Sign(policyBytes []byte, privKey ed25519.PrivateKey, signer string) (*SigFile, error) {
	sig := ed25519.Sign(privKey, policyBytes)
	pub := privKey.Public().(ed25519.PublicKey)

	return &SigFile{
		Version:   1,
		Algorithm: "ed25519",
		KeyID:     KeyID(pub),
		Signer:    signer,
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
		Signature: base64.StdEncoding.EncodeToString(sig),
		CertChain: []string{},
	}, nil
}

// SignFile reads a policy file, signs it, and writes the .sig file.
// If outputPath is empty, writes to <policyPath>.sig.
// If signer is empty, the signer field is omitted.
func SignFile(policyPath, privKeyPath, outputPath, signer string) error {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}

	privKey, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return err
	}

	sigFile, err := Sign(policyBytes, privKey, signer)
	if err != nil {
		return err
	}

	sigJSON, err := json.MarshalIndent(sigFile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}

	dest := outputPath
	if dest == "" {
		dest = policyPath + ".sig"
	}

	if err := os.WriteFile(dest, sigJSON, 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/signing/ -v -run 'TestSign'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/signing/sign.go internal/policy/signing/sign_test.go
git commit -m "feat(signing): add policy signing — Sign() and SignFile()"
```

---

## Task 4: Trust Store

**Files:**
- Create: `internal/policy/signing/truststore.go`
- Create: `internal/policy/signing/truststore_test.go`

- [ ] **Step 1: Write failing tests for trust store**

```go
// internal/policy/signing/truststore_test.go
package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrustStore_LoadAndFind(t *testing.T) {
	dir := t.TempDir()
	kid, err := GenerateKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	// Move public key to a trust store directory
	tsDir := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(dir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key1.json"), pubData, 0o644)

	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ts.FindKey(kid)
	if err != nil {
		t.Fatalf("expected to find key: %v", err)
	}
	if key.KeyID != kid {
		t.Fatalf("key_id mismatch")
	}
}

func TestTrustStore_UnknownKey(t *testing.T) {
	tsDir := t.TempDir()
	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ts.FindKey("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestTrustStore_ExpiredKey(t *testing.T) {
	tsDir := t.TempDir()
	pubFile := PublicKeyFile{
		KeyID:     "expired-key-id",
		Algorithm: "ed25519",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 bytes
		Label:     "expired",
		ExpiresAt: time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(pubFile, "", "  ")
	os.WriteFile(filepath.Join(tsDir, "expired.json"), data, 0o644)

	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ts.FindKey("expired-key-id")
	if err == nil {
		t.Fatal("expected error for expired key")
	}
}

func TestTrustStore_IgnoresNonJSON(t *testing.T) {
	tsDir := t.TempDir()
	os.WriteFile(filepath.Join(tsDir, "README.txt"), []byte("ignore me"), 0o644)
	os.WriteFile(filepath.Join(tsDir, ".gitkeep"), []byte(""), 0o644)

	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(ts.Keys))
	}
}

func TestTrustStore_MultipleKeys(t *testing.T) {
	tsDir := t.TempDir()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	kid1, _ := GenerateKeypair(dir1, "key1")
	kid2, _ := GenerateKeypair(dir2, "key2")

	pub1, _ := os.ReadFile(filepath.Join(dir1, "public.key.json"))
	pub2, _ := os.ReadFile(filepath.Join(dir2, "public.key.json"))

	os.WriteFile(filepath.Join(tsDir, "key1.json"), pub1, 0o644)
	os.WriteFile(filepath.Join(tsDir, "key2.json"), pub2, 0o644)

	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(ts.Keys))
	}

	if _, err := ts.FindKey(kid1); err != nil {
		t.Fatalf("key1 not found: %v", err)
	}
	if _, err := ts.FindKey(kid2); err != nil {
		t.Fatalf("key2 not found: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/signing/ -v -run 'TestTrustStore'`
Expected: FAIL — `TrustStore`, `LoadTrustStore`, `FindKey` undefined

- [ ] **Step 3: Write trust store implementation**

```go
// internal/policy/signing/truststore.go
package signing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TrustStore holds a set of trusted public keys loaded from a directory.
type TrustStore struct {
	Keys map[string]*PublicKeyFile // keyed by key_id
}

// LoadTrustStore reads all *.json files from dir and parses them as public key files.
func LoadTrustStore(dir string) (*TrustStore, error) {
	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read trust store dir: %w", err)
	}

	// Check directory permissions
	info, err := os.Stat(dir)
	if err == nil && info.Mode().Perm()&0o002 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: trust store directory %s is world-writable\n", dir)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())

		// Check file permissions
		fi, err := os.Stat(path)
		if err == nil && fi.Mode().Perm()&0o002 != 0 {
			fmt.Fprintf(os.Stderr, "WARNING: trust store key file %s is world-writable\n", path)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key file %s: %w", e.Name(), err)
		}
		var kf PublicKeyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, fmt.Errorf("parse key file %s: %w", e.Name(), err)
		}
		ts.Keys[kf.KeyID] = &kf
	}

	return ts, nil
}

// FindKey looks up a public key by key_id. Returns an error if the key is
// not found or has expired.
func (ts *TrustStore) FindKey(keyID string) (*PublicKeyFile, error) {
	kf, ok := ts.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown_key: %s", keyID)
	}
	if kf.IsExpired() {
		return nil, fmt.Errorf("expired_key: %s", keyID)
	}
	return kf, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/signing/ -v -run 'TestTrustStore'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/signing/truststore.go internal/policy/signing/truststore_test.go
git commit -m "feat(signing): add trust store — load keys from dir, lookup, expiry check"
```

---

## Task 5: Verification

**Files:**
- Create: `internal/policy/signing/verify.go`
- Create: `internal/policy/signing/verify_test.go`

- [ ] **Step 1: Write failing tests for verification**

```go
// internal/policy/signing/verify_test.go
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func setupSignedPolicy(t *testing.T) (policyPath, tsDir string) {
	t.Helper()
	keyDir := t.TempDir()
	_, err := GenerateKeypair(keyDir, "test")
	if err != nil {
		t.Fatal(err)
	}

	policyDir := t.TempDir()
	policyPath = filepath.Join(policyDir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)

	if err := SignFile(policyPath, filepath.Join(keyDir, "private.key.json"), "", ""); err != nil {
		t.Fatal(err)
	}

	tsDir = t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key.json"), pubData, 0o644)
	return
}

func TestVerify_Valid(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)

	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}

	policyBytes, _ := os.ReadFile(policyPath)
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)

	if err := Verify(policyBytes, &sig, ts); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestVerify_TamperedPolicy(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)

	ts, _ := LoadTrustStore(tsDir)

	// Tamper with the policy
	tamperedBytes := []byte("version: 1\nname: TAMPERED\n")
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)

	err := Verify(tamperedBytes, &sig, ts)
	if err == nil {
		t.Fatal("expected error for tampered policy")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	policyPath, _ := setupSignedPolicy(t)

	// Create a different trust store with a different key
	otherDir := t.TempDir()
	GenerateKeypair(otherDir, "other")
	tsDir2 := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(otherDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir2, "other.json"), pubData, 0o644)

	ts, _ := LoadTrustStore(tsDir2)
	policyBytes, _ := os.ReadFile(policyPath)
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)

	err := Verify(policyBytes, &sig, ts)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestVerifyPolicy_Valid(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)
	ts, _ := LoadTrustStore(tsDir)

	result, err := VerifyPolicy(policyPath, ts)
	if err != nil {
		t.Fatalf("expected valid: %v", err)
	}
	if result.KeyID == "" {
		t.Fatal("expected key_id in result")
	}
}

func TestVerifyPolicy_MissingSig(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)

	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}
	_, err := VerifyPolicy(policyPath, ts)
	if err == nil {
		t.Fatal("expected error for missing sig")
	}
}

func TestVerify_InvalidSigSchema(t *testing.T) {
	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}
	bad := &SigFile{Version: 2, Algorithm: "ed25519", KeyID: "x", Signature: "x", SignedAt: "x"}
	err := Verify([]byte("test"), bad, ts)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestVerify_KeyRotation(t *testing.T) {
	// Generate two keypairs
	keyDir1 := t.TempDir()
	keyDir2 := t.TempDir()
	_, err := GenerateKeypair(keyDir1, "key1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateKeypair(keyDir2, "key2")
	if err != nil {
		t.Fatal(err)
	}

	// Sign policy with key1
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	if err := SignFile(policyPath, filepath.Join(keyDir1, "private.key.json"), "", ""); err != nil {
		t.Fatal(err)
	}

	// Trust store has BOTH keys
	tsDir := t.TempDir()
	pub1, _ := os.ReadFile(filepath.Join(keyDir1, "public.key.json"))
	pub2, _ := os.ReadFile(filepath.Join(keyDir2, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key1.json"), pub1, 0o644)
	os.WriteFile(filepath.Join(tsDir, "key2.json"), pub2, 0o644)

	ts, _ := LoadTrustStore(tsDir)

	// Policy signed with key1 should verify with both keys in trust store
	result, err := VerifyPolicy(policyPath, ts)
	if err != nil {
		t.Fatalf("expected valid with key rotation: %v", err)
	}
	if result.KeyID == "" {
		t.Fatal("expected key_id in result")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/signing/ -v -run 'TestVerify'`
Expected: FAIL — `Verify`, `VerifyPolicy` undefined

- [ ] **Step 3: Write verification implementation**

```go
// internal/policy/signing/verify.go
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult holds the outcome of a successful policy verification.
type VerifyResult struct {
	KeyID    string
	Signer   string
	SignedAt string
}

// Verify checks an Ed25519 signature against policy bytes using the trust store.
func Verify(policyBytes []byte, sig *SigFile, ts *TrustStore) error {
	if err := sig.Validate(); err != nil {
		return fmt.Errorf("invalid signature file: %w", err)
	}

	kf, err := ts.FindKey(sig.KeyID)
	if err != nil {
		return err
	}

	pubBytes, err := base64.StdEncoding.DecodeString(kf.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(pub, policyBytes, sigBytes) {
		return fmt.Errorf("invalid_signature: Ed25519 verification failed")
	}

	return nil
}

// VerifyPolicy reads a policy file and its .sig file, then verifies against the trust store.
// Returns VerifyResult on success or an error describing the failure.
func VerifyPolicy(policyPath string, ts *TrustStore) (*VerifyResult, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return VerifyPolicyBytes(policyBytes, policyPath+".sig", ts)
}

// VerifyPolicyBytes verifies raw policy bytes against a sig file and trust store.
// This is the shared verification function used by all policy loading paths.
func VerifyPolicyBytes(policyBytes []byte, sigPath string, ts *TrustStore) (*VerifyResult, error) {
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("missing_signature: %w", err)
	}

	var sig SigFile
	if err := json.Unmarshal(sigData, &sig); err != nil {
		return nil, fmt.Errorf("parse signature file: %w", err)
	}

	if err := Verify(policyBytes, &sig, ts); err != nil {
		return nil, err
	}

	return &VerifyResult{
		KeyID:    sig.KeyID,
		Signer:   sig.Signer,
		SignedAt:  sig.SignedAt,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/signing/ -v -run 'TestVerify'`
Expected: PASS

- [ ] **Step 5: Run all signing package tests**

Run: `go test ./internal/policy/signing/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/policy/signing/verify.go internal/policy/signing/verify_test.go
git commit -m "feat(signing): add verification — Verify() and VerifyPolicy()"
```

---

## Task 6: Configuration

**Files:**
- Modify: `internal/config/config.go:691-701`

- [ ] **Step 1: Add SigningConfig to PoliciesConfig**

In `internal/config/config.go`, add a `SigningConfig` struct before `PoliciesConfig` and a new field:

```go
// SigningConfig configures policy signature verification.
type SigningConfig struct {
	TrustStore string `yaml:"trust_store"` // Directory of trusted public keys
	Mode       string `yaml:"mode"`        // "enforce", "warn", or "off" (default: "off")
}

// SigningMode returns the effective signing mode, defaulting to "off".
func (c *SigningConfig) SigningMode() string {
	if c.Mode == "" {
		return "off"
	}
	return c.Mode
}

// Validate checks that the signing config has valid values.
func (c *SigningConfig) Validate() error {
	switch c.Mode {
	case "", "off", "warn", "enforce":
		// valid
	default:
		return fmt.Errorf("invalid signing mode %q: must be \"enforce\", \"warn\", or \"off\"", c.Mode)
	}
	if (c.Mode == "enforce" || c.Mode == "warn") && c.TrustStore == "" {
		return fmt.Errorf("signing.trust_store is required when signing.mode is %q", c.Mode)
	}
	return nil
}
```

Add `Signing SigningConfig` field to `PoliciesConfig`:

```go
type PoliciesConfig struct {
	Dir               string          `yaml:"dir"`
	Default           string          `yaml:"default"`
	Allowed           []string        `yaml:"allowed"`
	ManifestPath      string          `yaml:"manifest_path"`
	Signing           SigningConfig   `yaml:"signing"`
	EnvPolicy         EnvPolicyConfig `yaml:"env_policy"`
	EnvShimPath       string          `yaml:"env_shim_path"`
	ReloadInterval    string          `yaml:"reload_interval"`
	DetectProjectRoot *bool           `yaml:"detect_project_root"`
	ProjectMarkers    []string        `yaml:"project_markers"`
}
```

- [ ] **Step 2: Build to verify no compilation errors**

Run: `go build ./...`
Expected: Success

- [ ] **Step 3: Run existing tests to verify no regressions**

Run: `go test ./internal/config/... -v -count=1`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(signing): add SigningConfig to PoliciesConfig"
```

---

## Task 7: Manager Integration

**Files:**
- Modify: `internal/policy/manager.go`
- Modify: `internal/policy/manager_test.go`

- [ ] **Step 1: Write failing tests for signing verification in Manager**

Add to `internal/policy/manager_test.go`. First, update the import block to include the signing package:

```go
import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/policy/signing"
)
```

Then add the tests:

```go
func TestManager_SigningEnforce_Valid(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")

	// Generate key and sign
	keyDir := t.TempDir()
	kid, err := signing.GenerateKeypair(keyDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = kid
	if err := signing.SignFile(
		filepath.Join(dir, "p.yaml"),
		filepath.Join(keyDir, "private.key.json"),
		"", "",
	); err != nil {
		t.Fatal(err)
	}

	// Setup trust store
	tsDir := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key.json"), pubData, 0o644)

	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("enforce", tsDir)
	p, err := m.Get()
	if err != nil {
		t.Fatalf("expected load ok, got %v", err)
	}
	if p.Name != "p" {
		t.Fatalf("expected p, got %s", p.Name)
	}
}

func TestManager_SigningEnforce_MissingSig(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")

	tsDir := t.TempDir()
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("enforce", tsDir)
	_, err := m.Get()
	if err == nil {
		t.Fatal("expected error for missing signature in enforce mode")
	}
}

func TestManager_SigningWarn_MissingSig(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")

	tsDir := t.TempDir()
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("warn", tsDir)
	p, err := m.Get()
	if err != nil {
		t.Fatalf("warn mode should still load, got %v", err)
	}
	if p.Name != "p" {
		t.Fatalf("expected p, got %s", p.Name)
	}
}

func TestManager_SigningOff(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")

	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("off", "")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("off mode should always load, got %v", err)
	}
	if p.Name != "p" {
		t.Fatalf("expected p, got %s", p.Name)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v -run 'TestManager_Signing'`
Expected: FAIL — `SetSigningConfig` undefined

- [ ] **Step 3: Add signing verification to Manager**

Modify `internal/policy/manager.go`:

1. Add `signingMode` and `trustStorePath` fields to `Manager` struct
2. Add `SetSigningConfig(mode, trustStorePath string)` method
3. Insert verification between hash check and YAML parse in `Get()`

Add fields to Manager:
```go
type Manager struct {
	selectedName   string
	dir            string
	manifestPath   string
	signingMode    string
	trustStorePath string
	once           sync.Once
	policy         *Policy
	err            error
}
```

Add method:
```go
// SetSigningConfig sets the signing verification mode and trust store path.
func (m *Manager) SetSigningConfig(mode, trustStorePath string) {
	m.signingMode = mode
	m.trustStorePath = trustStorePath
}
```

In `Get()`, after the manifest hash check block (`if m.manifestPath != "" { ... }`) and before the YAML decode, add:

```go
		if m.signingMode != "" && m.signingMode != "off" {
			if err := m.verifySigning(path, data); err != nil {
				if m.signingMode == "enforce" {
					m.err = fmt.Errorf("signing verification: %w", err)
					return
				}
				// warn mode: log and continue
				fmt.Fprintf(os.Stderr, "WARNING: policy signing verification failed: %v\n", err)
			}
		}
```

Add the `verifySigning` method (uses shared `VerifyPolicyBytes`):
```go
func (m *Manager) verifySigning(path string, data []byte) error {
	ts, err := signing.LoadTrustStore(m.trustStorePath)
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	_, err = signing.VerifyPolicyBytes(data, path+".sig", ts)
	return err
}
```

Add imports: `"github.com/agentsh/agentsh/internal/policy/signing"`

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v -run 'TestManager_Signing'`
Expected: PASS

- [ ] **Step 5: Run all existing manager tests to verify no regressions**

Run: `go test ./internal/policy/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/policy/manager.go internal/policy/manager_test.go
git commit -m "feat(signing): integrate signature verification into policy.Manager"
```

---

## Task 8: CLI Commands

**Files:**
- Modify: `internal/cli/policy_cmd.go`

- [ ] **Step 1: Add keygen subcommand**

In `newPolicyCmd()`, after the existing `cmd.AddCommand(generateCmd)` line, add:

```go
	// Keygen subcommand
	var keygenOutput string
	var keygenLabel string

	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir := keygenOutput
			if outDir == "" {
				outDir = "."
			}
			kid, err := signing.GenerateKeypair(outDir, keygenLabel)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", kid)
			fmt.Fprintf(cmd.ErrOrStderr(), "Keypair written to %s/\n", outDir)
			return nil
		},
	}
	keygenCmd.Flags().StringVar(&keygenOutput, "output", "", "Output directory (default: current dir)")
	keygenCmd.Flags().StringVar(&keygenLabel, "label", "", "Human-readable label for the key")
	cmd.AddCommand(keygenCmd)
```

- [ ] **Step 2: Add sign subcommand**

```go
	// Sign subcommand
	var signKey string
	var signOutput string
	var signSigner string

	signCmd := &cobra.Command{
		Use:   "sign POLICY_FILE",
		Short: "Sign a policy file with an Ed25519 private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signKey == "" {
				return fmt.Errorf("--key is required")
			}
			if err := signing.SignFile(args[0], signKey, signOutput, signSigner); err != nil {
				return err
			}
			dest := signOutput
			if dest == "" {
				dest = args[0] + ".sig"
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Signature written to %s\n", dest)
			return nil
		},
	}
	signCmd.Flags().StringVar(&signKey, "key", "", "Path to private key file (required)")
	signCmd.Flags().StringVar(&signOutput, "output", "", "Output path for .sig file (default: <policy>.sig)")
	signCmd.Flags().StringVar(&signSigner, "signer", "", "Human-readable signer label")
	cmd.AddCommand(signCmd)
```

- [ ] **Step 3: Add verify subcommand**

```go
	// Verify subcommand
	var verifyKeyDir string

	verifyCmd := &cobra.Command{
		Use:   "verify POLICY_FILE",
		Short: "Verify a policy file signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if verifyKeyDir == "" {
				return fmt.Errorf("--key-dir is required")
			}
			ts, err := signing.LoadTrustStore(verifyKeyDir)
			if err != nil {
				return fmt.Errorf("load trust store: %w", err)
			}
			result, err := signing.VerifyPolicy(args[0], ts)
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			return printJSON(cmd, map[string]any{
				"status":    "valid",
				"key_id":    result.KeyID,
				"signer":    result.Signer,
				"signed_at": result.SignedAt,
			})
		},
	}
	verifyCmd.Flags().StringVar(&verifyKeyDir, "key-dir", "", "Path to trust store directory (required)")
	cmd.AddCommand(verifyCmd)
```

Add import for `"github.com/agentsh/agentsh/internal/policy/signing"` to the file.

- [ ] **Step 4: Write CLI tests**

Create `internal/cli/policy_signing_test.go`:

```go
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyKeygen(t *testing.T) {
	dir := t.TempDir()
	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"keygen", "--output", dir, "--label", "test"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "private.key.json")); err != nil {
		t.Fatal("private key not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "public.key.json")); err != nil {
		t.Fatal("public key not created")
	}
}

func TestPolicySignAndVerify(t *testing.T) {
	dir := t.TempDir()

	// Generate keys
	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"keygen", "--output", dir, "--label", "test"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Write a policy
	policyPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)

	// Sign
	cmd = newPolicyCmd()
	cmd.SetArgs([]string{"sign", policyPath, "--key", filepath.Join(dir, "private.key.json")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if _, err := os.Stat(policyPath + ".sig"); err != nil {
		t.Fatal("sig file not created")
	}

	// Verify
	cmd = newPolicyCmd()
	cmd.SetArgs([]string{"verify", policyPath, "--key-dir", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestPolicyVerify_MissingSig(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)

	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"verify", policyPath, "--key-dir", dir})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing sig")
	}
}
```

- [ ] **Step 5: Run CLI tests**

Run: `go test ./internal/cli/ -v -run 'TestPolicyKeygen|TestPolicySign'`
Expected: PASS

- [ ] **Step 6: Build to verify compilation**

Run: `go build ./...`
Expected: Success

- [ ] **Step 7: Commit**

```bash
git add internal/cli/policy_cmd.go internal/cli/policy_signing_test.go
git commit -m "feat(signing): add CLI commands — keygen, sign, verify"
```

---

## Task 9: API Integration

**Files:**
- Modify: `internal/api/app.go:1407-1441`
- Modify: `internal/api/core.go:575-596`

- [ ] **Step 1: Add signing config to DefaultPolicyLoader**

In `internal/api/app.go`, add signing fields to `DefaultPolicyLoader`:

```go
type DefaultPolicyLoader struct {
	policyDir        string
	enforceApprovals bool
	enforceRedirects bool
	signingMode      string
	trustStorePath   string
}
```

Update `NewDefaultPolicyLoader`:
```go
func NewDefaultPolicyLoader(policyDir string, enforceApprovals, enforceRedirects bool, signingMode, trustStorePath string) *DefaultPolicyLoader {
	return &DefaultPolicyLoader{
		policyDir:        policyDir,
		enforceApprovals: enforceApprovals,
		enforceRedirects: enforceRedirects,
		signingMode:      signingMode,
		trustStorePath:   trustStorePath,
	}
}
```

Add verification to `Load()` using the shared `VerifyPolicyBytes`:

```go
func (l *DefaultPolicyLoader) Load(name string) (*policy.Engine, error) {
	if name == "" {
		return nil, fmt.Errorf("policy name is empty")
	}
	path, err := policy.ResolvePolicyPath(l.policyDir, name)
	if err != nil {
		return nil, fmt.Errorf("resolve policy %q: %w", name, err)
	}
	p, err := policy.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policy %q: %w", name, err)
	}

	// Signature verification (shared function — no duplication)
	if l.signingMode != "" && l.signingMode != "off" && l.trustStorePath != "" {
		ts, tsErr := signing.LoadTrustStore(l.trustStorePath)
		if tsErr != nil {
			if l.signingMode == "enforce" {
				return nil, fmt.Errorf("load trust store for %q: %w", name, tsErr)
			}
			fmt.Fprintf(os.Stderr, "WARNING: policy %q: failed to load trust store: %v\n", name, tsErr)
		} else {
			policyBytes, _ := os.ReadFile(path) // already validated by LoadFromFile above
			if _, vErr := signing.VerifyPolicyBytes(policyBytes, path+".sig", ts); vErr != nil {
				if l.signingMode == "enforce" {
					return nil, fmt.Errorf("signing verification for %q: %w", name, vErr)
				}
				fmt.Fprintf(os.Stderr, "WARNING: policy %q signing verification failed: %v\n", name, vErr)
			}
		}
	}

	engine, err := policy.NewEngine(p, l.enforceApprovals, l.enforceRedirects)
	if err != nil {
		return nil, fmt.Errorf("create policy engine for %q: %w", name, err)
	}
	return engine, nil
}
```

Add import for `"github.com/agentsh/agentsh/internal/policy/signing"`.

- [ ] **Step 2: Update the single caller of NewDefaultPolicyLoader**

In `internal/server/server.go:313`, change:

```go
// Before:
policyLoader := api.NewDefaultPolicyLoader(cfg.Policies.Dir, enforceApprovals, true)

// After:
policyLoader := api.NewDefaultPolicyLoader(
	cfg.Policies.Dir, enforceApprovals, true,
	cfg.Policies.Signing.SigningMode(), cfg.Policies.Signing.TrustStore,
)
```

- [ ] **Step 3: Add verification to inline policy loading in core.go**

In `internal/api/core.go:575-596`, after `LoadFromFile` and before `NewEngineWithVariables`, add verification using the shared function:

```go
		// Signature verification (shared function — no duplication)
		sigMode := a.cfg.Policies.Signing.SigningMode()
		if sigMode != "off" && a.cfg.Policies.Signing.TrustStore != "" {
			ts, tsErr := signing.LoadTrustStore(a.cfg.Policies.Signing.TrustStore)
			if tsErr != nil {
				if sigMode == "enforce" {
					return types.Session{}, http.StatusInternalServerError, fmt.Errorf("load trust store: %w", tsErr)
				}
				fmt.Fprintf(os.Stderr, "WARNING: failed to load trust store: %v\n", tsErr)
			} else {
				if _, vErr := signing.VerifyPolicyBytes(data, policyPath+".sig", ts); vErr != nil {
					if sigMode == "enforce" {
						return types.Session{}, http.StatusForbidden, fmt.Errorf("policy signing: %w", vErr)
					}
					fmt.Fprintf(os.Stderr, "WARNING: policy signing verification failed: %v\n", vErr)
				}
			}
		}
```

Note: This requires reading the raw policy bytes before parsing. The existing code at `core.go:583` calls `policy.LoadFromFile(policyPath)` which reads and parses in one step. Refactor to read bytes first (for verification), then parse:

```go
		data, err := os.ReadFile(policyPath)
		if err != nil {
			return types.Session{}, http.StatusInternalServerError, fmt.Errorf("read policy: %w", err)
		}

		// Signature verification (insert here, using data bytes)

		pol, err := policy.LoadFromBytes(data) // or parse inline
```

If `LoadFromBytes` does not exist, add it as a thin wrapper in `internal/policy/load.go` that accepts `[]byte` instead of a file path. This avoids double-reading the file.

Add import for `"github.com/agentsh/agentsh/internal/policy/signing"`.

- [ ] **Step 4: Build to verify compilation**

Run: `go build ./...`
Expected: Success

- [ ] **Step 5: Run all tests**

Run: `go test ./...`
Expected: All PASS

- [ ] **Step 6: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Success

- [ ] **Step 7: Commit**

```bash
git add internal/api/app.go internal/api/core.go internal/server/server.go
git commit -m "feat(signing): integrate verification into API policy loading paths"
```

---

## Task 10: End-to-End Verification

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -count=1`
Expected: All PASS

- [ ] **Step 2: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Success

- [ ] **Step 3: Manual smoke test of CLI commands**

```bash
# Generate a keypair
go run ./cmd/agentsh policy keygen --output /tmp/agentsh-keys --label test

# Sign a policy
go run ./cmd/agentsh policy sign configs/policies/default.yaml --key /tmp/agentsh-keys/private.key.json --signer test

# Verify the signed policy
go run ./cmd/agentsh policy verify configs/policies/default.yaml --key-dir /tmp/agentsh-keys

# Clean up
rm -rf /tmp/agentsh-keys configs/policies/default.yaml.sig
```

- [ ] **Step 4: Final commit if any cleanup needed**
