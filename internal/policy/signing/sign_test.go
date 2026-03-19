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
	if sig.Version != 1 { t.Fatalf("expected version 1, got %d", sig.Version) }
	if sig.Algorithm != "ed25519" { t.Fatalf("expected ed25519, got %s", sig.Algorithm) }
	if sig.KeyID != kid { t.Fatalf("key_id mismatch") }
	if sig.Signer != "test-signer" { t.Fatalf("expected signer test-signer, got %s", sig.Signer) }
	if sig.Signature == "" { t.Fatal("empty signature") }
	if sig.SignedAt == "" { t.Fatal("empty signed_at") }
	if err := sig.Validate(); err != nil { t.Fatalf("sig validation: %v", err) }
}

func TestSignFile(t *testing.T) {
	dir := t.TempDir()
	GenerateKeypair(dir, "test")
	policyPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	if err := SignFile(policyPath, filepath.Join(dir, "private.key.json"), "", ""); err != nil {
		t.Fatal(err)
	}
	sigData, err := os.ReadFile(policyPath + ".sig")
	if err != nil { t.Fatalf("sig file not created: %v", err) }
	var sig SigFile
	if err := json.Unmarshal(sigData, &sig); err != nil { t.Fatalf("parse sig: %v", err) }
	if err := sig.Validate(); err != nil { t.Fatalf("sig validation: %v", err) }
}

func TestSignFile_CustomOutput(t *testing.T) {
	dir := t.TempDir()
	GenerateKeypair(dir, "test")
	policyPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	customSig := filepath.Join(dir, "custom.sig")
	if err := SignFile(policyPath, filepath.Join(dir, "private.key.json"), customSig, "custom-signer"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(customSig); err != nil { t.Fatalf("custom sig not created: %v", err) }
	if _, err := os.Stat(policyPath + ".sig"); err == nil { t.Fatal("default sig should not exist") }
}
