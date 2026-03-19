package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

	// Verify private key file permissions (Unix only)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "private.key.json"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
		}
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
