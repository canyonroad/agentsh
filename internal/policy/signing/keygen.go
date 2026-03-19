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
	privPath := filepath.Join(dir, "private.key.json")
	if err := os.WriteFile(privPath, privJSON, 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		return "", fmt.Errorf("chmod private key: %w", err)
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
