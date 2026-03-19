package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TrustStore holds trusted public keys indexed by key_id.
type TrustStore struct {
	Keys map[string]*PublicKeyFile
}

// LoadTrustStore reads all .json files from dir and populates a TrustStore.
// Non-JSON files and subdirectories are silently skipped.
// Emits a warning to stderr if the directory or any key file is world-writable.
func LoadTrustStore(dir string) (*TrustStore, error) {
	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read trust store dir: %w", err)
	}
	info, err := os.Stat(dir)
	if err == nil && info.Mode().Perm()&0o002 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: trust store directory %s is world-writable\n", dir)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
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
		// Skip JSON files that aren't public key records
		if kf.KeyID == "" || kf.Algorithm == "" || kf.PublicKey == "" {
			continue
		}
		if kf.Algorithm != "ed25519" {
			return nil, fmt.Errorf("key file %s: unsupported algorithm %q", e.Name(), kf.Algorithm)
		}
		pubBytes, err := base64.StdEncoding.DecodeString(kf.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("key file %s: decode public_key: %w", e.Name(), err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key file %s: invalid public key size %d (expected %d)", e.Name(), len(pubBytes), ed25519.PublicKeySize)
		}
		derivedID := KeyID(ed25519.PublicKey(pubBytes))
		if kf.KeyID != derivedID {
			return nil, fmt.Errorf("key file %s: key_id %q does not match derived key_id %q", e.Name(), kf.KeyID, derivedID)
		}
		if kf.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, kf.ExpiresAt); err != nil {
				return nil, fmt.Errorf("key file %s: invalid expires_at: %w", e.Name(), err)
			}
		}
		if _, exists := ts.Keys[kf.KeyID]; exists {
			return nil, fmt.Errorf("key file %s: duplicate key_id %s", e.Name(), kf.KeyID)
		}
		ts.Keys[kf.KeyID] = &kf
	}
	return ts, nil
}

// FindKey looks up a key by key_id and returns an error if not found or expired.
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
