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
	kid, _ := GenerateKeypair(dir, "test")
	tsDir := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(dir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key1.json"), pubData, 0o644)
	ts, err := LoadTrustStore(tsDir)
	if err != nil { t.Fatal(err) }
	key, err := ts.FindKey(kid)
	if err != nil { t.Fatalf("expected to find key: %v", err) }
	if key.KeyID != kid { t.Fatalf("key_id mismatch") }
}

func TestTrustStore_UnknownKey(t *testing.T) {
	tsDir := t.TempDir()
	ts, err := LoadTrustStore(tsDir)
	if err != nil { t.Fatal(err) }
	_, err = ts.FindKey("nonexistent")
	if err == nil { t.Fatal("expected error for unknown key") }
}

func TestTrustStore_ExpiredKey(t *testing.T) {
	// Generate a real keypair to get valid key_id and public_key
	keyDir := t.TempDir()
	kid, _ := GenerateKeypair(keyDir, "test")
	pubData, _ := os.ReadFile(filepath.Join(keyDir, "public.key.json"))

	// Modify the public key file to add an expired timestamp
	var pubFile PublicKeyFile
	json.Unmarshal(pubData, &pubFile)
	pubFile.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	data, _ := json.MarshalIndent(pubFile, "", "  ")

	tsDir := t.TempDir()
	os.WriteFile(filepath.Join(tsDir, "expired.json"), data, 0o644)
	ts, err := LoadTrustStore(tsDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ts.FindKey(kid)
	if err == nil {
		t.Fatal("expected error for expired key")
	}
}

func TestTrustStore_IgnoresNonJSON(t *testing.T) {
	tsDir := t.TempDir()
	os.WriteFile(filepath.Join(tsDir, "README.txt"), []byte("ignore"), 0o644)
	os.WriteFile(filepath.Join(tsDir, ".gitkeep"), []byte(""), 0o644)
	ts, _ := LoadTrustStore(tsDir)
	if len(ts.Keys) != 0 { t.Fatalf("expected 0 keys, got %d", len(ts.Keys)) }
}

func TestTrustStore_MultipleKeys(t *testing.T) {
	tsDir := t.TempDir()
	dir1, dir2 := t.TempDir(), t.TempDir()
	kid1, _ := GenerateKeypair(dir1, "key1")
	kid2, _ := GenerateKeypair(dir2, "key2")
	pub1, _ := os.ReadFile(filepath.Join(dir1, "public.key.json"))
	pub2, _ := os.ReadFile(filepath.Join(dir2, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key1.json"), pub1, 0o644)
	os.WriteFile(filepath.Join(tsDir, "key2.json"), pub2, 0o644)
	ts, _ := LoadTrustStore(tsDir)
	if len(ts.Keys) != 2 { t.Fatalf("expected 2 keys, got %d", len(ts.Keys)) }
	if _, err := ts.FindKey(kid1); err != nil { t.Fatalf("key1 not found: %v", err) }
	if _, err := ts.FindKey(kid2); err != nil { t.Fatalf("key2 not found: %v", err) }
}
