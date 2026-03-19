package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func setupSignedPolicy(t *testing.T) (policyPath, tsDir string) {
	t.Helper()
	keyDir := t.TempDir()
	_, err := GenerateKeypair(keyDir, "test")
	if err != nil { t.Fatal(err) }
	policyDir := t.TempDir()
	policyPath = filepath.Join(policyDir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	if err := SignFile(policyPath, filepath.Join(keyDir, "private.key.json"), "", ""); err != nil { t.Fatal(err) }
	tsDir = t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key.json"), pubData, 0o644)
	return
}

func TestVerify_Valid(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)
	ts, _ := LoadTrustStore(tsDir, false)
	policyBytes, _ := os.ReadFile(policyPath)
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)
	if err := Verify(policyBytes, &sig, ts); err != nil { t.Fatalf("expected valid: %v", err) }
}

func TestVerify_TamperedPolicy(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)
	ts, _ := LoadTrustStore(tsDir, false)
	tamperedBytes := []byte("version: 1\nname: TAMPERED\n")
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)
	if err := Verify(tamperedBytes, &sig, ts); err == nil { t.Fatal("expected error for tampered policy") }
}

func TestVerify_WrongKey(t *testing.T) {
	policyPath, _ := setupSignedPolicy(t)
	otherDir := t.TempDir()
	GenerateKeypair(otherDir, "other")
	tsDir2 := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(otherDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir2, "other.json"), pubData, 0o644)
	ts, _ := LoadTrustStore(tsDir2, false)
	policyBytes, _ := os.ReadFile(policyPath)
	sigData, _ := os.ReadFile(policyPath + ".sig")
	var sig SigFile
	json.Unmarshal(sigData, &sig)
	if err := Verify(policyBytes, &sig, ts); err == nil { t.Fatal("expected error for wrong key") }
}

func TestVerifyPolicy_Valid(t *testing.T) {
	policyPath, tsDir := setupSignedPolicy(t)
	ts, _ := LoadTrustStore(tsDir, false)
	result, err := VerifyPolicy(policyPath, ts)
	if err != nil { t.Fatalf("expected valid: %v", err) }
	if result.KeyID == "" { t.Fatal("expected key_id in result") }
}

func TestVerifyPolicy_MissingSig(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}
	_, err := VerifyPolicy(policyPath, ts)
	if err == nil { t.Fatal("expected error for missing sig") }
}

func TestVerify_InvalidSigSchema(t *testing.T) {
	ts := &TrustStore{Keys: make(map[string]*PublicKeyFile)}
	bad := &SigFile{Version: 2, Algorithm: "ed25519", KeyID: "x", Signature: "x", SignedAt: "x"}
	if err := Verify([]byte("test"), bad, ts); err == nil { t.Fatal("expected error for bad version") }
}

func TestVerify_KeyRotation(t *testing.T) {
	keyDir1, keyDir2 := t.TempDir(), t.TempDir()
	GenerateKeypair(keyDir1, "key1")
	GenerateKeypair(keyDir2, "key2")
	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	SignFile(policyPath, filepath.Join(keyDir1, "private.key.json"), "", "")
	tsDir := t.TempDir()
	pub1, _ := os.ReadFile(filepath.Join(keyDir1, "public.key.json"))
	pub2, _ := os.ReadFile(filepath.Join(keyDir2, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key1.json"), pub1, 0o644)
	os.WriteFile(filepath.Join(tsDir, "key2.json"), pub2, 0o644)
	ts, _ := LoadTrustStore(tsDir, false)
	result, err := VerifyPolicy(policyPath, ts)
	if err != nil { t.Fatalf("expected valid with key rotation: %v", err) }
	if result.KeyID == "" { t.Fatal("expected key_id in result") }
}
