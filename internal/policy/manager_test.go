package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/policy/signing"
)

func TestManager_SelectsAllowedEnv(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "safe.yml", "version: 1\nname: safe\n")

	m := NewManager(dir, "default", []string{"safe"}, "", "safe")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("expected load ok, got %v", err)
	}
	if p.Name != "safe" {
		t.Fatalf("expected safe policy, got %s", p.Name)
	}
}

func TestManager_FallbackWhenDisallowed(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "default.yml", "version: 1\nname: default\n")

	m := NewManager(dir, "default", []string{"default"}, "", "bad")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("expected load ok, got %v", err)
	}
	if p.Name != "default" {
		t.Fatalf("expected default fallback, got %s", p.Name)
	}
}

func TestManager_RejectsInvalidName(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "default.yml", "version: 1\nname: default\n")

	m := NewManager(dir, "default", []string{"default"}, "", "../evil")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("expected load ok, got %v", err)
	}
	if p.Name != "default" {
		t.Fatalf("expected default fallback, got %s", p.Name)
	}
}

func TestManager_MissingFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "missing", []string{"missing"}, "", "missing")
	if _, err := m.Get(); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestManager_ManifestMismatch(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yml", "version: 1\nname: p\n")
	manifest := filepath.Join(dir, "manifest")
	if err := os.WriteFile(manifest, []byte("deadbeef  p.yml\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	m := NewManager(dir, "p", []string{"p"}, manifest, "p")
	if _, err := m.Get(); err == nil {
		t.Fatalf("expected hash mismatch error")
	}
}

func TestManager_LoadsOnceAndCaches(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yml", "version: 1\nname: p\n")
	manifest := filepath.Join(dir, "manifest")
	sum := hashFile(t, filepath.Join(dir, "p.yml"))
	if err := os.WriteFile(manifest, []byte(sum+"  p.yml\n"), 0o644); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	m := NewManager(dir, "p", []string{"p"}, manifest, "p")

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			if _, err := m.Get(); err != nil {
				t.Errorf("get err: %v", err)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	p1, _ := m.Get()
	p2, _ := m.Get()
	if p1 != p2 {
		t.Fatalf("expected cached policy pointer")
	}
}

// helpers
func writePolicy(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestManager_SigningEnforce_Valid(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")
	keyDir := t.TempDir()
	kid, err := signing.GenerateKeypair(keyDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = kid
	if err := signing.SignFile(filepath.Join(dir, "p.yaml"), filepath.Join(keyDir, "private.key.json"), "", ""); err != nil {
		t.Fatal(err)
	}
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

// setupSignedPolicyDir creates a policy, signs it, and returns (policyDir, trustStoreDir).
func setupSignedPolicyDir(t *testing.T, policyName, policyContent string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	writePolicy(t, dir, policyName+".yaml", policyContent)
	keyDir := t.TempDir()
	_, err := signing.GenerateKeypair(keyDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.SignFile(filepath.Join(dir, policyName+".yaml"), filepath.Join(keyDir, "private.key.json"), "", ""); err != nil {
		t.Fatal(err)
	}
	tsDir := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	os.WriteFile(filepath.Join(tsDir, "key.json"), pubData, 0o644)
	return dir, tsDir
}

func TestManager_SigningEnforce_TamperedPolicy(t *testing.T) {
	dir, tsDir := setupSignedPolicyDir(t, "p", "version: 1\nname: p\n")
	// Tamper with the policy after signing
	os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("version: 1\nname: tampered\n"), 0o644)
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("enforce", tsDir)
	_, err := m.Get()
	if err == nil {
		t.Fatal("expected error for tampered policy in enforce mode")
	}
}

func TestManager_SigningWarn_TamperedPolicy(t *testing.T) {
	dir, tsDir := setupSignedPolicyDir(t, "p", "version: 1\nname: p\n")
	// Tamper with the policy after signing
	os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("version: 1\nname: tampered\n"), 0o644)
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("warn", tsDir)
	p, err := m.Get()
	if err != nil {
		t.Fatalf("warn mode should still load tampered policy, got %v", err)
	}
	if p.Name != "tampered" {
		t.Fatalf("expected tampered, got %s", p.Name)
	}
}

func TestManager_SigningEnforce_WrongKey(t *testing.T) {
	dir, _ := setupSignedPolicyDir(t, "p", "version: 1\nname: p\n")
	// Create a different trust store with unrelated key
	otherKeyDir := t.TempDir()
	signing.GenerateKeypair(otherKeyDir, "other")
	otherTsDir := t.TempDir()
	pubData, _ := os.ReadFile(filepath.Join(otherKeyDir, "public.key.json"))
	os.WriteFile(filepath.Join(otherTsDir, "key.json"), pubData, 0o644)

	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("enforce", otherTsDir)
	_, err := m.Get()
	if err == nil {
		t.Fatal("expected error for wrong key in enforce mode")
	}
}

func TestManager_SigningEnforce_EmptyTrustStore(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("enforce", "")
	_, err := m.Get()
	if err == nil {
		t.Fatal("expected error for enforce mode with empty trust store")
	}
}

func TestManager_SigningWarn_EmptyTrustStore(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("warn", "")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("warn mode with empty trust store should still load, got %v", err)
	}
	if p.Name != "p" {
		t.Fatalf("expected p, got %s", p.Name)
	}
}

func TestManager_SigningOff_UnsignedPolicy(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "p.yaml", "version: 1\nname: p\n")
	// No signing, no sig file — off mode should not care
	m := NewManager(dir, "p", []string{"p"}, "", "p")
	m.SetSigningConfig("off", "/nonexistent")
	p, err := m.Get()
	if err != nil {
		t.Fatalf("off mode should always load, got %v", err)
	}
	if p.Name != "p" {
		t.Fatalf("expected p, got %s", p.Name)
	}
}
