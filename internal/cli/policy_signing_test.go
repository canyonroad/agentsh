package cli

import (
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
	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"keygen", "--output", dir, "--label", "test"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nname: test\n"), 0o644)
	cmd = newPolicyCmd()
	cmd.SetArgs([]string{"sign", policyPath, "--key", filepath.Join(dir, "private.key.json")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if _, err := os.Stat(policyPath + ".sig"); err != nil {
		t.Fatal("sig file not created")
	}
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
