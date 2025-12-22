package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
