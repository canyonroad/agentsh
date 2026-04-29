package skillcheck

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadSkill_Minimal(t *testing.T) {
	ref, files, err := LoadSkill(filepath.FromSlash("testdata/skills/minimal"), DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("LoadSkill: %v", err)
	}
	if ref.Name != "minimal" {
		t.Errorf("name=%q want minimal", ref.Name)
	}
	if ref.Manifest.Description == "" {
		t.Errorf("description should be parsed")
	}
	if len(ref.SHA256) != 64 {
		t.Errorf("SHA256 should be 64 hex chars, got %d", len(ref.SHA256))
	}
	if _, ok := files["SKILL.md"]; !ok {
		t.Errorf("file map should contain SKILL.md, got keys: %v", keysOf(files))
	}
}

func TestLoadSkill_DeterministicHash(t *testing.T) {
	r1, _, err := LoadSkill(filepath.FromSlash("testdata/skills/minimal"), DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("LoadSkill #1: %v", err)
	}
	r2, _, err := LoadSkill(filepath.FromSlash("testdata/skills/minimal"), DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("LoadSkill #2: %v", err)
	}
	if r1.SHA256 != r2.SHA256 {
		t.Errorf("hash should be deterministic; got %s vs %s", r1.SHA256, r2.SHA256)
	}
}

func TestLoadSkill_AllowedFrontmatter(t *testing.T) {
	ref, _, err := LoadSkill(filepath.FromSlash("testdata/skills/with-allowed"), DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("LoadSkill: %v", err)
	}
	if len(ref.Manifest.Allowed) != 2 {
		t.Errorf("expected 2 allowed entries, got %v", ref.Manifest.Allowed)
	}
	if ref.Manifest.Allowed[0] != "read" || ref.Manifest.Allowed[1] != "bash" {
		t.Errorf("allowed=%v", ref.Manifest.Allowed)
	}
}

func TestLoadSkill_PerFileLimit(t *testing.T) {
	limits := LoaderLimits{PerFileBytes: 1024, TotalBytes: 1 << 30}
	_, _, err := LoadSkill(filepath.FromSlash("testdata/skills/oversized"), limits)
	if err == nil {
		t.Fatalf("expected per-file size error, got nil")
	}
	if !strings.Contains(err.Error(), "per-file size limit") {
		t.Errorf("error should mention per-file size limit; got %v", err)
	}
}

func TestLoadSkill_SourceFromManifest(t *testing.T) {
	ref, _, err := LoadSkill(filepath.FromSlash("testdata/skills/git-origin"), DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("LoadSkill: %v", err)
	}
	if ref.Manifest.Source != "https://github.com/example/skills" {
		t.Errorf("source=%q", ref.Manifest.Source)
	}
	// Origin from .git/config: not set because no .git here. Loader should
	// fall back to manifest.Source.
	if ref.Origin == nil || ref.Origin.URL != "https://github.com/example/skills" {
		t.Errorf("origin=%+v want URL=https://github.com/example/skills", ref.Origin)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLoadSkill_RejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows; covered on unix")
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "SKILL.md"), []byte("---\nname: x\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Plant a symlink that would otherwise pull in /etc/passwd content.
	if err := os.Symlink("/etc/passwd", filepath.Join(tmp, "evil.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := LoadSkill(tmp, DefaultLoaderLimits())
	if err == nil {
		t.Fatalf("expected error for skill containing symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlinks; got %v", err)
	}
}
