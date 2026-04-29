package skillcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrashQuarantine_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "evil-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# evil"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	trashDir := filepath.Join(dir, ".trash")
	q := NewTrashQuarantiner(trashDir)
	token, err := q.Quarantine(SkillRef{Name: "evil-skill", Path: skillDir}, "test reason")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if token == "" {
		t.Errorf("expected non-empty token")
	}
	if _, err := os.Stat(skillDir); !os.IsNotExist(err) {
		t.Errorf("expected skill dir to be removed; stat err=%v", err)
	}
}
