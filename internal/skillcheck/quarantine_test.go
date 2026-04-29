package skillcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/trash"
)

func TestTrashQuarantine_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "evil-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	skillContent := []byte("# evil")
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), skillContent, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	trashDir := filepath.Join(dir, ".trash")
	q := NewTrashQuarantiner(trashDir)
	token, err := q.Quarantine(SkillRef{Name: "evil-skill", Path: skillDir}, "test reason")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
	if _, err := os.Stat(skillDir); !os.IsNotExist(err) {
		t.Errorf("expected skill dir to be removed; stat err=%v", err)
	}

	// Round-trip: the returned token must identify a restorable entry.
	// Restore to a fresh path so we don't collide with the now-removed source.
	restoreDest := filepath.Join(dir, "restored-skill")
	out, err := trash.Restore(trashDir, token, restoreDest, false)
	if err != nil {
		t.Fatalf("Restore with token %q: %v", token, err)
	}
	if out == "" {
		t.Fatalf("Restore returned empty path")
	}
	// Verify the SKILL.md inside the restored tree matches the original.
	got, err := os.ReadFile(filepath.Join(out, "SKILL.md"))
	if err != nil {
		t.Fatalf("read restored SKILL.md: %v", err)
	}
	if string(got) != string(skillContent) {
		t.Errorf("restored content mismatch: got %q want %q", got, skillContent)
	}
}
