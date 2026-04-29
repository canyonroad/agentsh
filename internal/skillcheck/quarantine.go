package skillcheck

import (
	"github.com/agentsh/agentsh/internal/trash"
)

// trashQuarantiner adapts internal/trash to the Quarantiner interface.
type trashQuarantiner struct {
	trashDir string
}

// NewTrashQuarantiner returns a Quarantiner backed by internal/trash. The
// trashDir is the soft-delete store (typically ~/.agentsh/skillcheck/trash).
func NewTrashQuarantiner(trashDir string) Quarantiner {
	return &trashQuarantiner{trashDir: trashDir}
}

func (q *trashQuarantiner) Quarantine(skill SkillRef, reason string) (string, error) {
	cfg := trash.Config{TrashDir: q.trashDir, Command: reason}
	entry, err := trash.Divert(skill.Path, cfg)
	if err != nil {
		return "", err
	}
	return entry.Token, nil
}
