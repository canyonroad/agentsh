package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCobraRestore_ForwardsToken(t *testing.T) {
	// Use a real temp dir as TrashDir so runRestore's guard (`c.TrashDir == ""`)
	// does not fire. With TrashDir set and the token forwarded, the inner CLI
	// calls trash.Restore, which fails with "restore: ..." because the token
	// doesn't exist in trash. That error path never prints the "<token>"
	// placeholder. Without the fix (args dropped), runRestore receives
	// args=[] → len(args)<1 → prints the usage line that contains "<token>".
	// Asserting that "<token>" is absent therefore distinguishes forwarded from
	// dropped.
	tmpDir := t.TempDir()
	cmd := newSkillcheckCmdWith(skillcheckConfig{TrashDir: tmpDir})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"restore", "sometoken-xyz"})
	_ = cmd.ExecuteContext(context.Background())
	out := buf.String()
	// The usage message contains the literal "<token>" placeholder.
	// It only appears when args were not forwarded; a real restore call
	// (success or trash error) never prints it.
	if strings.Contains(out, "<token>") {
		t.Errorf("cobra dropped restore token; got usage error: %s", out)
	}
}

func TestCobraCachePrune_ForwardsSubcommand(t *testing.T) {
	cmd := newSkillcheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"cache", "prune"})
	_ = cmd.ExecuteContext(context.Background())
	out := buf.String()
	// If "prune" is forwarded correctly, the inner CLI runCache receives
	// args=["prune"] and prints the deferred message.
	// If "prune" was dropped (old bug: argv=["cache"]), runCache receives
	// args=[] and returns "usage: agentsh skillcheck cache prune".
	if !strings.Contains(out, "deferred") {
		t.Errorf("cobra dropped 'prune'; expected deferred message, got: %s", out)
	}
}
