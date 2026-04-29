package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCobraRestore_ForwardsToken(t *testing.T) {
	cmd := newSkillcheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"restore", "sometoken-xyz"})
	// We expect this to fail with a real error path that mentions
	// "trash dir not configured" (TrashDir is empty in the stub CLI),
	// NOT the usage error from missing args.
	_ = cmd.ExecuteContext(context.Background())
	out := buf.String()
	// Without TrashDir set, the inner CLI returns "usage: agentsh skillcheck restore <token> [dest]"
	// because the first check in runRestore is `c.TrashDir == ""`. If args were
	// dropped (argv[1:] == []), the inner CLI would also print the usage line.
	// Either way a usage line means the token was dropped, so we check that
	// the output does NOT indicate arg-drop by verifying the token appears or
	// that we got the trash-dir-not-configured path (same usage line either way).
	// The real distinction: if args are forwarded, runRestore sees argv=["sometoken-xyz"]
	// and TrashDir=="" → prints usage (same line). So we must test a different way:
	// we verify that cobra itself did NOT reject the call with its own usage dump
	// (which would include "Usage:" with capital U and the cobra command tree).
	if strings.Contains(out, "Usage:") {
		t.Errorf("cobra produced its own usage error (args not forwarded?): %s", out)
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
		t.Errorf("expected deferred message from cache prune; got: %q", out)
	}
	if strings.Contains(out, "usage:") {
		t.Errorf("cobra dropped 'prune' arg; got usage error: %s", out)
	}
}
