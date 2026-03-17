package cli

import "testing"

func TestParseExecInput_CommandLine(t *testing.T) {
	sid, req, err := parseExecInput([]string{"session-1", "--", "ls", "-la"}, "", "30s", false)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-1" || req.Command != "ls" || len(req.Args) != 1 || req.Args[0] != "-la" || req.Timeout != "30s" {
		t.Fatalf("unexpected parse result: sid=%q cmd=%q args=%v timeout=%q", sid, req.Command, req.Args, req.Timeout)
	}
}

func TestParseExecInput_JSON(t *testing.T) {
	sid, req, err := parseExecInput([]string{"session-1"}, `{"command":"pwd"}`, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-1" || req.Command != "pwd" {
		t.Fatalf("unexpected parse result: sid=%q cmd=%q", sid, req.Command)
	}
}

// Regression test: nested "--" inside the child command must be preserved
// as a regular argument, not treated as the agentsh separator.
// e.g. agentsh exec SESSION -- opencode run --format json -- "prompt"
// After Cobra strips the first "--", args is:
//   ["opencode", "run", "--format", "json", "--", "prompt"]
// The inner "--" belongs to opencode, not agentsh.
func TestParseExecInput_NestedDoubleDash(t *testing.T) {
	// Simulate what Cobra passes after stripping the outer "--":
	// agentsh exec SESSION -- opencode run --attach http://x --format json -- "prompt"
	args := []string{"opencode", "run", "--attach", "http://x", "--format", "json", "--", "Reply with VM_OK"}
	sid, req, err := parseExecInputWithEnv(args, "", "", false, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-1" {
		t.Errorf("session = %q, want session-1", sid)
	}
	if req.Command != "opencode" {
		t.Errorf("Command = %q, want opencode", req.Command)
	}
	wantArgs := []string{"run", "--attach", "http://x", "--format", "json", "--", "Reply with VM_OK"}
	if len(req.Args) != len(wantArgs) {
		t.Fatalf("Args = %v, want %v", req.Args, wantArgs)
	}
	for i, a := range wantArgs {
		if req.Args[i] != a {
			t.Errorf("Args[%d] = %q, want %q", i, req.Args[i], a)
		}
	}
}

// Same as above but with session ID in args (no env var).
func TestParseExecInput_NestedDoubleDash_WithSessionArg(t *testing.T) {
	// Format after Cobra: SESSION_ID opencode run ... -- prompt
	// (Cobra stripped the first --, so no "--" at position 1)
	args := []string{"session-1", "opencode", "run", "--format", "json", "--", "prompt"}
	sid, req, err := parseExecInput(args, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if sid != "session-1" {
		t.Errorf("session = %q, want session-1", sid)
	}
	if req.Command != "opencode" {
		t.Errorf("Command = %q, want opencode", req.Command)
	}
	// The inner "--" and "prompt" should be part of args
	if len(req.Args) != 5 {
		t.Fatalf("Args = %v, want 5 elements", req.Args)
	}
	if req.Args[3] != "--" || req.Args[4] != "prompt" {
		t.Errorf("Args = %v, expected '--' and 'prompt' at end", req.Args)
	}
}
