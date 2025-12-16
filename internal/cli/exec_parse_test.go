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
