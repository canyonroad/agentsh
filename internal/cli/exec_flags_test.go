package cli

import "testing"

func TestExecCmd_HasArgv0Flag(t *testing.T) {
	cmd := newExecCmd()
	if cmd.Flags().Lookup("argv0") == nil {
		t.Fatalf("expected exec command to define --argv0 flag")
	}
}

