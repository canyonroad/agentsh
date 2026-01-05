//go:build darwin

package main

import (
	"testing"
)

func TestValidateArgs_Valid(t *testing.T) {
	args := []string{"agentsh-macwrap", "--", "echo", "hello"}
	cmd, cmdArgs, err := validateArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != "echo" {
		t.Errorf("cmd = %q, want echo", cmd)
	}
	if len(cmdArgs) != 2 || cmdArgs[0] != "echo" || cmdArgs[1] != "hello" {
		t.Errorf("cmdArgs = %v, want [echo hello]", cmdArgs)
	}
}

func TestValidateArgs_MissingDash(t *testing.T) {
	args := []string{"agentsh-macwrap", "echo", "hello"}
	_, _, err := validateArgs(args)
	if err == nil {
		t.Error("expected error for missing --")
	}
}

func TestValidateArgs_NoCommand(t *testing.T) {
	args := []string{"agentsh-macwrap", "--"}
	_, _, err := validateArgs(args)
	if err == nil {
		t.Error("expected error for missing command")
	}
}
