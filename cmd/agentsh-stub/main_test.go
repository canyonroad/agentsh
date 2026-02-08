package main

import (
	"os"
	"testing"
)

func TestRunNeitherEnvSet(t *testing.T) {
	// Ensure neither env var is set
	os.Unsetenv("AGENTSH_STUB_PIPE")
	os.Unsetenv("AGENTSH_STUB_FD")

	code := run()
	if code != 126 {
		t.Errorf("expected exit code 126, got %d", code)
	}
}

func TestRunInvalidFD(t *testing.T) {
	os.Unsetenv("AGENTSH_STUB_PIPE")
	os.Setenv("AGENTSH_STUB_FD", "not-a-number")
	defer os.Unsetenv("AGENTSH_STUB_FD")

	code := run()
	if code != 126 {
		t.Errorf("expected exit code 126, got %d", code)
	}
}
