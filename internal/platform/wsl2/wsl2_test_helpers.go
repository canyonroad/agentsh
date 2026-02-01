//go:build windows

package wsl2

import (
	"os"
	"testing"
)

// skipIfWSLUnavailable skips tests that require a fully functional WSL2 environment.
// These tests should only run in environments where WSL2 is properly configured
// and running (e.g., in CI with WSL2 setup, or on a developer machine with WSL2).
//
// Set AGENTSH_TEST_WSL2=1 to explicitly enable these tests.
func skipIfWSLUnavailable(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTSH_TEST_WSL2") != "1" {
		t.Skip("WSL2 tests require AGENTSH_TEST_WSL2=1 (WSL2 must be properly configured)")
	}
}
