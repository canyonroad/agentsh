//go:build darwin

package darwin

import (
	"io"
	"os"
	"testing"

	"github.com/agentsh/agentsh/internal/platform/darwin/xpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPolicyChecker implements ESExecPolicyChecker for testing.
type mockPolicyChecker struct {
	decision          string
	effectiveDecision string
	rule              string
	message           string

	// Capture the last call for verification.
	lastCmd  string
	lastArgs []string
}

func (m *mockPolicyChecker) CheckCommand(cmd string, args []string) ESExecPolicyResult {
	m.lastCmd = cmd
	m.lastArgs = args
	return ESExecPolicyResult{
		Decision:          m.decision,
		EffectiveDecision: m.effectiveDecision,
		Rule:              m.rule,
		Message:           m.message,
	}
}

func TestESExecHandler_PolicyMapping(t *testing.T) {
	tests := []struct {
		name              string
		decision          string
		effectiveDecision string
		wantAction        string
		wantDecision      string
	}{
		// Basic allow/deny/audit
		{"allow", "allow", "allow", "continue", "allow"},
		{"audit", "audit", "audit", "continue", "audit"},
		{"deny", "deny", "deny", "deny", "deny"},

		// Redirect and approve in enforced mode
		{"approve_enforced", "approve", "approve", "redirect", "approve"},
		{"redirect_enforced", "redirect", "redirect", "redirect", "redirect"},

		// Shadow mode: policy says approve/redirect but effective is allow
		// (shadow mode lets the command through while logging the policy intent)
		{"approve_shadow", "approve", "allow", "continue", "approve"},
		{"redirect_shadow", "redirect", "allow", "continue", "redirect"},

		// Shadow mode: policy says deny but effective is allow
		{"deny_shadow", "deny", "allow", "continue", "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &mockPolicyChecker{
				decision:          tt.decision,
				effectiveDecision: tt.effectiveDecision,
				rule:              "test-rule",
				message:           "test message",
			}
			handler := NewESExecHandler(checker, "")
			result := handler.CheckExec("/usr/bin/test", []string{"/usr/bin/test", "-f", "foo"}, 1234, 1233, "sess-1", xpc.ExecContext{})

			assert.Equal(t, tt.wantAction, result.Action, "action mismatch")
			assert.Equal(t, tt.wantDecision, result.Decision, "decision mismatch")
			assert.Equal(t, "test-rule", result.Rule, "rule mismatch")
			assert.Equal(t, "test message", result.Message, "message mismatch")
		})
	}
}

func TestESExecHandler_NilPolicyChecker(t *testing.T) {
	handler := NewESExecHandler(nil, "")
	result := handler.CheckExec("/usr/bin/test", nil, 1234, 1233, "sess-1", xpc.ExecContext{})

	assert.Equal(t, "continue", result.Action)
	assert.Equal(t, "allow", result.Decision)
	assert.Equal(t, "no_policy", result.Rule)
	assert.Empty(t, result.Message)
}

func TestESExecHandler_UnknownDecision(t *testing.T) {
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "something_unknown",
		effectiveDecision: "something_unknown",
		rule:              "weird-rule",
		message:           "weird message",
	}, "")
	result := handler.CheckExec("/usr/bin/test", nil, 1234, 1233, "sess-1", xpc.ExecContext{})

	// Unknown decisions should fail-secure (deny).
	assert.Equal(t, "deny", result.Action)
	assert.Equal(t, "something_unknown", result.Decision)
	assert.Equal(t, "unknown", result.Rule)
	assert.Equal(t, "unknown effective decision", result.Message)
}

func TestESExecHandler_EffectiveDecisionFallback(t *testing.T) {
	// When EffectiveDecision is empty, falls back to Decision.
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "allow",
		effectiveDecision: "", // empty
		rule:              "fallback-rule",
	}, "")
	result := handler.CheckExec("/usr/bin/ls", nil, 100, 99, "sess-2", xpc.ExecContext{})

	assert.Equal(t, "continue", result.Action)
	assert.Equal(t, "allow", result.Decision)
	assert.Equal(t, "fallback-rule", result.Rule)
}

func TestESExecHandler_PassesArgsToChecker(t *testing.T) {
	checker := &mockPolicyChecker{
		decision:          "allow",
		effectiveDecision: "allow",
		rule:              "check-args",
	}
	handler := NewESExecHandler(checker, "")

	args := []string{"/usr/bin/curl", "-s", "https://example.com"}
	handler.CheckExec("/usr/bin/curl", args, 5678, 5677, "sess-3", xpc.ExecContext{})

	assert.Equal(t, "/usr/bin/curl", checker.lastCmd)
	assert.Equal(t, args, checker.lastArgs)
}

func TestESExecHandler_RedirectSpawnsStub(t *testing.T) {
	// Verify that redirect decisions trigger the stub spawn goroutine.
	// We can't easily test the goroutine completes, but we can verify the
	// response is correct and no panic occurs.
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "redirect",
		effectiveDecision: "redirect",
		rule:              "redirect-rule",
		message:           "redirecting",
	}, "/usr/local/bin/agentsh-stub")

	result := handler.CheckExec("/usr/bin/git", []string{"/usr/bin/git", "push"}, 9999, 9998, "sess-4", xpc.ExecContext{})

	assert.Equal(t, "redirect", result.Action)
	assert.Equal(t, "redirect", result.Decision)
	assert.Equal(t, "redirect-rule", result.Rule)
	assert.Equal(t, "redirecting", result.Message)
}

func TestESExecHandler_ApproveSpawnsStub(t *testing.T) {
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "approve",
		effectiveDecision: "approve",
		rule:              "approve-rule",
		message:           "needs approval",
	}, "/usr/local/bin/agentsh-stub")

	result := handler.CheckExec("/usr/bin/rm", []string{"/usr/bin/rm", "-rf", "/"}, 1111, 1110, "sess-5", xpc.ExecContext{})

	assert.Equal(t, "redirect", result.Action)
	assert.Equal(t, "approve", result.Decision)
	assert.Equal(t, "approve-rule", result.Rule)
	assert.Equal(t, "needs approval", result.Message)
}

func TestNewESExecHandler(t *testing.T) {
	checker := &mockPolicyChecker{}
	handler := NewESExecHandler(checker, "/path/to/stub")

	require.NotNil(t, handler)
	assert.Equal(t, "/path/to/stub", handler.stubBinary)
	assert.Equal(t, checker, handler.policyChecker)
}

func TestCreateSocketPair(t *testing.T) {
	stubFile, srvConn, err := createSocketPair()
	require.NoError(t, err)
	defer stubFile.Close()
	defer srvConn.Close()

	// Write from server side, read from stub side.
	msg := []byte("hello from server")
	_, err = srvConn.Write(msg)
	require.NoError(t, err)

	// The stubFile is an *os.File wrapping one end of the socketpair.
	// Read from it to verify data flows through.
	buf := make([]byte, 64)
	n, err := stubFile.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, string(msg), string(buf[:n]))

	// Write from stub side, read from server side.
	msg2 := []byte("hello from stub")
	_, err = stubFile.Write(msg2)
	require.NoError(t, err)

	buf2 := make([]byte, 64)
	n2, err := io.ReadAtLeast(srvConn, buf2, len(msg2))
	require.NoError(t, err)
	assert.Equal(t, string(msg2), string(buf2[:n2]))
}

func TestLaunchStub_NoTTY(t *testing.T) {
	// When TTYPath is empty, launchStub should not panic and should
	// handle the missing binary gracefully (the stub binary doesn't exist in test).
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "redirect",
		effectiveDecision: "redirect",
	}, "/nonexistent/agentsh-stub")

	// Create a dummy file to pass as stubFile.
	tmpFile, err := os.CreateTemp("", "stub-test-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Should not panic, even with empty TTY and missing binary.
	handler.launchStub(tmpFile, "/usr/bin/test", 1234, xpc.ExecContext{
		CWDPath: "/tmp",
	})
}

func TestLaunchStub_MissingBinary(t *testing.T) {
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "redirect",
		effectiveDecision: "redirect",
	}, "") // empty stub binary

	tmpFile, err := os.CreateTemp("", "stub-test-*")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Should return early without panic when stub binary is empty.
	handler.launchStub(tmpFile, "/usr/bin/test", 1234, xpc.ExecContext{})
}

func TestSpawnStubServer_NoStubBinary(t *testing.T) {
	// Verify spawnStubServer returns early without panic when stubBinary is empty.
	handler := NewESExecHandler(&mockPolicyChecker{
		decision:          "redirect",
		effectiveDecision: "redirect",
	}, "") // empty stub binary

	// Should not panic.
	handler.spawnStubServer("/usr/bin/test", []string{"/usr/bin/test"}, 1234, 1233, "sess-1", xpc.ExecContext{})
}

// Compile-time interface check: ESExecHandler must implement xpc.ExecHandler.
var _ xpc.ExecHandler = (*ESExecHandler)(nil)
