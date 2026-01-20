//go:build integration && linux

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
)

// TestExecveInterception_HandlerLogic tests the handler without actual seccomp
// This doesn't require root and tests the logic in isolation
//
// DEPTH SEMANTICS:
// - Session root (registered via RegisterSession) is at depth -1 (marker only)
// - First command from session root has depth 0 (direct user command)
// - Commands spawned by that command have depth 1+ (nested)
func TestExecveInterception_HandlerLogic(t *testing.T) {
	// Create a simple policy that blocks curl when nested (depth >= 1)
	// Depth 0 = direct command from session, depth 1+ = nested (spawned by scripts)
	pol := &policy.Policy{
		Version: 1,
		Name:    "test-policy",
		CommandRules: []policy.CommandRule{
			{
				Name:     "block-curl-nested",
				Commands: []string{"curl"},
				Decision: "deny",
				Context:  policy.ContextConfig{MinDepth: 1, MaxDepth: -1}, // depth >= 1 means nested
			},
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  policy.ContextConfig{MinDepth: 0, MaxDepth: -1},
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	// Create depth tracker and register a session
	dt := unixmon.NewDepthTracker()
	dt.RegisterSession(1000, "test-session")

	// Create handler config
	cfg := unixmon.ExecveHandlerConfig{
		MaxArgc:        1000,
		MaxArgvBytes:   65536,
		OnTruncated:    "deny",
		InternalBypass: []string{"/usr/local/bin/agentsh"},
	}

	// Create wrapper that adapts policy.Engine to PolicyChecker
	policyWrapper := &policyEngineWrapper{engine: engine}
	h := unixmon.NewExecveHandler(cfg, policyWrapper, dt, nil)

	// Test 1: Direct curl should be allowed (depth 0, i.e. direct from session)
	t.Run("direct curl allowed", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1001,
			ParentPID: 1000, // Parent is session root at depth -1
			Filename:  "/usr/bin/curl",
			Argv:      []string{"curl", "http://example.com"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow, "direct curl (depth 0) should be allowed")
	})

	// Test 2: Nested curl should be blocked (depth >= 1)
	t.Run("nested curl blocked", func(t *testing.T) {
		// First allow a shell (direct, depth 0)
		shellCtx := unixmon.ExecveContext{
			PID:       1002,
			ParentPID: 1000,
			Filename:  "/bin/sh",
			Argv:      []string{"sh", "-c", "curl http://example.com"},
			Truncated: false,
		}
		shellResult := h.Handle(shellCtx)
		assert.True(t, shellResult.Allow, "shell should be allowed")

		// Now curl from the shell is nested (depth 1)
		curlCtx := unixmon.ExecveContext{
			PID:       1003,
			ParentPID: 1002, // Parent is shell at depth 0
			Filename:  "/usr/bin/curl",
			Argv:      []string{"curl", "http://example.com"},
			Truncated: false,
		}
		curlResult := h.Handle(curlCtx)
		assert.False(t, curlResult.Allow, "nested curl (depth 1) should be blocked")
	})

	// Test 3: Internal bypass
	t.Run("internal bypass", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1004,
			ParentPID: 1000,
			Filename:  "/usr/local/bin/agentsh",
			Argv:      []string{"agentsh", "exec"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow, "agentsh should bypass")
		assert.Equal(t, "internal_bypass", result.Rule)
	})

	// Test 4: Truncated args denied
	t.Run("truncated args denied", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1005,
			ParentPID: 1000,
			Filename:  "/bin/echo",
			Argv:      []string{"echo", "hello"},
			Truncated: true,
		}
		result := h.Handle(ctx)
		assert.False(t, result.Allow, "truncated should be denied")
		assert.Equal(t, "truncated", result.Reason)
	})
}

// TestExecveInterception_DepthTracking tests the depth tracker integration
// Session root is at depth -1, first command is depth 0, and so on.
func TestExecveInterception_DepthTracking(t *testing.T) {
	// Create a policy that denies commands at depth >= 3
	// (depth 0-2 allowed, depth 3+ denied)
	pol := &policy.Policy{
		Version: 1,
		Name:    "depth-test-policy",
		CommandRules: []policy.CommandRule{
			{
				Name:     "deny-deep-nesting",
				Commands: []string{"*"},
				Decision: "deny",
				Context:  policy.ContextConfig{MinDepth: 3, MaxDepth: -1},
			},
			{
				Name:     "allow-shallow",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  policy.ContextConfig{MinDepth: 0, MaxDepth: 2},
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	dt := unixmon.NewDepthTracker()
	dt.RegisterSession(1000, "test-session") // depth -1

	cfg := unixmon.ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}

	policyWrapper := &policyEngineWrapper{engine: engine}
	h := unixmon.NewExecveHandler(cfg, policyWrapper, dt, nil)

	// Execute a chain: shell -> script -> nested command
	// Depth 0: first shell (from session root at depth -1)
	t.Run("depth 0 - direct command", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1001,
			ParentPID: 1000, // session root
			Filename:  "/bin/bash",
			Argv:      []string{"bash"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow, "depth 0 should be allowed")
	})

	// Depth 1: script from bash
	t.Run("depth 1 - nested", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1002,
			ParentPID: 1001,
			Filename:  "/usr/local/bin/script.sh",
			Argv:      []string{"script.sh"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow, "depth 1 should be allowed")
	})

	// Depth 2: command from script
	t.Run("depth 2 - double nested", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1003,
			ParentPID: 1002,
			Filename:  "/bin/ls",
			Argv:      []string{"ls", "-la"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow, "depth 2 should be allowed")
	})

	// Depth 3: should be denied
	t.Run("depth 3 - too deep", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1004,
			ParentPID: 1003,
			Filename:  "/bin/cat",
			Argv:      []string{"cat", "file.txt"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.False(t, result.Allow, "depth 3 should be denied")
	})
}

// TestExecveInterception_SessionIsolation tests that sessions are properly isolated
func TestExecveInterception_SessionIsolation(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Name:    "session-test-policy",
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  policy.ContextConfig{MinDepth: 0, MaxDepth: -1}, // all depths
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	dt := unixmon.NewDepthTracker()

	// Register two separate sessions
	dt.RegisterSession(1000, "session-A")
	dt.RegisterSession(2000, "session-B")

	cfg := unixmon.ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}

	policyWrapper := &policyEngineWrapper{engine: engine}
	h := unixmon.NewExecveHandler(cfg, policyWrapper, dt, nil)

	// Execute commands in session A
	t.Run("session A command", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/bin/echo",
			Argv:      []string{"echo", "hello"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow)

		// Verify session ID was set (after allow, PID is recorded)
		state, ok := dt.Get(1001)
		require.True(t, ok, "PID should be recorded after allow")
		assert.Equal(t, "session-A", state.SessionID)
		assert.Equal(t, 0, state.Depth) // Direct command from session root
	})

	// Execute commands in session B
	t.Run("session B command", func(t *testing.T) {
		ctx := unixmon.ExecveContext{
			PID:       2001,
			ParentPID: 2000,
			Filename:  "/bin/date",
			Argv:      []string{"date"},
			Truncated: false,
		}
		result := h.Handle(ctx)
		assert.True(t, result.Allow)

		// Verify session ID is different
		state, ok := dt.Get(2001)
		require.True(t, ok, "PID should be recorded after allow")
		assert.Equal(t, "session-B", state.SessionID)
		assert.Equal(t, 0, state.Depth) // Direct command from session root
	})

	// Cleanup session A and verify B still works
	t.Run("cleanup session A", func(t *testing.T) {
		dt.CleanupSession("session-A")

		// Session A PIDs should be gone
		_, ok := dt.Get(1001)
		assert.False(t, ok, "session A child PID should be cleaned up")
		_, ok = dt.Get(1000)
		assert.False(t, ok, "session A root PID should be cleaned up")

		// Session B PIDs should still exist
		state, ok := dt.Get(2001)
		assert.True(t, ok, "session B child PID should still exist")
		assert.Equal(t, "session-B", state.SessionID)

		state, ok = dt.Get(2000)
		assert.True(t, ok, "session B root PID should still exist")
		assert.Equal(t, "session-B", state.SessionID)
	})
}

// TestExecveInterception_NoPolicy tests behavior when no policy is configured
func TestExecveInterception_NoPolicy(t *testing.T) {
	dt := unixmon.NewDepthTracker()
	dt.RegisterSession(1000, "test-session")

	cfg := unixmon.ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}

	// No policy wrapper - nil policy
	h := unixmon.NewExecveHandler(cfg, nil, dt, nil)

	ctx := unixmon.ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/bin/anything",
		Argv:      []string{"anything"},
		Truncated: false,
	}

	result := h.Handle(ctx)
	assert.True(t, result.Allow, "should allow when no policy")
	assert.Equal(t, "no_policy", result.Rule)
}

// TestExecveInterception_TruncationPolicies tests different truncation handling modes
func TestExecveInterception_TruncationPolicies(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Name:    "test-policy",
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  policy.ContextConfig{MinDepth: 0, MaxDepth: -1}, // all depths
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	tests := []struct {
		name        string
		onTruncated string
		expectAllow bool
		expectRule  string
	}{
		{"deny on truncated", "deny", false, ""},
		{"allow on truncated (falls through to policy)", "allow", true, "allow-all"},
		{"approval on truncated", "approval", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dt := unixmon.NewDepthTracker()
			dt.RegisterSession(1000, "test-session")

			cfg := unixmon.ExecveHandlerConfig{
				MaxArgc:      1000,
				MaxArgvBytes: 65536,
				OnTruncated:  tt.onTruncated,
			}

			policyWrapper := &policyEngineWrapper{engine: engine}
			h := unixmon.NewExecveHandler(cfg, policyWrapper, dt, nil)

			ctx := unixmon.ExecveContext{
				PID:       1001,
				ParentPID: 1000,
				Filename:  "/bin/echo",
				Argv:      []string{"echo"},
				Truncated: true,
			}

			result := h.Handle(ctx)
			assert.Equal(t, tt.expectAllow, result.Allow, "truncation policy %s failed", tt.onTruncated)
			if tt.expectRule != "" {
				assert.Equal(t, tt.expectRule, result.Rule)
			}
		})
	}
}

// policyEngineWrapper adapts policy.Engine to unixmon.PolicyChecker
type policyEngineWrapper struct {
	engine *policy.Engine
}

func (w *policyEngineWrapper) CheckExecve(filename string, argv []string, depth int) unixmon.PolicyDecision {
	dec := w.engine.CheckExecve(filename, argv, depth)
	return unixmon.PolicyDecision{
		Decision:          string(dec.PolicyDecision),
		EffectiveDecision: string(dec.EffectiveDecision),
		Rule:              dec.Rule,
		Message:           dec.Message,
	}
}
