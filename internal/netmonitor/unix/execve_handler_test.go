// internal/netmonitor/unix/execve_handler_test.go
package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockPolicy implements PolicyChecker for testing
type mockPolicy struct {
	decision PolicyDecision
}

func (m *mockPolicy) CheckExecve(filename string, argv []string, depth int) PolicyDecision {
	return m.decision
}

func TestExecveHandler_Handle_Allow(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "allow", Rule: "allow-git"}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123")

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/git",
		Argv:      []string{"git", "status"},
		Truncated: false,
	}

	result := h.Handle(ctx)
	assert.True(t, result.Allow)
	assert.Equal(t, "allow-git", result.Rule)
}

func TestExecveHandler_Handle_Deny(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "deny", Rule: "block-curl"}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123")

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/curl",
		Argv:      []string{"curl", "http://evil.com"},
		Truncated: false,
	}

	result := h.Handle(ctx)
	assert.False(t, result.Allow)
}

func TestExecveHandler_Handle_TruncatedDeny(t *testing.T) {
	cfg := ExecveHandlerConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
		OnTruncated:  "deny",
	}
	pol := &mockPolicy{decision: PolicyDecision{Decision: "allow", Rule: "test"}}
	dt := NewDepthTracker()

	h := NewExecveHandler(cfg, pol, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	}

	result := h.Handle(ctx)
	assert.False(t, result.Allow)
	assert.Equal(t, "truncated", result.Reason)
}

func TestExecveHandler_Handle_InternalBypass(t *testing.T) {
	cfg := ExecveHandlerConfig{
		InternalBypass: []string{"/usr/local/bin/agentsh"},
	}
	// Policy should NOT be called for internal bypass
	dt := NewDepthTracker()

	h := NewExecveHandler(cfg, nil, dt, nil)

	ctx := ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/local/bin/agentsh",
		Argv:      []string{"agentsh", "exec"},
		Truncated: false,
	}

	result := h.Handle(ctx)
	assert.True(t, result.Allow)
	assert.Equal(t, "internal_bypass", result.Rule)
}

func TestExecveHandler_InternalBypass(t *testing.T) {
	cfg := ExecveHandlerConfig{
		InternalBypass: []string{
			"/usr/local/bin/agentsh",
			"/usr/local/bin/agentsh-*",
			"*.real",
		},
	}
	h := NewExecveHandler(cfg, nil, nil, nil)

	tests := []struct {
		filename string
		bypass   bool
	}{
		{"/usr/local/bin/agentsh", true},
		{"/usr/local/bin/agentsh-unixwrap", true},
		{"/bin/bash.real", true},
		{"/usr/bin/sh.real", true},
		{"/usr/bin/git", false},
		{"/bin/bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.bypass, h.isInternalBypass(tt.filename))
		})
	}
}
