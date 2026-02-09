//go:build linux && cgo

// internal/netmonitor/unix/execve_handler_test.go
package unix

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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

	result := h.Handle(context.Background(), ctx)
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

	result := h.Handle(context.Background(), ctx)
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

	result := h.Handle(context.Background(), ctx)
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

	result := h.Handle(context.Background(), ctx)
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

// TestExecveHandler_Action tests that the Action field is set correctly
// for all decision types in the exec pipeline.
func TestExecveHandler_Action(t *testing.T) {
	t.Run("allow produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "allow-git",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/git",
			Argv:      []string{"git", "status"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "allow", result.Decision)
	})

	t.Run("deny produces ActionDeny with EACCES", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "deny",
			EffectiveDecision: "deny",
			Rule:              "block-curl",
			Message:           "not allowed",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/curl",
			Argv:      []string{"curl", "http://evil.com"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
		assert.Equal(t, "deny", result.Decision)
	})

	t.Run("approve produces ActionRedirect", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "approve",
			EffectiveDecision: "approve",
			Rule:              "needs-approval",
			Message:           "requires human approval",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/rm",
			Argv:      []string{"rm", "-rf", "/important"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionRedirect, result.Action)
		assert.Equal(t, "approve", result.Decision)
	})

	t.Run("redirect produces ActionRedirect", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "redirect",
			EffectiveDecision: "redirect",
			Rule:              "redirect-rm",
			Message:           "redirecting to trash",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/rm",
			Argv:      []string{"rm", "file.txt"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionRedirect, result.Action)
		assert.Equal(t, "redirect", result.Decision)
	})

	t.Run("audit with effective allow produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "audit",
			EffectiveDecision: "allow",
			Rule:              "audit-npm",
			Message:           "logging npm usage",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/npm",
			Argv:      []string{"npm", "install"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "audit", result.Decision)
	})

	t.Run("internal bypass produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			InternalBypass: []string{"/usr/local/bin/agentsh"},
		}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/local/bin/agentsh",
			Argv:      []string{"agentsh", "exec"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "internal_bypass", result.Rule)
	})

	t.Run("no policy produces ActionContinue", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, nil, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/ls",
			Argv:      []string{"ls"},
		})

		require.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
		assert.Equal(t, "no_policy", result.Rule)
	})

	t.Run("truncated deny produces ActionDeny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{OnTruncated: "deny"}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
	})

	t.Run("truncated approval no approver produces ActionDeny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{OnTruncated: "approval"}
		dt := NewDepthTracker()
		h := NewExecveHandler(cfg, nil, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_no_approver", result.Reason)
	})

	t.Run("unknown effective decision produces ActionDeny (fail-secure)", func(t *testing.T) {
		cfg := ExecveHandlerConfig{}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "some_future_decision",
			EffectiveDecision: "some_future_decision",
			Rule:              "unknown-rule",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		h := NewExecveHandler(cfg, pol, dt, nil)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/mystery",
			Argv:      []string{"mystery"},
		})

		require.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, int32(unix.EACCES), result.Errno)
	})
}

// mockApprover implements ApprovalRequester for testing
type mockApprover struct {
	approved bool
	err      error
	called   bool
	gotReq   ApprovalRequest
}

func (m *mockApprover) RequestExecApproval(ctx context.Context, req ApprovalRequest) (bool, error) {
	m.called = true
	m.gotReq = req
	return m.approved, m.err
}

func TestExecveHandler_TruncatedApproval_Approved(t *testing.T) {
	cfg := ExecveHandlerConfig{
		OnTruncated:     "approval",
		ApprovalTimeout: 5 * time.Second,
	}
	pol := &mockPolicy{decision: PolicyDecision{
		Decision:          "allow",
		EffectiveDecision: "allow",
		Rule:              "test-rule",
	}}
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-1")
	approver := &mockApprover{approved: true}
	h := NewExecveHandler(cfg, pol, dt, nil)
	h.SetApprover(approver)

	result := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something", "arg1"},
		Truncated: true,
	})

	require.True(t, approver.called)
	assert.Equal(t, "/usr/bin/something", approver.gotReq.Command)
	assert.Equal(t, []string{"something", "arg1"}, approver.gotReq.Args)
	// Approved — falls through to policy check → ActionContinue
	assert.True(t, result.Allow)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestExecveHandler_TruncatedApproval_Denied(t *testing.T) {
	cfg := ExecveHandlerConfig{
		OnTruncated:     "approval",
		ApprovalTimeout: 5 * time.Second,
	}
	dt := NewDepthTracker()
	approver := &mockApprover{approved: false}
	h := NewExecveHandler(cfg, nil, dt, nil)
	h.SetApprover(approver)

	result := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	})

	require.True(t, approver.called)
	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "truncated_approval_denied", result.Reason)
}

func TestExecveHandler_TruncatedApproval_Timeout(t *testing.T) {
	t.Run("timeout action deny", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "deny",
		}
		dt := NewDepthTracker()
		approver := &mockApprover{err: context.DeadlineExceeded}
		h := NewExecveHandler(cfg, nil, dt, nil)
		h.SetApprover(approver)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		assert.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_approval_timeout", result.Reason)
	})

	t.Run("timeout action allow", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "allow",
		}
		pol := &mockPolicy{decision: PolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "test-rule",
		}}
		dt := NewDepthTracker()
		dt.RegisterSession(1000, "sess-1")
		approver := &mockApprover{err: context.DeadlineExceeded}
		h := NewExecveHandler(cfg, pol, dt, nil)
		h.SetApprover(approver)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		// Timeout with "allow" action — falls through to policy check
		assert.True(t, result.Allow)
		assert.Equal(t, ActionContinue, result.Action)
	})

	t.Run("non-timeout error always denies even with allow action", func(t *testing.T) {
		cfg := ExecveHandlerConfig{
			OnTruncated:           "approval",
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: "allow",
		}
		dt := NewDepthTracker()
		approver := &mockApprover{err: fmt.Errorf("transport error")}
		h := NewExecveHandler(cfg, nil, dt, nil)
		h.SetApprover(approver)

		result := h.Handle(context.Background(), ExecveContext{
			PID:       1001,
			ParentPID: 1000,
			Filename:  "/usr/bin/something",
			Argv:      []string{"something"},
			Truncated: true,
		})

		require.True(t, approver.called)
		// Non-timeout error with "allow" action — still denies (fail-secure)
		assert.False(t, result.Allow)
		assert.Equal(t, ActionDeny, result.Action)
		assert.Equal(t, "truncated_approval_error", result.Reason)
	})
}

func TestExecveHandler_TruncatedApproval_NoApprover(t *testing.T) {
	cfg := ExecveHandlerConfig{OnTruncated: "approval"}
	dt := NewDepthTracker()
	h := NewExecveHandler(cfg, nil, dt, nil)
	// No approver set — fail-secure

	result := h.Handle(context.Background(), ExecveContext{
		PID:       1001,
		ParentPID: 1000,
		Filename:  "/usr/bin/something",
		Argv:      []string{"something"},
		Truncated: true,
	})

	assert.False(t, result.Allow)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, "truncated_no_approver", result.Reason)
}
