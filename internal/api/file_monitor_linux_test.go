//go:build linux && cgo

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateFileHandler_Disabled(t *testing.T) {
	cfg := config.SandboxSeccompFileMonitorConfig{Enabled: false}
	h := createFileHandler(cfg, nil, nil)
	assert.Nil(t, h)
}

func TestCreateFileHandler_Enabled(t *testing.T) {
	cfg := config.SandboxSeccompFileMonitorConfig{
		Enabled:            true,
		EnforceWithoutFUSE: true,
	}
	h := createFileHandler(cfg, nil, nil)
	assert.NotNil(t, h)
}

func TestCreateFileHandler_NilPolicy(t *testing.T) {
	cfg := config.SandboxSeccompFileMonitorConfig{
		Enabled:            true,
		EnforceWithoutFUSE: true,
	}
	h := createFileHandler(cfg, nil, nil)
	require.NotNil(t, h)

	// With nil policy, Handle should return ActionContinue
	result := h.Handle(unixmon.FileRequest{
		PID:       1,
		Path:      "/any/path",
		Operation: "open",
	})
	assert.Equal(t, unixmon.ActionContinue, result.Action)
}

func TestCreateFileHandler_EnforceWithoutFUSE(t *testing.T) {
	// Create a policy engine that denies /etc/** for open operations.
	pol := &policy.Policy{
		Version: 1,
		Name:    "test-deny-etc",
		FileRules: []policy.FileRule{
			{
				Name:       "deny-etc",
				Paths:      []string{"/etc/**"},
				Operations: []string{"open"},
				Decision:   "deny",
				Message:    "denied by test policy",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	t.Run("enforce_false_allows_denied", func(t *testing.T) {
		cfg := config.SandboxSeccompFileMonitorConfig{
			Enabled:            true,
			EnforceWithoutFUSE: false, // audit-only
		}
		h := createFileHandler(cfg, engine, nil)
		require.NotNil(t, h)

		result := h.Handle(unixmon.FileRequest{
			PID:       1,
			Path:      "/etc/shadow",
			Operation: "open",
		})
		assert.Equal(t, unixmon.ActionContinue, result.Action,
			"audit-only mode should allow even when policy denies")
	})

	t.Run("enforce_true_denies", func(t *testing.T) {
		cfg := config.SandboxSeccompFileMonitorConfig{
			Enabled:            true,
			EnforceWithoutFUSE: true, // enforcing
		}
		h := createFileHandler(cfg, engine, nil)
		require.NotNil(t, h)

		result := h.Handle(unixmon.FileRequest{
			PID:       1,
			Path:      "/etc/shadow",
			Operation: "open",
		})
		assert.Equal(t, unixmon.ActionDeny, result.Action,
			"enforce mode should deny when policy denies")
	})
}

func TestFilePolicyEngineWrapper_CheckFile(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Name:    "test-wrapper",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-home",
				Paths:      []string{"/home/**"},
				Operations: []string{"open", "write"},
				Decision:   "allow",
			},
			{
				Name:       "deny-etc",
				Paths:      []string{"/etc/**"},
				Operations: []string{"open"},
				Decision:   "deny",
				Message:    "etc is off limits",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false)
	require.NoError(t, err)

	w := &filePolicyEngineWrapper{engine: engine}

	t.Run("allow_decision", func(t *testing.T) {
		dec := w.CheckFile("/home/user/file.txt", "open")
		assert.Equal(t, "allow", dec.Decision)
		assert.Equal(t, "allow", dec.EffectiveDecision)
		assert.Equal(t, "allow-home", dec.Rule)
	})

	t.Run("deny_decision", func(t *testing.T) {
		dec := w.CheckFile("/etc/shadow", "open")
		assert.Equal(t, "deny", dec.Decision)
		assert.Equal(t, "deny", dec.EffectiveDecision)
		assert.Equal(t, "deny-etc", dec.Rule)
		assert.Equal(t, "etc is off limits", dec.Message)
	})

	t.Run("default_deny_for_unmatched", func(t *testing.T) {
		dec := w.CheckFile("/var/log/syslog", "open")
		assert.Equal(t, "deny", dec.Decision)
		assert.Equal(t, "deny", dec.EffectiveDecision)
		assert.Equal(t, "default-deny-files", dec.Rule)
	})
}

func TestGetMountRegistry_Singleton(t *testing.T) {
	r1 := getMountRegistry()
	r2 := getMountRegistry()
	assert.Same(t, r1, r2)
}
