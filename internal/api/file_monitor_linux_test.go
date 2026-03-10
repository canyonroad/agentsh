//go:build linux && cgo

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
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
	engine, err := policy.NewEngine(pol, false, true)
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
	engine, err := policy.NewEngine(pol, false, true)
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

func TestMountFUSEForSession_RegistersMountPointNotSourcePath(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	mgr := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	require.NoError(t, os.MkdirAll(ws, 0o755))
	s, err := mgr.Create(ws, "default")
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Sandbox.FUSE.Enabled = true
	cfg.Sandbox.FUSE.Deferred = true
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Policies.Default = "default"

	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "allow-all", Domains: []string{"**"}, Decision: "allow"},
		},
	}, false, true)
	require.NoError(t, err)

	app := NewApp(cfg, mgr, store, engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)

	mfs := &mockFilesystem{}
	mfs.available.Store(true)

	ok := app.mountFUSEForSession(context.Background(), fuseMountParams{
		session:  s,
		engine:   engine,
		fs:       mfs,
		deferred: false,
	})
	require.True(t, ok, "expected mountFUSEForSession to succeed")

	reg := getMountRegistry()
	mountPoint := s.WorkspaceMountPath()

	// The mount point (not the source workspace path) should be registered.
	assert.True(t, reg.IsUnderFUSEMount(s.ID, mountPoint),
		"expected mount point %q to be registered in MountRegistry", mountPoint)

	// The source workspace path should NOT be registered — seccomp must not
	// defer enforcement for paths that FUSE is not actually overlaying.
	assert.False(t, reg.IsUnderFUSEMount(s.ID, s.Workspace),
		"source path %q should NOT be registered in MountRegistry (only mount points)", s.Workspace)

	// After unmount, the mount point should be deregistered.
	require.NoError(t, s.UnmountWorkspace())
	assert.False(t, reg.IsUnderFUSEMount(s.ID, mountPoint),
		"mount point %q should be deregistered after unmount", mountPoint)
}
