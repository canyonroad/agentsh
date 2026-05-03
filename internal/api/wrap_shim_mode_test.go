//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_NothingEnabled verifies that shim-mode wrap-init
// returns an empty response (no WrapperBinary, no NotifySocket) when neither
// the seccomp wrapper nor Landlock are configured. The shim treats absent
// WrapperBinary as the skip signal and falls through to the existing
// agentsh-exec proxy path. (We intentionally do NOT use a boolean
// install_required field — see pkg/types/sessions.go's WrapInitResponse
// doc comment for why presence-of-WrapperBinary is the fail-closed choice.)
func TestWrapInit_ShimMode_NothingEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = func(b bool) *bool { return &b }(false)
	cfg.Landlock.Enabled = false

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/bash",
		AgentArgs:    []string{"-c", "echo hi"},
		Mode:         "shim",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("got code %d, want 200", code)
	}
	if resp.WrapperBinary != "" {
		t.Fatalf("got WrapperBinary=%q, want empty (nothing enabled)", resp.WrapperBinary)
	}
	if resp.NotifySocket != "" {
		t.Fatalf("got NotifySocket=%q, want empty (nothing enabled)", resp.NotifySocket)
	}
}
