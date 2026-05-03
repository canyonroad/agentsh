//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_PopulatesWrapperBinary verifies that wrap-init with
// Mode=="shim" returns the same shape of response as agent mode: a populated
// WrapperBinary. We deliberately do NOT short-circuit on the server based on
// which features are configured — see the longer rationale in
// docs/superpowers/specs/2026-05-02-shim-kernel-enforcement-design.md.
func TestWrapInit_ShimMode_PopulatesWrapperBinary(t *testing.T) {
	cfg := &config.Config{}
	// Use /bin/true as a stable wrapper path so the test runs in any CI
	// without requiring agentsh-unixwrap to be preinstalled on PATH.
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.UnixSockets.Enabled = func(b bool) *bool { return &b }(true)

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
	if resp.WrapperBinary == "" {
		t.Fatal("got empty WrapperBinary; shim mode must return the same shape as agent mode")
	}
	if resp.NotifySocket == "" {
		t.Fatal("got empty NotifySocket; expected a populated socket path")
	}
}

// TestWrapInit_ShimMode_NoFeaturesConfigured covers the documented "no
// server-side install/skip predicate" contract: even when no enforcement
// features are explicitly enabled in cfg, the server still returns a
// populated WrapperBinary for Mode==shim (matching agent-mode behavior).
// The shim's mode=auto/on/off config governs install/skip; the server
// does not predict.
func TestWrapInit_ShimMode_NoFeaturesConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	// Note: NOT setting UnixSockets.Enabled, Landlock.Enabled, or any
	// Seccomp feature flags. This is the "operator forgot to enable
	// anything" config — the server still hands back a populated wrapper
	// response, leaving the install decision to the shim.

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
	if resp.WrapperBinary == "" {
		t.Fatal("server short-circuited (empty WrapperBinary) in shim mode; the spec mandates no server-side predicate")
	}
	if resp.NotifySocket == "" {
		t.Fatal("got empty NotifySocket; both WrapperBinary and NotifySocket must be populated for the install signal")
	}
}
