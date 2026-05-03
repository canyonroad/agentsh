//go:build linux

package api

import (
	"os/exec"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_PopulatesWrapperBinary verifies that wrap-init with
// Mode=="shim" returns the same shape of response as agent mode: a populated
// WrapperBinary. We deliberately do NOT short-circuit on the server based on
// which features are configured — there is no maintainable predicate that
// covers every wrapper-install path (the seccomp wrapper installs filters
// for several non-notify configs too: errno/kill blocks, blocked socket
// families, block_io_uring), and any partial predicate is a silent
// policy-bypass risk. The shim always installs in mode=auto/on; mode=off
// is the explicit operator opt-out.
func TestWrapInit_ShimMode_PopulatesWrapperBinary(t *testing.T) {
	if _, err := exec.LookPath("agentsh-unixwrap"); err != nil {
		t.Skip("agentsh-unixwrap not on PATH; cannot exercise wrap-init success path")
	}

	cfg := &config.Config{}
	// Match the gate that the historical agent-mode tests use to reach the
	// populated path. Look at wrap_test.go for the canonical setup.
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
		t.Fatal("got empty WrapperBinary; shim mode must return the same shape as agent mode (no server-side install/skip predicate)")
	}
	if resp.NotifySocket == "" {
		t.Fatal("got empty NotifySocket; expected a populated socket path")
	}
}
