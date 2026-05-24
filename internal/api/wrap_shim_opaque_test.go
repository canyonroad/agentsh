package api

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// Issue #375: the shim wrap-init guard must be interception-aware. With execve
// enforcement off, an opaque shim command is denied by the guard (403). With it
// on, the guard must let wrap-init proceed (the wrapper runs the command and
// inner execs are policed by CheckExecve).
func TestWrapInit_ShimGuard_OpaqueInterceptionAware(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	buildApp := func(t *testing.T, execve bool) (*App, *session.Manager) {
		enabled := true
		cfg := &config.Config{}
		cfg.Sandbox.UnixSockets.Enabled = &enabled
		cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
		cfg.Sandbox.Seccomp.Execve.Enabled = execve
		app, mgr := newTestAppForWrap(t, cfg)
		p := &policy.Policy{
			CommandRules: []policy.CommandRule{
				{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
				{Name: "allow-shells", Commands: []string{"sh", "bash", "dash", "zsh"}, Decision: "allow"},
			},
		}
		eng, err := policy.NewEngine(p, false, true)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		app.SwapPolicy(eng)
		return app, mgr
	}

	req := types.WrapInitRequest{
		Mode:         "shim",
		AgentCommand: "/bin/sh",
		AgentArgs:    []string{"-c", "echo $HOME | head"},
		CallerUID:    nonzeroTestUID(),
	}

	t.Run("no execve enforcement denies opaque (403)", func(t *testing.T) {
		app, mgr := buildApp(t, false)
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		_, code, err := app.wrapInitCore(s, s.ID, req)
		if code != http.StatusForbidden {
			t.Fatalf("code = %d (err=%v), want 403 (opaque denied by shim guard)", code, err)
		}
	})

	t.Run("execve enforcement lets opaque proceed (not 403)", func(t *testing.T) {
		app, mgr := buildApp(t, true)
		s, err := mgr.Create(t.TempDir(), "default")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		resp, code, err := app.wrapInitCore(s, s.ID, req)
		if code == http.StatusForbidden {
			t.Fatalf("code = 403 (err=%v), want non-403 (opaque allowed when execve enforced)", err)
		}
		if resp.NotifySocket != "" {
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(resp.NotifySocket)) })
		}
	})
}
