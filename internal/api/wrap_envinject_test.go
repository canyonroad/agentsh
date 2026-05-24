package api

import (
	"os"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ResponseCarriesEnvInject is the regression guard for issue #374:
// on the client-spawned wrap (kernel-install) path the server never delivered
// sandbox.env_inject to the shim, so injected vars (e.g. BASH_ENV hardening)
// silently never reached executed commands. wrapInitCore must surface them in
// the response so the client can apply them.
func TestWrapInit_ResponseCarriesEnvInject(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.EnvInject = map[string]string{
		"BASH_ENV":          "/usr/lib/agentsh/bash_startup.sh",
		"OTEL_SERVICE_NAME": "agentsh-blaxel",
	}

	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    nonzeroTestUID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.NotifySocket != "" {
		t.Cleanup(func() { _ = os.RemoveAll(resp.NotifySocket) })
	}

	if got := resp.EnvInject["BASH_ENV"]; got != "/usr/lib/agentsh/bash_startup.sh" {
		t.Errorf("resp.EnvInject[BASH_ENV] = %q, want the configured hardening path", got)
	}
	if got := resp.EnvInject["OTEL_SERVICE_NAME"]; got != "agentsh-blaxel" {
		t.Errorf("resp.EnvInject[OTEL_SERVICE_NAME] = %q, want agentsh-blaxel", got)
	}
}
