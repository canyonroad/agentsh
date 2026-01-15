package api

import (
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func newTestAppForSeccomp(t *testing.T, cfg *config.Config) *App {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	return NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil)
}

func TestSetupSeccompWrapper_DisabledByConfig(t *testing.T) {
	// Test that wrapper is not used when unix_sockets.enabled is false
	enabled := false
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should return original request unchanged
	if result.wrappedReq.Command != "/bin/echo" {
		t.Errorf("expected command to be unchanged, got %q", result.wrappedReq.Command)
	}
	if result.extraCfg != nil {
		t.Error("expected extraCfg to be nil when wrapper disabled")
	}
}

func TestSetupSeccompWrapper_NilEnabled(t *testing.T) {
	// Test that wrapper is not used when unix_sockets.enabled is nil
	// (before defaults are applied)
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = nil

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should return original request unchanged
	if result.wrappedReq.Command != "/bin/echo" {
		t.Errorf("expected command to be unchanged, got %q", result.wrappedReq.Command)
	}
	if result.extraCfg != nil {
		t.Error("expected extraCfg to be nil when enabled is nil")
	}
}

func TestSetupSeccompWrapper_NonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test only runs on non-Linux platforms")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should return original request unchanged on non-Linux
	if result.wrappedReq.Command != "/bin/echo" {
		t.Errorf("expected command to be unchanged on non-Linux, got %q", result.wrappedReq.Command)
	}
	if result.extraCfg != nil {
		t.Error("expected extraCfg to be nil on non-Linux")
	}
}

func TestSetupSeccompWrapper_WrapperNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-12345"

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should return original request unchanged when wrapper not found
	if result.wrappedReq.Command != "/bin/echo" {
		t.Errorf("expected command to be unchanged when wrapper not found, got %q", result.wrappedReq.Command)
	}
	if result.extraCfg != nil {
		t.Error("expected extraCfg to be nil when wrapper not found")
	}
}

func TestSetupSeccompWrapper_Enabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	// Use a wrapper binary that exists - /bin/true is a good test stand-in
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello", "world"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should wrap the command
	if result.wrappedReq.Command != "/bin/true" {
		t.Errorf("expected command to be wrapper binary, got %q", result.wrappedReq.Command)
	}

	// Args should be: -- /bin/echo hello world
	expectedArgs := []string{"--", "/bin/echo", "hello", "world"}
	if len(result.wrappedReq.Args) != len(expectedArgs) {
		t.Errorf("expected %d args, got %d: %v", len(expectedArgs), len(result.wrappedReq.Args), result.wrappedReq.Args)
	} else {
		for i, arg := range expectedArgs {
			if result.wrappedReq.Args[i] != arg {
				t.Errorf("arg[%d]: expected %q, got %q", i, arg, result.wrappedReq.Args[i])
			}
		}
	}

	// extraCfg should be set
	if result.extraCfg == nil {
		t.Fatal("expected extraCfg to be non-nil when wrapper enabled")
	}

	// Original command should be preserved
	if result.extraCfg.origCommand != "/bin/echo" {
		t.Errorf("expected origCommand to be /bin/echo, got %q", result.extraCfg.origCommand)
	}

	// Should have notify socket FD env var
	if result.wrappedReq.Env["AGENTSH_NOTIFY_SOCK_FD"] != "3" {
		t.Errorf("expected AGENTSH_NOTIFY_SOCK_FD=3, got %q", result.wrappedReq.Env["AGENTSH_NOTIFY_SOCK_FD"])
	}

	// Should have seccomp config env var
	if _, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]; !ok {
		t.Error("expected AGENTSH_SECCOMP_CONFIG env var to be set")
	}

	// Clean up file descriptors
	if result.extraCfg.notifyParentSock != nil {
		result.extraCfg.notifyParentSock.Close()
	}
	for _, f := range result.extraCfg.extraFiles {
		if f != nil {
			f.Close()
		}
	}
}

func TestSetupSeccompWrapper_PreservesEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
		Env: map[string]string{
			"MY_VAR": "my_value",
		},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)

	// Should preserve existing env vars
	if result.wrappedReq.Env["MY_VAR"] != "my_value" {
		t.Errorf("expected MY_VAR to be preserved, got %q", result.wrappedReq.Env["MY_VAR"])
	}

	// Clean up
	if result.extraCfg != nil {
		if result.extraCfg.notifyParentSock != nil {
			result.extraCfg.notifyParentSock.Close()
		}
		for _, f := range result.extraCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}
}
