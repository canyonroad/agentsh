package api

import (
	"encoding/json"
	"runtime"
	"strings"
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
	return NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil)
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

func TestSetupSeccompWrapper_FileMonitorDefaults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled

	app := newTestAppForSeccomp(t, cfg)

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)
	if result == nil || result.extraCfg == nil {
		t.Fatal("expected non-nil wrapper setup result with extraCfg")
	}
	defer func() {
		if result.extraCfg.notifyParentSock != nil {
			result.extraCfg.notifyParentSock.Close()
		}
		for _, f := range result.extraCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}()

	seccompJSON, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
	if !ok {
		t.Fatal("AGENTSH_SECCOMP_CONFIG env var not set")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(seccompJSON), &parsed); err != nil {
		t.Fatalf("unmarshal seccomp config: %v\n%s", err, seccompJSON)
	}

	if got, _ := parsed["file_monitor_enabled"].(bool); !got {
		t.Fatalf("file_monitor_enabled = %v, want true (JSON: %s)", got, seccompJSON)
	}
	if got, _ := parsed["intercept_metadata"].(bool); !got {
		t.Fatalf("intercept_metadata = %v, want true (JSON: %s)", got, seccompJSON)
	}
	if got, _ := parsed["block_io_uring"].(bool); !got {
		t.Fatalf("block_io_uring = %v, want true (JSON: %s)", got, seccompJSON)
	}
}

func TestBuildSeccompWrapperConfig_WriteOnlyOpensDefaultsFromInterceptMetadata(t *testing.T) {
	trueVal := true
	falseVal := false

	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &trueVal
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &trueVal
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &falseVal
	app := newTestAppForSeccomp(t, cfg)

	got := app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if !got.WriteOnlyOpens {
		t.Fatal("write_only_opens should default true when intercept_metadata is false")
	}

	cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens = &falseVal
	got = app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WriteOnlyOpens {
		t.Fatal("explicit write_only_opens=false should override the intercept_metadata-derived default")
	}

	cfg.Sandbox.Seccomp.FileMonitor.WriteOnlyOpens = nil
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &trueVal
	got = app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WriteOnlyOpens {
		t.Fatal("write_only_opens should default false when intercept_metadata is true")
	}
}

func TestSetupSeccompWrapper_WriteOnlyOpensForwarded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	disabled := false
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled

	app := newTestAppForSeccomp(t, cfg)
	result := app.setupSeccompWrapper(types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}, "test-session", nil)
	if result == nil || result.extraCfg == nil {
		t.Fatal("expected non-nil wrapper setup result with extraCfg")
	}
	defer func() {
		if result.extraCfg.notifyParentSock != nil {
			result.extraCfg.notifyParentSock.Close()
		}
		for _, f := range result.extraCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}()

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]), &parsed); err != nil {
		t.Fatalf("unmarshal seccomp config: %v", err)
	}
	if got, _ := parsed["write_only_opens"].(bool); !got {
		t.Fatalf("write_only_opens = %v, want true", got)
	}
}

func TestSetupSeccompWrapper_PtraceSync_MitigationSetFamilyLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"

	app := newTestAppForSeccomp(t, cfg)
	addTestMitigationSet(t, cfg, "ptrace-sync-family", `
version: 1
id: ptrace-sync-family
seccomp:
  blocked_socket_families:
    - family: AF_ALG
      action: log
`)
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Ptrace.Trace.Execve = true
	cfg.Sandbox.Ptrace.Trace.File = false
	cfg.Sandbox.Ptrace.Trace.Network = false
	cfg.Sandbox.Ptrace.Trace.Signal = false
	app.ptraceTracer = struct{}{}

	req := types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"hello"},
	}

	result := app.setupSeccompWrapper(req, "test-session", nil)
	if result == nil || result.extraCfg == nil {
		t.Fatal("expected non-nil wrapper setup result with extraCfg")
	}
	defer func() {
		if result.extraCfg.notifyParentSock != nil {
			result.extraCfg.notifyParentSock.Close()
		}
		for _, f := range result.extraCfg.extraFiles {
			if f != nil {
				f.Close()
			}
		}
	}()

	if !result.extraCfg.ptraceSync {
		t.Fatal("expected ptrace sync when a mitigation-set socket family uses log")
	}
	if got := result.extraCfg.envInject["AGENTSH_PTRACE_SYNC"]; got != "1" {
		t.Fatalf("AGENTSH_PTRACE_SYNC = %q, want 1", got)
	}
}

func TestSeccompWrapperConfig_WaitKillable_JSON(t *testing.T) {
	cases := []struct {
		name       string
		in         *bool
		wantSubstr string
		wantAbsent bool
	}{
		{name: "absent", in: nil, wantAbsent: true},
		{name: "true", in: boolPtrLocal(true), wantSubstr: `"wait_killable":true`},
		{name: "false", in: boolPtrLocal(false), wantSubstr: `"wait_killable":false`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := seccompWrapperConfig{WaitKillable: tc.in}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(b)
			if tc.wantAbsent && strings.Contains(s, "wait_killable") {
				t.Fatalf("expected wait_killable to be omitted, got %s", s)
			}
			if !tc.wantAbsent && !strings.Contains(s, tc.wantSubstr) {
				t.Fatalf("expected %q in %s", tc.wantSubstr, s)
			}
		})
	}
}

func boolPtrLocal(v bool) *bool { return &v }

// TestBuildSeccompWrapperConfig_PropagatesWaitKillable asserts the
// boot-time decision stored on App flows through to every wrapper
// config. The test bypasses NewApp (and therefore the behavioral probe)
// by constructing App directly — it covers only the propagation contract.
// Issue #369.
func TestBuildSeccompWrapperConfig_PropagatesWaitKillable(t *testing.T) {
	app := &App{
		cfg:                  &config.Config{},
		waitKillableDecision: false,
		waitKillableSource:   "behavioral_probe",
	}
	got := app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WaitKillable == nil {
		t.Fatal("WaitKillable not set")
	}
	if *got.WaitKillable != false {
		t.Fatalf("want false, got true")
	}

	app.waitKillableDecision = true
	got = app.buildSeccompWrapperConfig(nil, seccompWrapperParams{})
	if got.WaitKillable == nil || *got.WaitKillable != true {
		t.Fatal("want &true after flipping decision")
	}
}
