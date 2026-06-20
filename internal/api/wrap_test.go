package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/require"
)

func newTestAppForWrap(t *testing.T, cfg *config.Config) (*App, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	app := NewApp(cfg, mgr, store, nil, broker, nil, nil, nil, nil, nil, nil, nil)
	return app, mgr
}

func addTestMitigationSet(t *testing.T, cfg *config.Config, id string, data string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(data), 0o600))
	cfg.Sandbox.Seccomp.MitigationSets = append(cfg.Sandbox.Seccomp.MitigationSets, id)
	cfg.Sandbox.Seccomp.MitigationDirs = append(cfg.Sandbox.Seccomp.MitigationDirs, dir)
}

func nonzeroTestUID() int {
	// UID 0 is the helper's fallback sentinel, so pick any nonzero UID for coverage.
	uid := os.Getuid()
	if uid == 0 {
		return 1
	}
	return uid
}

func TestSecureNotifyDir_ChownSuccess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureNotifyDir is Linux-only")
	}

	dir := t.TempDir()
	if got := secureNotifyDir(dir, nonzeroTestUID()); !got {
		t.Fatal("expected chown success path")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("expected 0700 permissions, got %04o", got)
	}
}

func TestSecureNotifyDir_CallerUIDZero_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureNotifyDir is Linux-only")
	}

	dir := t.TempDir()
	if got := secureNotifyDir(dir, 0); got {
		t.Fatal("expected fallback path")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0711 {
		t.Fatalf("expected 0711 permissions, got %04o", got)
	}
}

func TestSecureSocket_ChownOK(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureSocket is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "socket.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod socket before helper: %v", err)
	}

	secureSocket(sockPath, nonzeroTestUID(), true)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected socket mode to stay 0600, got %04o", got)
	}
}

func TestSecureSocket_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("secureSocket is Linux-only")
	}

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "socket.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod socket before helper: %v", err)
	}

	secureSocket(sockPath, os.Getuid(), false)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0666 {
		t.Fatalf("expected fallback socket mode 0666, got %04o", got)
	}
}

func TestWrapInit_NotifyDirPermissions_Fallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)
	app.ptraceTracer = struct{}{}

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	dirInfo, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0711 {
		t.Fatalf("expected fallback notify dir mode 0711, got %04o", got)
	}

	socketInfo, err := os.Stat(resp.NotifySocket)
	if err != nil {
		t.Fatalf("stat notify socket: %v", err)
	}
	if got := socketInfo.Mode().Perm(); got != 0666 {
		t.Fatalf("expected fallback notify socket mode 0666, got %04o", got)
	}
}

func TestWrapInit_NotifyDirPermissions_CallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
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

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	dirInfo, err := os.Stat(notifyDir)
	if err != nil {
		t.Fatalf("stat notify dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("expected caller-owned notify dir mode 0700, got %04o", got)
	}
}

func TestWrapInit_NotifyDirPermissions_ValidationFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	prevChmod := wrapChmod
	wrapChmod = func(string, os.FileMode) error { return nil }
	t.Cleanup(func() { wrapChmod = prevChmod })

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err == nil {
		t.Fatal("expected error when notify permissions are not established")
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", code)
	}
}

func TestWrapInit_SessionNotFound(t *testing.T) {
	cfg := &config.Config{}
	app, _ := newTestAppForWrap(t, cfg)

	_, ok := app.sessions.Get("nonexistent")
	if ok {
		t.Fatal("expected session not found")
	}
}

func TestWrapInit_NotLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test only runs on non-Linux platforms")
	}
	if runtime.GOOS == "windows" {
		t.Skip("wrap is supported on Windows via driver")
	}

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)

	// Create a session
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error on non-Linux")
	}
	if code != 400 {
		t.Errorf("expected status 400, got %d", code)
	}
}

// TestWrapInit_UnixSocketsExplicitlyDisabled covers issue #361
// (v0.20.0-rc1 regression): when the operator sets
// sandbox.unix_sockets.enabled=false, wrap-init must refuse to engage
// rather than returning a wrapper binary that the shim then launches
// against a server with no notify-fd handler — which manifests as
// "server rejected wrap setup" on Vercel/Daytona with empty stdout
// and exit 1. Mirrors the exec-path gate in core.go::setupSeccompWrapper.
func TestWrapInit_UnixSocketsExplicitlyDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.UnixSockets.Enabled = &disabled
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error when unix_sockets.enabled is false")
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", code)
	}
	if !strings.Contains(err.Error(), "unix_sockets.enabled is false") {
		t.Errorf("expected error to mention unix_sockets.enabled, got %q", err.Error())
	}
	if resp.WrapperBinary != "" || resp.NotifySocket != "" {
		t.Errorf("expected empty WrapperBinary/NotifySocket on refusal, got %+v", resp)
	}
}

// TestWrapInit_UnixSocketsNilDefaultsToEnabled verifies that the gate
// added for #361 only fires on an explicit false. A nil Enabled (which
// applyDefaults sets to true in production) must NOT short-circuit
// wrap-init — otherwise every test that builds a bare Config would
// regress.
func TestWrapInit_UnixSocketsNilDefaultsToEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	cfg := &config.Config{}
	// Sandbox.UnixSockets.Enabled is left nil (the pre-applyDefaults state).
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	// Should fall through to wrapper-resolution (errWrapperNotFound, 503),
	// NOT the unix_sockets gate.
	if err == nil {
		t.Fatal("expected wrapper-not-found error")
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", code)
	}
	if strings.Contains(err.Error(), "unix_sockets.enabled is false") {
		t.Errorf("nil Enabled must not trigger the unix_sockets gate, got %q", err.Error())
	}
}

// TestWrapInit_UnixSocketsDisabledButEBPFRequiresWrapper covers the
// override branch of the #361 gate: when pre-ACK cgroup/eBPF setup is
// required (Network.EBPF.Required, Cgroups.Enabled, etc.), the wrapper
// must still engage even with sandbox.unix_sockets.enabled=false, because
// the user-notify handoff is what keeps the wrapper alive long enough to
// attach eBPF before exec. Skipping in that case would silently disable
// eBPF enforcement.
//
// This is closely related to TestWrapInit_ForcesNotifyHandoffWhenEBPFRequiresPreAckCgroup
// but documents the gate from the unix_sockets side rather than the
// notify-handoff side.
func TestWrapInit_UnixSocketsDisabledButEBPFRequiresWrapper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	disabled := false
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &disabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Network.EBPF.Required = true
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("expected status 200 (eBPF override), got %d", code)
	}
	// Pin the assertion to the post-gate path: a 200 here could otherwise
	// come from an earlier branch (ptrace, etc.) that would also bypass
	// the gate accidentally. WrapperBinary is populated only in the main
	// path that follows the unix_sockets gate, so a non-empty value
	// uniquely proves the override branch was taken.
	if resp.WrapperBinary == "" {
		t.Errorf("expected WrapperBinary set (override branch must produce a wrapper), got empty")
	}
	if resp.NotifySocket == "" {
		t.Errorf("expected NotifySocket set (override branch must produce a socket), got empty")
	}
}

// TestWrapInit_UnixSocketsDisabledWithPolicyLimitsButNoCgroup covers the
// follow-up regression reported in #361 after the initial 093e1852 fix.
// secure-sandbox presets ship policy resource_limits (max_memory_mb /
// cpu_quota_percent / pids_max) for every adapter. Before this fix,
// wrapNeedsCgroupBeforeAck returned true whenever ANY policy limit was
// non-zero, which forced the wrapper to engage on hosts that disabled
// BOTH unix_sockets AND cgroups — defeating the unix_sockets gate. The
// wrapper then loaded its seccomp filter, the server tried to apply
// cgroups, applyCgroupV2 returned CgroupResourceLimitsUnavailableError
// (no soft-fail), and the user's command silently died (empty stdout,
// exit 1) — the same symptom this issue is supposed to prevent.
//
// With policy limits but no cgroup/eBPF enforcement configured, the
// limits cannot be enforced anyway, so the wrapper must NOT engage and
// the gate must fire.
func TestWrapInit_UnixSocketsDisabledWithPolicyLimitsButNoCgroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.UnixSockets.Enabled = &disabled
	// Explicitly leave Cgroups / Network.EBPF unconfigured — mirrors the
	// Vercel/Daytona/Firecracker server config from secure-sandbox.

	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		ResourceLimits: policy.ResourceLimits{
			MaxMemoryMB:     8192,
			CPUQuotaPercent: 100,
			PidsMax:         500,
		},
		CommandRules: []policy.CommandRule{
			{Name: "allow-all", Commands: []string{}, Decision: "allow"},
		},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, wrapErr := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})
	if wrapErr == nil {
		t.Fatal("expected wrap-init to refuse engagement when unix_sockets is disabled and no cgroup/eBPF enforcement is configured")
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", code)
	}
	if !strings.Contains(wrapErr.Error(), "unix_sockets.enabled is false") {
		t.Errorf("expected unix_sockets gate to fire, got %q", wrapErr.Error())
	}
}

// TestWrapNeedsCgroupBeforeAck_PolicyLimitsAloneInsufficient is the unit
// counterpart for the #361 follow-up: pins the contract that policy
// limits, on their own, are not enough to force the pre-ACK cgroup
// engagement path. Without cgroups/eBPF configured, the limits cannot be
// enforced anyway — keeping the wrapper alive would only lead to
// applyCgroupV2 failing with CgroupResourceLimitsUnavailableError.
func TestWrapNeedsCgroupBeforeAck_PolicyLimitsAloneInsufficient(t *testing.T) {
	cfg := &config.Config{}
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		ResourceLimits: policy.ResourceLimits{
			MaxMemoryMB:     1024,
			CPUQuotaPercent: 50,
			PidsMax:         100,
		},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	if wrapNeedsCgroupBeforeAck(app, s) {
		t.Fatal("wrapNeedsCgroupBeforeAck must return false when policy has limits but no cgroup/eBPF enforcement is configured")
	}

	// Sanity: enabling cgroups must flip the result so the original
	// pre-ACK engagement contract still holds for operators who actually
	// configured enforcement.
	cfg.Sandbox.Cgroups.Enabled = true
	if !wrapNeedsCgroupBeforeAck(app, s) {
		t.Fatal("wrapNeedsCgroupBeforeAck must return true when cgroups is enabled")
	}
}

func TestWrapInit_WrapperNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	cfg := &config.Config{}
	// Set a wrapper binary that doesn't exist
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error when wrapper not found")
	}
	if code != 503 {
		t.Errorf("expected status 503, got %d", code)
	}
}

// TestWrapInit_ShimMode_PolicyDeny covers the v0.19.1 docker-test
// regression: when the shim's kernel-install path calls wrap-init for a
// command the policy denies, the server must return 403 so the shim's
// ModeAuto branch falls through to the existing `agentsh exec` path
// (which surfaces "command denied by policy" to the user). Without this
// pre-check, wrap-init succeeded for denied commands and the wrapper
// ran without the policy gate firing — regression introduced in #274.
func TestWrapInit_ShimMode_PolicyDeny(t *testing.T) {
	cfg := &config.Config{}
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "block-system-commands", Commands: []string{"shutdown", "reboot"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// shim mode + denied inner command via shell-c derivation must return 403.
	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "shutdown now"},
		Mode:         "shim",
	})
	if err == nil {
		t.Fatal("expected wrap-init to return policy denial for shutdown via shell-c")
	}
	if code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", code)
	}
	if !strings.Contains(err.Error(), "policy") {
		t.Errorf("error must surface policy gate; got %q", err.Error())
	}
}

// TestWrapInit_ShimMode_PolicyApprove guards roborev #7867 (High): if a
// rule that requires human approval is enforced, the shim wrap path
// must not silently issue a wrapper. Falling back to the agentsh-exec
// path is what surfaces the approval prompt.
func TestWrapInit_ShimMode_PolicyApprove(t *testing.T) {
	cfg := &config.Config{}
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "approve-pip", Commands: []string{"pip"}, Decision: "approve"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}, true /* enforceApprovals */, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, _ := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "pip install requests"},
		Mode:         "shim",
	})
	if code != http.StatusForbidden {
		t.Fatalf("approve must not silently issue a wrapper; got code %d", code)
	}
}

// TestWrapInit_ShimMode_PolicyRedirect covers the redirect decision.
// Same reasoning as approve — redirect rewrites the command, which the
// shim wrap path does not implement, so we must defer to agentsh-exec.
func TestWrapInit_ShimMode_PolicyRedirect(t *testing.T) {
	cfg := &config.Config{}
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "redirect-rm", Commands: []string{"rm"}, Decision: "redirect", RedirectTo: &policy.CommandRedirect{Command: "trash"}},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}, true, true /* enforceRedirects */)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, _ := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "rm /tmp/x"},
		Mode:         "shim",
	})
	if code != http.StatusForbidden {
		t.Fatalf("redirect must not silently issue a wrapper; got code %d", code)
	}
}

// TestWrapInit_ShimMode_PolicySoftDelete guards roborev #7872 (High):
// soft_delete resolves to EffectiveDecision=allow even though the
// underlying rule requires the rm-to-trash redirect that only the
// agentsh-exec path implements. Gating on EffectiveDecision alone let
// soft_delete commands through unrewritten — the wrapper would have
// faithfully run rm against the requested path. Test asserts both that
// the pre-check rejects soft_delete and that PolicyDecision is the gate
// (a future change reverting to EffectiveDecision-only would re-fail).
func TestWrapInit_ShimMode_PolicySoftDelete(t *testing.T) {
	cfg := &config.Config{}
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "soft-delete-rm", Commands: []string{"rm"}, Decision: "soft_delete"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, _ := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "rm /tmp/x"},
		Mode:         "shim",
	})
	if code != http.StatusForbidden {
		t.Fatalf("soft_delete must not silently issue a wrapper; got code %d", code)
	}
}

// TestWrapInit_ShimMode_PolicyAuditAllowed covers the inverse: audit is
// "allow + enhanced logging" — the wrapper SHOULD be issued so the
// session's audit pipeline can record events. This is the only non-allow
// effective decision the shim path admits.
func TestWrapInit_ShimMode_PolicyAuditAllowed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only beyond the policy pre-check")
	}
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "audit-curl", Commands: []string{"curl"}, Decision: "audit"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "curl example"},
		Mode:         "shim",
	})
	// Pre-check must let audit through; downstream wrapper resolution
	// then fails (503) since we configured a non-existent binary. 403
	// would mean the policy gate incorrectly blocked an audit decision.
	if code == http.StatusForbidden {
		t.Fatalf("audit must pass the policy gate; got 403 with err: %v", err)
	}
}

// TestWrapInit_ShimMode_PolicyAllow confirms the pre-check does not
// reject allowed shim invocations. /bin/sh -c "echo hi" must pass the
// policy gate so wrap-init proceeds normally.
func TestWrapInit_ShimMode_PolicyAllow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only beyond the policy pre-check; this test runs the post-check path")
	}
	cfg := &config.Config{}
	// Force wrap-init to fail AFTER the policy pre-check (e.g. wrapper not
	// found) so we observe the policy gate let us through without inheriting
	// the platform's full wrapper-launch path.
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "allow-safe-commands", Commands: []string{"echo", "sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
			{Name: "block-system-commands", Commands: []string{"shutdown"}, Decision: "deny"},
		},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "echo hi"},
		Mode:         "shim",
	})
	// wrap-init goes past the policy pre-check, then fails at wrapper
	// resolution with 503. Policy denial would have produced 403 — ensure
	// we did NOT short-circuit there.
	if code == http.StatusForbidden {
		t.Fatalf("policy pre-check incorrectly denied an allowed command: %v", err)
	}
}

// TestWrapInit_AgentMode_PolicyNotChecked verifies the pre-check is
// scoped to Mode=="shim" only. The agentsh wrap path (Mode=="agent" or
// empty) retains pre-existing behavior — pre-check would change the
// semantics of `agentsh wrap` for any operator policy that does not
// list the agent's outer binary.
func TestWrapInit_AgentMode_PolicyNotChecked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only beyond the policy pre-check")
	}
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.WrapperBin = "nonexistent-wrapper-binary-xyz-12345"
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{Name: "block-system-commands", Commands: []string{"shutdown"}, Decision: "deny"},
		},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Same denied command but Mode="" (agent default). Pre-check must NOT fire.
	_, code, _ := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/sh.real",
		AgentArgs:    []string{"-c", "shutdown now"},
	})
	if code == http.StatusForbidden {
		t.Fatal("agent-mode wrap-init must not invoke shim-mode policy pre-check")
	}
}

func TestWrapInit_RejectsNegativeCallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("negative caller uid validation is Linux-only")
	}

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    -1,
	})

	if err == nil {
		t.Fatal("expected error for negative caller uid")
	}
	if code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", code)
	}
	if resp.NotifySocket != "" || resp.WrapperBinary != "" || resp.StubBinary != "" {
		t.Fatalf("expected empty wrap response on invalid caller uid, got %#v", resp)
	}
	if !strings.Contains(err.Error(), "invalid caller uid") {
		t.Fatalf("expected invalid caller uid error, got %v", err)
	}
}

func TestWrapInit_SafeToBypassShellShim_Ptrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap ptrace mode is Linux-only")
	}

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	app.ptraceTracer = struct{}{}

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if !resp.SafeToBypassShellShim {
		t.Fatal("expected ptrace mode to be safe to bypass the shell shim")
	}
}

func TestWrapInit_SafeToBypassShellShim_SeccompExecveEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap seccomp mode is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if !resp.SafeToBypassShellShim {
		t.Fatal("expected execve-enabled seccomp mode to be safe to bypass the shell shim")
	}
}

func TestWrapInit_SafeToBypassShellShim_SeccompExecveDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap seccomp mode is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = false
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.SafeToBypassShellShim {
		t.Fatal("expected execve-disabled seccomp mode to require the shell shim")
	}
}

func TestWrapInit_HTTPResponseIncludesSafeToBypassShellShimFalse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap response serialization is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = false
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	body := []byte(`{"agent_command":"/bin/echo","caller_uid":0}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+s.ID+"/wrap-init", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	app.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"safe_to_bypass_shell_shim":false`) {
		t.Fatalf("expected serialized response to include safe_to_bypass_shell_shim=false, got %s", rr.Body.String())
	}
}

func TestWrapInit_Success(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	// Use /bin/true as a stand-in for the wrapper binary
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// Verify response fields
	if resp.WrapperBinary != "/bin/true" {
		t.Errorf("expected wrapper binary /bin/true, got %q", resp.WrapperBinary)
	}
	if resp.NotifySocket == "" {
		t.Error("expected notify socket path to be set")
	}
	if resp.SeccompConfig == "" {
		t.Error("expected seccomp config to be set")
	}
	if resp.WrapperEnv == nil {
		t.Error("expected wrapper env to be set")
	}
	if _, ok := resp.WrapperEnv["AGENTSH_SECCOMP_CONFIG"]; !ok {
		t.Error("expected AGENTSH_SECCOMP_CONFIG in wrapper env")
	}
}

func TestWrapInit_CallerUIDPassedThrough(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		CallerUID:    1000,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.NotifySocket == "" {
		t.Fatal("expected notify socket path to be set")
	}
}

func TestWrapInit_SeccompConfigContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	cfg.Sandbox.Seccomp.FileMonitor.EnforceWithoutFUSE = &enabled
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
	}

	if got, _ := parsed["unix_socket_enabled"].(bool); !got {
		t.Fatalf("unix_socket_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["execve_enabled"].(bool); !got {
		t.Fatalf("execve_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["file_monitor_enabled"].(bool); !got {
		t.Fatalf("file_monitor_enabled = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["intercept_metadata"].(bool); !got {
		t.Fatalf("intercept_metadata = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
	if got, _ := parsed["block_io_uring"].(bool); !got {
		t.Fatalf("block_io_uring = %v, want true (JSON: %s)", got, resp.SeccompConfig)
	}
}

func TestWrapInit_ForcesNotifyHandoffWhenEBPFRequiresPreAckCgroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	disabled := false
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &disabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}

	var parsed seccompWrapperConfig
	require.NoError(t, json.Unmarshal([]byte(resp.SeccompConfig), &parsed))
	require.True(t, parsed.UnixSocketEnabled, "pre-ACK cgroup/eBPF setup requires a user-notify handoff before wrapper exec")
}

func TestWrapInit_SeccompConfigContent_MitigationSetsForwardSocketRules(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SeccompConfig == "" {
		t.Fatal("expected seccomp config")
	}

	var parsed seccompWrapperConfig
	require.NoError(t, json.Unmarshal([]byte(resp.SeccompConfig), &parsed))
	require.Len(t, parsed.SocketRules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", parsed.SocketRules[0].Name)
	require.Equal(t, "dirtyfrag-conservative-xfrm", parsed.SocketRules[1].Name)
}

func TestWrapInit_SeccompConfigContent_MitigationSetsForwardSyscallsAndFamilies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "log"
	addTestMitigationSet(t, cfg, "api-runtime", `
version: 1
id: api-runtime
seccomp:
  syscalls:
    block:
      - ptrace
  blocked_socket_families:
    - family: AF_ALG
      action: log
`)
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SeccompConfig == "" {
		t.Fatal("expected seccomp config")
	}

	var parsed seccompWrapperConfig
	require.NoError(t, json.Unmarshal([]byte(resp.SeccompConfig), &parsed))
	require.Equal(t, []string{"ptrace"}, parsed.BlockedSyscalls)
	require.Equal(t, "log", parsed.OnBlock)
	require.Len(t, parsed.BlockedFamilies, 1)
	require.Equal(t, "AF_ALG", parsed.BlockedFamilies[0].Name)
	require.Equal(t, "log", string(parsed.BlockedFamilies[0].Action))
}

func TestWrapInit_LongTMPDIR_LongSessionID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	// Use a TMPDIR that simulates macOS /var/folders nesting (~40 chars)
	// while still leaving enough room for the socket path.
	// Budget: 104 - len(TMPDIR) - ~25 (agentsh-wrap-*) - 13 (fixed parts)
	longDir := filepath.Join(t.TempDir(), "deep")
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatalf("create tmpdir: %v", err)
	}
	t.Setenv("TMPDIR", longDir)

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	// Use a 128-char session ID to exercise the hashing/truncation path
	longSessionID := strings.Repeat("x", 128)
	s, err := mgr.CreateWithID(longSessionID, t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, longSessionID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}
	if resp.NotifySocket == "" {
		t.Error("expected notify socket path to be set")
	}
	// Verify socket path is under the limit
	if len(resp.NotifySocket) > 104 {
		t.Errorf("socket path %d bytes exceeds 104 byte limit: %s", len(resp.NotifySocket), resp.NotifySocket)
	}
}

func TestWrapInit_BudgetExhausted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	// Create a TMPDIR so long that the socket path budget is exhausted (< 1).
	// Socket path limit is 104; fixed parts take ~13 bytes; the temp dir
	// (including "agentsh-wrap-*") must consume the rest.
	base := t.TempDir()
	longDir := filepath.Join(base, strings.Repeat("d", 120))
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatalf("create tmpdir: %v", err)
	}
	t.Setenv("TMPDIR", longDir)

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	_, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
		AgentArgs:    []string{"hello"},
	})

	if err == nil {
		t.Fatal("expected error when TMPDIR is too long")
	}
	if code != 500 {
		t.Errorf("expected status 500, got %d", code)
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' in error, got: %v", err)
	}
}

func newTestAppForWrapWithSignalPolicy(t *testing.T, cfg *config.Config) (*App, *session.Manager) {
	t.Helper()
	mgr := session.NewManager(5)
	store := composite.New(mockEventStore{}, nil)
	broker := events.NewBroker()
	// Create a policy with signal rules so SignalEngine() returns non-nil
	p := &policy.Policy{
		Version: 1,
		Name:    "test-signal",
		SignalRules: []policy.SignalRule{
			{
				Name:     "audit-all",
				Signals:  []string{"SIGKILL"},
				Target:   policy.SignalTargetSpec{Type: "external"},
				Decision: "audit",
			},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("create policy engine: %v", err)
	}
	app := NewApp(cfg, mgr, store, engine, broker, nil, nil, nil, nil, nil, nil, nil)
	return app, mgr
}

func TestWrapInit_SignalFilterEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// Verify signal_filter_enabled is true in the seccomp config
	var seccompCfg map[string]interface{}
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &seccompCfg); err != nil {
		t.Fatalf("failed to parse seccomp config: %v", err)
	}
	sigEnabled, ok := seccompCfg["signal_filter_enabled"]
	if !ok {
		t.Fatal("seccomp config missing signal_filter_enabled field")
	}
	if sigEnabled != true {
		t.Errorf("expected signal_filter_enabled=true, got %v", sigEnabled)
	}
}

func TestWrapInit_SignalSocketSet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// SignalSocket should be set when policy has signal rules
	if resp.SignalSocket == "" {
		t.Error("expected SignalSocket to be set when signal engine is available")
	}
	// Signal socket should be in the same directory as notify socket
	if filepath.Dir(resp.SignalSocket) != filepath.Dir(resp.NotifySocket) {
		t.Errorf("expected signal and notify sockets in same directory: signal=%s notify=%s",
			resp.SignalSocket, resp.NotifySocket)
	}
	// Signal socket path should be under the limit
	if len(resp.SignalSocket) > 104 {
		t.Errorf("signal socket path %d bytes exceeds 104 byte limit: %s",
			len(resp.SignalSocket), resp.SignalSocket)
	}

	// AGENTSH_SIGNAL_SOCK_FD should be in wrapper env
	if fd, ok := resp.WrapperEnv["AGENTSH_SIGNAL_SOCK_FD"]; !ok {
		t.Error("expected AGENTSH_SIGNAL_SOCK_FD in wrapper env")
	} else if fd != "4" {
		t.Errorf("expected AGENTSH_SIGNAL_SOCK_FD=4, got %q", fd)
	}
}

func TestWrapInit_SignalSocketPermissions_CallerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrapWithSignalPolicy(t, cfg)

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
	if code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", code)
	}
	if resp.SignalSocket == "" {
		t.Fatal("expected signal socket to be created")
	}

	notifyDir := filepath.Dir(resp.NotifySocket)
	t.Cleanup(func() { _ = os.RemoveAll(notifyDir) })

	notifyInfo, err := os.Stat(resp.NotifySocket)
	if err != nil {
		t.Fatalf("stat notify socket: %v", err)
	}
	if got := notifyInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected caller-owned notify socket mode 0600, got %04o", got)
	}

	signalInfo, err := os.Stat(resp.SignalSocket)
	if err != nil {
		t.Fatalf("stat signal socket: %v", err)
	}
	if got := signalInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected caller-owned signal socket mode 0600, got %04o", got)
	}
	if filepath.Dir(resp.SignalSocket) != notifyDir {
		t.Fatalf("expected signal socket to share notify dir, got %s vs %s", filepath.Dir(resp.SignalSocket), notifyDir)
	}
}

func TestWrapInit_NoSignalSocketWithoutPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	// Use standard helper (no signal policy)
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("expected status 200, got %d", code)
	}

	// SignalSocket should NOT be set without signal policy
	if resp.SignalSocket != "" {
		t.Errorf("expected empty SignalSocket without signal policy, got %q", resp.SignalSocket)
	}

	// AGENTSH_SIGNAL_SOCK_FD should NOT be in wrapper env
	if _, ok := resp.WrapperEnv["AGENTSH_SIGNAL_SOCK_FD"]; ok {
		t.Error("expected no AGENTSH_SIGNAL_SOCK_FD in wrapper env without signal policy")
	}

	// signal_filter_enabled should be false in seccomp config
	var seccompCfg map[string]interface{}
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &seccompCfg); err != nil {
		t.Fatalf("failed to parse seccomp config: %v", err)
	}
	sigEnabled, ok := seccompCfg["signal_filter_enabled"]
	if !ok {
		t.Fatal("seccomp config missing signal_filter_enabled field")
	}
	if sigEnabled != false {
		t.Errorf("expected signal_filter_enabled=false, got %v", sigEnabled)
	}
}

func TestWrapInit_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_true_bind_true", true, true, true, true},
		{"connect_false_bind_false", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind
			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
			cfg.Sandbox.Seccomp.Execve.Enabled = true
			cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app, mgr := newTestAppForWrap(t, cfg)
			s, err := mgr.Create(t.TempDir(), "default")
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
				AgentCommand: "/bin/echo",
			})
			if err != nil {
				t.Fatalf("wrapInitCore: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
				t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, resp.SeccompConfig)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, resp.SeccompConfig)
			}
		})
	}
}

func TestWrapInit_LandlockNetwork_BackCompatDefaults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	// Minimal YAML: Landlock enabled, no network block.
	// Exercises the back-compat promise: omitting landlock.network.* must
	// yield allow_network=true (proxy-compatible) and allow_bind=false
	// (new security default, replacing prior accidental permissive behavior).
	yamlData := []byte(`
landlock:
  enabled: true
sandbox:
  unix_sockets:
    enabled: true
    wrapper_bin: /bin/true
  seccomp:
    execve:
      enabled: true
    unix_socket:
      enabled: true
`)
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, yamlData, 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	// Sanity: applyDefaults ran via config.Load.
	if cfg.Landlock.Network.AllowConnectTCP == nil {
		t.Fatal("applyDefaults should have filled AllowConnectTCP")
	}
	if cfg.Landlock.Network.AllowBindTCP == nil {
		t.Fatal("applyDefaults should have filled AllowBindTCP")
	}

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotNet, _ := parsed["allow_network"].(bool)
	gotBind, _ := parsed["allow_bind"].(bool)
	if !gotNet {
		t.Error("back-compat: allow_network should default to true (proxy needs it)")
	}
	if gotBind {
		t.Error("back-compat: allow_bind should default to false (security hardening vs prior accidental permissive)")
	}
}

// TestBlockedFamiliesUsesNotify verifies that the helper function correctly
// identifies families that require the userspace notify handler.
func TestBlockedFamiliesUsesNotify(t *testing.T) {
	cases := []struct {
		name     string
		families []config.SandboxSeccompSocketFamilyConfig
		want     bool
	}{
		{
			name:     "empty",
			families: nil,
			want:     false,
		},
		{
			name:     "errno only",
			families: []config.SandboxSeccompSocketFamilyConfig{{Family: "AF_ALG", Action: "errno"}},
			want:     false,
		},
		{
			name:     "kill only",
			families: []config.SandboxSeccompSocketFamilyConfig{{Family: "AF_ALG", Action: "kill"}},
			want:     false,
		},
		{
			name:     "log",
			families: []config.SandboxSeccompSocketFamilyConfig{{Family: "AF_ALG", Action: "log"}},
			want:     true,
		},
		{
			name:     "log_and_kill",
			families: []config.SandboxSeccompSocketFamilyConfig{{Family: "AF_ALG", Action: "log_and_kill"}},
			want:     true,
		},
		{
			name: "mixed: log and errno — log wins",
			families: []config.SandboxSeccompSocketFamilyConfig{
				{Family: "AF_ALG", Action: "errno"},
				{Family: "AF_INET", Action: "log"},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := blockedFamiliesUsesNotify(tc.families)
			if got != tc.want {
				t.Errorf("blockedFamiliesUsesNotify(%v) = %v, want %v", tc.families, got, tc.want)
			}
		})
	}
}

func TestSocketRulesUsesNotify(t *testing.T) {
	cases := []struct {
		name  string
		rules []config.SandboxSeccompSocketRuleConfig
		want  bool
	}{
		{name: "empty", rules: nil, want: false},
		{name: "errno", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "errno"}}, want: false},
		{name: "kill", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "kill"}}, want: false},
		{name: "log", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "log"}}, want: true},
		{name: "log_and_kill", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "log_and_kill"}}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := socketRulesUsesNotify(tc.rules)
			if got != tc.want {
				t.Fatalf("socketRulesUsesNotify() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMainFilterUsesUserNotify_SocketRuleLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{{
		Name:     "dirtyfrag-xfrm",
		Family:   "AF_NETLINK",
		Protocol: "NETLINK_XFRM",
		Action:   "log",
	}}
	app := &App{cfg: cfg}
	if !app.mainFilterUsesUserNotify(false) {
		t.Fatal("mainFilterUsesUserNotify should return true when a socket rule uses log")
	}
}

func TestMainFilterUsesUserNotify_SocketRuleMitigationSet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app := &App{cfg: cfg}
	if !app.mainFilterUsesUserNotify(false) {
		t.Fatal("mainFilterUsesUserNotify should return true when a mitigation set expands to log socket rules")
	}
}

func TestMainFilterUsesUserNotify_MitigationSetSyscallLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.Syscalls.OnBlock = "log"
	addTestMitigationSet(t, cfg, "notify-syscall", `
version: 1
id: notify-syscall
seccomp:
  syscalls:
    block:
      - ptrace
`)
	app := &App{cfg: cfg}
	if !app.mainFilterUsesUserNotify(false) {
		t.Fatal("mainFilterUsesUserNotify should return true when a mitigation set adds a log syscall block")
	}
}

func TestMainFilterUsesUserNotify_MitigationSetFamilyLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	addTestMitigationSet(t, cfg, "notify-family", `
version: 1
id: notify-family
seccomp:
  blocked_socket_families:
    - family: AF_ALG
      action: log
`)
	app := &App{cfg: cfg}
	if !app.mainFilterUsesUserNotify(false) {
		t.Fatal("mainFilterUsesUserNotify should return true when a mitigation set adds a log socket family")
	}
}

// TestMainFilterUsesUserNotify_FamilyLog verifies that mainFilterUsesUserNotify
// returns true when the config contains a family with a log action, even when
// all other notify-triggering options are disabled. This guards against the
// signal-filter stacking bug (#191): if the predicate misses family-log entries,
// a second USER_NOTIF filter (signal) could be stacked on top of the main one.
func TestMainFilterUsesUserNotify_FamilyLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	// All notify features explicitly off.
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	// Only a single family with log action.
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []config.SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "log"},
	}
	app := &App{cfg: cfg}

	if !app.mainFilterUsesUserNotify(false) {
		t.Error("mainFilterUsesUserNotify should return true when a family has log action")
	}
}

// TestMainFilterUsesUserNotify_FamilyLogAndKill mirrors TestMainFilterUsesUserNotify_FamilyLog
// for log_and_kill.
func TestMainFilterUsesUserNotify_FamilyLogAndKill(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []config.SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "log_and_kill"},
	}
	app := &App{cfg: cfg}

	if !app.mainFilterUsesUserNotify(false) {
		t.Error("mainFilterUsesUserNotify should return true when a family has log_and_kill action")
	}
}

// TestMainFilterUsesUserNotify_FamilyErrnoAndKill_NoNotify verifies that
// mainFilterUsesUserNotify returns false when all families use kernel-side
// actions (errno or kill).
func TestMainFilterUsesUserNotify_FamilyErrnoAndKill_NoNotify(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.BlockedSocketFamilies = []config.SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "errno"},
		{Family: "AF_INET", Action: "kill"},
	}
	app := &App{cfg: cfg}

	if app.mainFilterUsesUserNotify(false) {
		t.Error("mainFilterUsesUserNotify should return false when all families use errno/kill (kernel-side)")
	}
}

// TestWrapInit_AllowExecuteIncludesAgentCommandDir covers the #283
// regression on Tensorlake (and any environment where the shell-shim is
// installed): wrap-init must include the parent directory of the
// AgentCommand in the seccomp wrapper's AllowExecute list, otherwise
// Landlock denies execve of the renamed real shell (e.g.,
// /bin/bash.real) because typical policies use bare command names
// (`commands: [bash, sh]`) and DeriveExecutePathsFromPolicy adds
// nothing for those.
//
// Without this fix, every wrapped command on Tensorlake exits 1 with
// `resolve command "/bin/bash.real": exec: ... permission denied` —
// the EACCES surfaces from Go's exec.LookPath after Landlock has been
// applied to unixwrap's process.
func TestWrapInit_AllowExecuteIncludesAgentCommandDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Landlock.Enabled = true

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/bash.real",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
	}

	rawAllow, _ := parsed["allow_execute"].([]any)
	allow := make([]string, 0, len(rawAllow))
	for _, p := range rawAllow {
		if s, ok := p.(string); ok {
			allow = append(allow, s)
		}
	}

	found := false
	for _, p := range allow {
		if p == "/bin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /bin in allow_execute, got %v\nfull config: %s", allow, resp.SeccompConfig)
	}
}

// TestWrapInit_AllowExecuteSkipsBareCommandName verifies the inverse:
// when AgentCommand is a bare name (no slash, e.g., "echo"), wrap-init
// does NOT add anything based on it — there is no parent directory to
// derive, and resolving via PATH at exec time is the unixwrap caller's
// responsibility. The list still contains whatever the policy and
// global config supplied.
func TestWrapInit_AllowExecuteSkipsBareCommandName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Landlock.Enabled = true

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp.SeccompConfig), &parsed); err != nil {
		t.Fatalf("unmarshal SeccompConfig: %v\n%s", err, resp.SeccompConfig)
	}

	// We don't assert the exact list (it depends on default policy +
	// landlock config); we just confirm no spurious entry derived from
	// the bare name was injected. "" or "." would be the most likely
	// bug shapes if filepath.Dir was applied unguarded.
	rawAllow, _ := parsed["allow_execute"].([]any)
	for _, p := range rawAllow {
		s, ok := p.(string)
		if !ok {
			continue
		}
		if s == "" || s == "." {
			t.Errorf("allow_execute should not contain bare-name-derived %q; got list %v", s, rawAllow)
		}
	}
}
