//go:build linux

package api

import (
	"os/exec"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)

func oneFamilySlice() []seccompkg.BlockedFamily {
	return []seccompkg.BlockedFamily{
		{Family: 38, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
	}
}

func TestSelectFamilyBlockingEngine_Seccomp(t *testing.T) {
	// seccomp available + enabled + wrapper present → seccomp engine
	withPresentWrapper(t)
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEngineSeccomp {
		t.Errorf("expected familyEngineSeccomp; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_SeccompDisabled_PtraceAvailable(t *testing.T) {
	// seccomp disabled → ptrace fallback even if seccomp capable
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: false},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEnginePtrace {
		t.Errorf("expected familyEnginePtrace; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_SeccompUnavailable_PtraceEnabled(t *testing.T) {
	// seccomp not available on host, ptrace enabled → ptrace engine
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: false, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEnginePtrace {
		t.Errorf("expected familyEnginePtrace; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_NeitherAvailable(t *testing.T) {
	// neither engine available → none
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: false, Ptrace: false}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEngineNone {
		t.Errorf("expected familyEngineNone; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_NeitherEnabled(t *testing.T) {
	// both disabled in config → none
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: false},
		Ptrace:  config.SandboxPtraceConfig{Enabled: false},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEngineNone {
		t.Errorf("expected familyEngineNone; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_EmptyFamilies(t *testing.T) {
	// no families configured → none regardless of caps
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(nil, cfg, caps)
	if got != familyEngineNone {
		t.Errorf("expected familyEngineNone for nil families; got %v", got)
	}
	got = selectFamilyBlockingEngine([]seccompkg.BlockedFamily{}, cfg, caps)
	if got != familyEngineNone {
		t.Errorf("expected familyEngineNone for empty families; got %v", got)
	}
}

func TestSelectFamilyBlockingEngine_SeccompPreferredOverPtrace(t *testing.T) {
	// when both are available + enabled + wrapper present, seccomp wins (cheaper)
	withPresentWrapper(t)
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
	}
	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEngineSeccomp {
		t.Errorf("expected seccomp over ptrace when both available; got %v", got)
	}
}

// withMissingWrapper temporarily replaces familyEngineLookPath so that any
// lookup of "agentsh-unixwrap" returns an error (binary not found).
func withMissingWrapper(t *testing.T) {
	t.Helper()
	orig := familyEngineLookPath
	familyEngineLookPath = func(file string) (string, error) {
		return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
	}
	t.Cleanup(func() { familyEngineLookPath = orig })
}

// withPresentWrapper temporarily replaces familyEngineLookPath so that any
// lookup returns a fixed path (wrapper present).
func withPresentWrapper(t *testing.T) {
	t.Helper()
	orig := familyEngineLookPath
	familyEngineLookPath = func(file string) (string, error) {
		return "/usr/local/bin/" + file, nil
	}
	t.Cleanup(func() { familyEngineLookPath = orig })
}

func TestSelectFamilyEngine_WrapperMissing_FallsBackToPtrace(t *testing.T) {
	// Capabilities: seccomp + ptrace both available.
	// Config: seccomp enabled, unix_sockets enabled (nil → default true).
	// Wrapper binary: NOT on PATH.
	// Ptrace: enabled.
	// Expected: familyEnginePtrace (NOT familyEngineSeccomp).
	withMissingWrapper(t)

	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: true},
		// UnixSockets.Enabled is nil → treated as true (default), so the
		// only reason wrapperWillRun returns false is the missing binary.
	}

	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEnginePtrace {
		t.Errorf("expected familyEnginePtrace when wrapper binary missing; got %v", got)
	}
}

func TestSelectFamilyEngine_WrapperMissing_NeitherFallback(t *testing.T) {
	// Same as above but ptrace also unavailable/disabled.
	// Expected: familyEngineNone (silent fail — caller logs the warning).
	withMissingWrapper(t)

	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: false}
	cfg := &config.SandboxConfig{
		Seccomp: config.SandboxSeccompConfig{Enabled: true},
		Ptrace:  config.SandboxPtraceConfig{Enabled: false},
	}

	got := selectFamilyBlockingEngine(families, cfg, caps)
	if got != familyEngineNone {
		t.Errorf("expected familyEngineNone when wrapper missing and ptrace unavailable; got %v", got)
	}
}

// TestResolveFamilyCheckerForPtrace_AlwaysWiresWhenFamiliesConfigured verifies
// the defensive wiring fix: resolveFamilyCheckerForPtrace must return a
// non-nil FamilyChecker whenever BlockedSocketFamilies is non-empty,
// regardless of which engine selectFamilyBlockingEngine would choose.
// This is the direct regression test for the hybrid-ptrace fail-open bug
// (see commit message for context).
func TestResolveFamilyCheckerForPtrace_AlwaysWiresWhenFamiliesConfigured(t *testing.T) {
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Seccomp: config.SandboxSeccompConfig{
				Enabled: true,
				BlockedSocketFamilies: []config.SandboxSeccompSocketFamilyConfig{
					{Family: "AF_ALG", Action: "errno"},
				},
			},
			Ptrace: config.SandboxPtraceConfig{Enabled: true},
		},
	}

	checker, err := resolveFamilyCheckerForPtrace(cfg)
	if err != nil {
		t.Fatalf("resolveFamilyCheckerForPtrace returned unexpected error: %v", err)
	}
	if checker == nil {
		t.Error("expected non-nil FamilyChecker when BlockedSocketFamilies is configured; got nil (families would fail open)")
	}
}

// TestResolveFamilyCheckerForPtrace_NilWhenNoFamilies verifies that no
// FamilyChecker is created when the blocked families list is empty.
func TestResolveFamilyCheckerForPtrace_NilWhenNoFamilies(t *testing.T) {
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Seccomp: config.SandboxSeccompConfig{
				Enabled:               true,
				BlockedSocketFamilies: nil,
			},
			Ptrace: config.SandboxPtraceConfig{Enabled: true},
		},
	}

	checker, err := resolveFamilyCheckerForPtrace(cfg)
	if err != nil {
		t.Fatalf("resolveFamilyCheckerForPtrace returned unexpected error: %v", err)
	}
	if checker != nil {
		t.Error("expected nil FamilyChecker when BlockedSocketFamilies is empty; got non-nil")
	}
}

// TestResolveFamilyCheckerForPtrace_SeccompSelectedEngine verifies the key
// scenario from the bug report: even when selectFamilyBlockingEngine would
// choose familyEngineSeccomp (wrapper present, seccomp enabled), the helper
// still returns a non-nil checker so the ptrace tracer is wired defensively.
func TestResolveFamilyCheckerForPtrace_SeccompSelectedEngine(t *testing.T) {
	// Simulate "seccomp would win" from the selector's perspective.
	withPresentWrapper(t)

	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Seccomp: config.SandboxSeccompConfig{
				Enabled: true,
				BlockedSocketFamilies: []config.SandboxSeccompSocketFamilyConfig{
					{Family: "AF_ALG", Action: "errno"},
				},
			},
			Ptrace: config.SandboxPtraceConfig{Enabled: true},
		},
	}

	// Confirm selector would pick seccomp.
	families := oneFamilySlice()
	caps := &capabilities.SecurityCapabilities{Seccomp: true, Ptrace: true}
	engine := selectFamilyBlockingEngine(families, &cfg.Sandbox, caps)
	if engine != familyEngineSeccomp {
		t.Skipf("precondition failed: expected seccomp engine, got %v", engine)
	}

	// The defensive helper must still wire the checker.
	checker, err := resolveFamilyCheckerForPtrace(cfg)
	if err != nil {
		t.Fatalf("resolveFamilyCheckerForPtrace returned unexpected error: %v", err)
	}
	if checker == nil {
		t.Error("expected non-nil FamilyChecker even when seccomp engine is selected; " +
			"ptrace tracer must be defensively wired (families would fail open otherwise)")
	}
}
