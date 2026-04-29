//go:build linux

package api

import (
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
	// seccomp available + enabled → seccomp engine
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
	// when both are available + enabled, seccomp wins (cheaper)
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
