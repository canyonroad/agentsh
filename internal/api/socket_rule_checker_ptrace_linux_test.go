//go:build linux

package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func TestResolveSocketRuleCheckerForPtrace_RawSocketRules(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{{
		Name:     "dirtyfrag-xfrm",
		Family:   "AF_NETLINK",
		Protocol: "NETLINK_XFRM",
		Action:   "log_and_kill",
	}}

	checker, err := resolveSocketRuleCheckerForPtrace(cfg, nil)
	if err != nil {
		t.Fatalf("resolveSocketRuleCheckerForPtrace returned error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil SocketRuleChecker")
	}
	rule, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), uint64(unix.SOCK_RAW), uint64(unix.NETLINK_XFRM))
	if !ok {
		t.Fatal("expected checker to match configured NETLINK_XFRM socket rule")
	}
	if rule.Name != "dirtyfrag-xfrm" || rule.Action != seccomp.OnBlockLogAndKill {
		t.Fatalf("unexpected rule: %+v", rule)
	}
}

func TestResolveSocketRuleCheckerForPtrace_MitigationSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}

	checker, err := resolveSocketRuleCheckerForPtrace(cfg, nil)
	if err != nil {
		t.Fatalf("resolveSocketRuleCheckerForPtrace returned error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil SocketRuleChecker")
	}
	if rule, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_RXRPC), uint64(unix.SOCK_DGRAM), 0); !ok || rule.Name != "dirtyfrag-conservative-rxrpc" {
		t.Fatalf("expected RXRPC mitigation-set rule, got rule=%+v ok=%v", rule, ok)
	}
	if rule, ok := checker.Check(uint64(unix.SYS_SOCKETPAIR), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_XFRM)); !ok || rule.Name != "dirtyfrag-conservative-xfrm" {
		t.Fatalf("expected XFRM mitigation-set rule, got rule=%+v ok=%v", rule, ok)
	}
}

func TestResolveFamilyCheckerForPtrace_MitigationSet(t *testing.T) {
	cfg := &config.Config{}
	addTestMitigationSet(t, cfg, "ptrace-family", `
version: 1
id: ptrace-family
seccomp:
  blocked_socket_families:
    - family: AF_ALG
      action: log
`)

	checker, err := resolveFamilyCheckerForPtrace(cfg, nil)
	if err != nil {
		t.Fatalf("resolveFamilyCheckerForPtrace returned error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil FamilyChecker")
	}
	family, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_ALG))
	if !ok {
		t.Fatal("expected checker to match mitigation-set AF_ALG socket family")
	}
	if family.Name != "AF_ALG" || family.Action != seccomp.OnBlockLog {
		t.Fatalf("unexpected family: %+v", family)
	}
}

func TestResolveSocketRuleCheckerForPtrace_NilWhenNoRules(t *testing.T) {
	cfg := &config.Config{}

	checker, err := resolveSocketRuleCheckerForPtrace(cfg, nil)
	if err != nil {
		t.Fatalf("resolveSocketRuleCheckerForPtrace returned error: %v", err)
	}
	if checker != nil {
		t.Fatal("expected nil checker when no socket rules are configured")
	}
}

func TestResolveSocketRuleCheckerForPtrace_ErrorOnInvalidConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{{
		Name:     "bad-xfrm",
		Family:   "AF_INET",
		Protocol: "NETLINK_XFRM",
		Action:   "log",
	}}

	checker, err := resolveSocketRuleCheckerForPtrace(cfg, nil)
	if err == nil {
		t.Fatal("expected invalid socket rule config to return an error")
	}
	if checker != nil {
		t.Fatalf("expected nil checker on error, got %+v", checker)
	}
}

func TestResolveSocketRuleCheckerForPtrace_WarnIfSocketRulesOrphan_RawRules(t *testing.T) {
	withMissingWrapper(t)
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Ptrace.Enabled = false
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{{
		Name:     "dirtyfrag-xfrm",
		Family:   "AF_NETLINK",
		Protocol: "NETLINK_XFRM",
		Action:   "log_and_kill",
	}}
	app := &App{cfg: cfg}

	warned := app.warnIfSocketRulesOrphanWithCaps(&capabilities.SecurityCapabilities{
		Seccomp: true,
		Ptrace:  false,
	})
	if !warned {
		t.Fatal("expected orphan warning for socket_rules when ptrace is disabled and wrapper is missing")
	}
}

func TestResolveSocketRuleCheckerForPtrace_WarnIfSocketRulesOrphan_MitigationSet(t *testing.T) {
	withMissingWrapper(t)
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Ptrace.Enabled = false
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app := &App{cfg: cfg}

	warned := app.warnIfSocketRulesOrphanWithCaps(&capabilities.SecurityCapabilities{
		Seccomp: true,
		Ptrace:  false,
	})
	if !warned {
		t.Fatal("expected orphan warning for dirtyfrag-conservative socket rules when ptrace is disabled and wrapper is missing")
	}
}

func TestResolveSocketRuleCheckerForPtrace_WarnIfSocketRulesOrphan_NoWarnWhenWrapperWillRun(t *testing.T) {
	withPresentWrapper(t)
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Ptrace.Enabled = false
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app := &App{cfg: cfg}

	warned := app.warnIfSocketRulesOrphanWithCaps(&capabilities.SecurityCapabilities{
		Seccomp: true,
		Ptrace:  false,
	})
	if warned {
		t.Fatal("must not warn when seccomp wrapper will enforce socket rules")
	}
}

func TestResolveSocketRuleCheckerForPtrace_WarnIfSocketRulesOrphan_NoWarnWhenWrapperRunsWithSeccompDisabled(t *testing.T) {
	withPresentWrapper(t)
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Enabled = false
	cfg.Sandbox.Ptrace.Enabled = false
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	enabled := true
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	app := &App{cfg: cfg}

	warned := app.warnIfSocketRulesOrphanWithCaps(&capabilities.SecurityCapabilities{
		Seccomp: true,
		Ptrace:  false,
	})
	if warned {
		t.Fatal("must not warn when unix_sockets wrapper can enforce socket rules even with sandbox.seccomp.enabled=false")
	}
}

func TestResolveSocketRuleCheckerForPtrace_WarnIfSocketRulesOrphan_NoWarnWhenPtraceEnabled(t *testing.T) {
	withMissingWrapper(t)
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.Enabled = true
	cfg.Sandbox.Ptrace.Enabled = true
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app := &App{cfg: cfg}

	warned := app.warnIfSocketRulesOrphanWithCaps(&capabilities.SecurityCapabilities{
		Seccomp: true,
		Ptrace:  true,
	})
	if warned {
		t.Fatal("must not warn when ptrace is enabled and available to enforce socket rules")
	}
}
