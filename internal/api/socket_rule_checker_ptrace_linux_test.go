//go:build linux

package api

import (
	"testing"

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

func TestResolveSocketRuleCheckerForPtrace_HardeningProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.HardeningProfiles = []string{"dirtyfrag-conservative"}

	checker, err := resolveSocketRuleCheckerForPtrace(cfg, nil)
	if err != nil {
		t.Fatalf("resolveSocketRuleCheckerForPtrace returned error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected non-nil SocketRuleChecker")
	}
	if rule, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_RXRPC), uint64(unix.SOCK_DGRAM), 0); !ok || rule.Name != "dirtyfrag-conservative-rxrpc" {
		t.Fatalf("expected RXRPC hardening profile rule, got rule=%+v ok=%v", rule, ok)
	}
	if rule, ok := checker.Check(uint64(unix.SYS_SOCKETPAIR), uint64(unix.AF_NETLINK), uint64(unix.SOCK_DGRAM), uint64(unix.NETLINK_XFRM)); !ok || rule.Name != "dirtyfrag-conservative-xfrm" {
		t.Fatalf("expected XFRM hardening profile rule, got rule=%+v ok=%v", rule, ok)
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
