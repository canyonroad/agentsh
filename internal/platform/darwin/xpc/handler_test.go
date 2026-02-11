package xpc

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestPolicyAdapter_CheckFile_Allow(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/test/file.txt", "read")

	if !allow {
		t.Error("expected allow=true")
	}
	if rule != "allow-all" {
		t.Errorf("rule: got %q, want %q", rule, "allow-all")
	}
}

func TestPolicyAdapter_CheckFile_Deny(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-secrets", Paths: []string{"/etc/passwd"}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	adapter := NewPolicyAdapter(engine, nil)
	allow, rule := adapter.CheckFile("/etc/passwd", "read")

	if allow {
		t.Error("expected allow=false")
	}
	if rule != "deny-secrets" {
		t.Errorf("rule: got %q, want %q", rule, "deny-secrets")
	}
}

func TestPolicyAdapter_CheckNetwork(t *testing.T) {
	t.Run("allow with domain", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-example", Domains: []string{"example.com"}, Ports: []int{443}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckNetwork("1.2.3.4", 443, "example.com")

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-example" {
			t.Errorf("rule: got %q, want %q", rule, "allow-example")
		}
	})

	t.Run("allow with IP (no domain)", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-ip", CIDRs: []string{"10.0.0.0/8"}, Ports: []int{80}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckNetwork("10.1.2.3", 80, "")

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-ip" {
			t.Errorf("rule: got %q, want %q", rule, "allow-ip")
		}
	})

	t.Run("domain takes precedence over IP", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			NetworkRules: []policy.NetworkRule{
				{Name: "allow-domain", Domains: []string{"api.example.com"}, Ports: []int{443}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		// Even with an IP, domain should be used for matching
		allow, rule := adapter.CheckNetwork("93.184.216.34", 443, "api.example.com")

		if !allow {
			t.Error("expected allow=true when domain matches")
		}
		if rule != "allow-domain" {
			t.Errorf("rule: got %q, want %q", rule, "allow-domain")
		}
	})
}

func TestPolicyAdapter_CheckCommand(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckCommand("ls", []string{"-la"})

		if !allow {
			t.Error("expected allow=true")
		}
		if rule != "allow-ls" {
			t.Errorf("rule: got %q, want %q", rule, "allow-ls")
		}
	})

	t.Run("deny", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		allow, rule := adapter.CheckCommand("rm", []string{"-rf", "/"})

		if allow {
			t.Error("expected allow=false")
		}
		if rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", rule, "deny-rm")
		}
	})
}

func TestPolicyAdapter_CheckExec(t *testing.T) {
	t.Run("allow_returns_continue", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("ls", []string{"-la"}, 1234, 1, "session-1", ExecContext{})

		if result.Decision != "allow" {
			t.Errorf("decision: got %q, want %q", result.Decision, "allow")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q", result.Action, "continue")
		}
		if result.Rule != "allow-ls" {
			t.Errorf("rule: got %q, want %q", result.Rule, "allow-ls")
		}
	})

	t.Run("deny_returns_deny", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("rm", []string{"-rf", "/"}, 5678, 1, "session-1", ExecContext{})

		if result.Decision != "deny" {
			t.Errorf("decision: got %q, want %q", result.Decision, "deny")
		}
		if result.Action != "deny" {
			t.Errorf("action: got %q, want %q", result.Action, "deny")
		}
		if result.Rule != "deny-rm" {
			t.Errorf("rule: got %q, want %q", result.Rule, "deny-rm")
		}
	})

	t.Run("redirect_effective_allow_returns_continue", func(t *testing.T) {
		// Redirect policy: PolicyDecision is "redirect" but EffectiveDecision
		// is "allow" (redirects are handled at another layer), so action = "continue".
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "redirect-git", Commands: []string{"git"}, Decision: "redirect"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("git", []string{"push"}, 9999, 1, "session-1", ExecContext{})

		if result.Decision != "redirect" {
			t.Errorf("decision: got %q, want %q", result.Decision, "redirect")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q (EffectiveDecision is allow)", result.Action, "continue")
		}
		if result.Rule != "redirect-git" {
			t.Errorf("rule: got %q, want %q", result.Rule, "redirect-git")
		}
	})

	t.Run("audit_returns_continue", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "audit-curl", Commands: []string{"curl"}, Decision: "audit"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("curl", []string{"https://example.com"}, 2222, 1, "session-1", ExecContext{})

		if result.Decision != "audit" {
			t.Errorf("decision: got %q, want %q", result.Decision, "audit")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q", result.Action, "continue")
		}
		if result.Rule != "audit-curl" {
			t.Errorf("rule: got %q, want %q", result.Rule, "audit-curl")
		}
	})

	t.Run("approve_shadow_mode_returns_continue", func(t *testing.T) {
		// In shadow mode (enforceApprovals=false), PolicyDecision is "approve"
		// but EffectiveDecision is "allow", so the action should be "continue".
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, false)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("sudo", []string{"ls"}, 3333, 1, "session-1", ExecContext{})

		if result.Decision != "approve" {
			t.Errorf("decision: got %q, want %q", result.Decision, "approve")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q (shadow mode should continue, not redirect)", result.Action, "continue")
		}
		if result.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", result.Rule, "approve-sudo")
		}
	})

	t.Run("approve_enforced_returns_redirect", func(t *testing.T) {
		// In enforced mode (enforceApprovals=true), both PolicyDecision and
		// EffectiveDecision are "approve", so the action should be "redirect".
		p := &policy.Policy{
			Version: 1,
			Name:    "test",
			CommandRules: []policy.CommandRule{
				{Name: "approve-sudo", Commands: []string{"sudo"}, Decision: "approve"},
				{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
			},
		}
		engine, err := policy.NewEngine(p, true)
		if err != nil {
			t.Fatal(err)
		}

		adapter := NewPolicyAdapter(engine, nil)
		result := adapter.CheckExec("sudo", []string{"ls"}, 3333, 1, "session-1", ExecContext{})

		if result.Decision != "approve" {
			t.Errorf("decision: got %q, want %q", result.Decision, "approve")
		}
		if result.Action != "redirect" {
			t.Errorf("action: got %q, want %q", result.Action, "redirect")
		}
		if result.Rule != "approve-sudo" {
			t.Errorf("rule: got %q, want %q", result.Rule, "approve-sudo")
		}
	})
}

// mockSessionResolver implements SessionResolver for testing.
type mockSessionResolver struct {
	sessions map[int32]string
}

func (m *mockSessionResolver) SessionForPID(pid int32) string {
	if m.sessions == nil {
		return ""
	}
	return m.sessions[pid]
}

func TestPolicyAdapter_ResolveSession(t *testing.T) {
	t.Run("nil resolver returns empty", func(t *testing.T) {
		adapter := NewPolicyAdapter(nil, nil)
		session := adapter.ResolveSession(1234)

		if session != "" {
			t.Errorf("expected empty session, got %q", session)
		}
	})

	t.Run("mock resolver returns session", func(t *testing.T) {
		resolver := &mockSessionResolver{
			sessions: map[int32]string{
				1234: "session-abc",
				5678: "session-xyz",
			},
		}
		adapter := NewPolicyAdapter(nil, resolver)

		session := adapter.ResolveSession(1234)
		if session != "session-abc" {
			t.Errorf("session: got %q, want %q", session, "session-abc")
		}

		session = adapter.ResolveSession(5678)
		if session != "session-xyz" {
			t.Errorf("session: got %q, want %q", session, "session-xyz")
		}

		// Unknown PID returns empty
		session = adapter.ResolveSession(9999)
		if session != "" {
			t.Errorf("expected empty session for unknown PID, got %q", session)
		}
	})
}

func TestPolicyAdapter_NilEngine(t *testing.T) {
	adapter := NewPolicyAdapter(nil, nil)

	t.Run("CheckFile returns no-policy", func(t *testing.T) {
		allow, rule := adapter.CheckFile("/any/path", "read")
		if !allow {
			t.Error("expected allow=true with nil engine")
		}
		if rule != "no-policy" {
			t.Errorf("rule: got %q, want %q", rule, "no-policy")
		}
	})

	t.Run("CheckNetwork returns no-policy", func(t *testing.T) {
		allow, rule := adapter.CheckNetwork("1.2.3.4", 443, "example.com")
		if !allow {
			t.Error("expected allow=true with nil engine")
		}
		if rule != "no-policy" {
			t.Errorf("rule: got %q, want %q", rule, "no-policy")
		}
	})

	t.Run("CheckCommand returns no-policy", func(t *testing.T) {
		allow, rule := adapter.CheckCommand("rm", []string{"-rf", "/"})
		if !allow {
			t.Error("expected allow=true with nil engine")
		}
		if rule != "no-policy" {
			t.Errorf("rule: got %q, want %q", rule, "no-policy")
		}
	})

	t.Run("ResolveSession returns empty", func(t *testing.T) {
		session := adapter.ResolveSession(1234)
		if session != "" {
			t.Errorf("expected empty session, got %q", session)
		}
	})

	t.Run("CheckExec returns no-policy", func(t *testing.T) {
		result := adapter.CheckExec("/usr/bin/ls", []string{"-la"}, 1234, 1, "session-1", ExecContext{})
		if result.Decision != "allow" {
			t.Errorf("decision: got %q, want %q", result.Decision, "allow")
		}
		if result.Action != "continue" {
			t.Errorf("action: got %q, want %q", result.Action, "continue")
		}
		if result.Rule != "no-policy" {
			t.Errorf("rule: got %q, want %q", result.Rule, "no-policy")
		}
	})
}
