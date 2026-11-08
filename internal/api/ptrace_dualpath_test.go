//go:build linux

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/ptrace"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestMergeDualPathDecision(t *testing.T) {
	allow := policy.Decision{PolicyDecision: types.DecisionAllow, EffectiveDecision: types.DecisionAllow}
	deny := policy.Decision{PolicyDecision: types.DecisionDeny, EffectiveDecision: types.DecisionDeny, Rule: "d"}
	approve := policy.Decision{PolicyDecision: types.DecisionApprove, EffectiveDecision: types.DecisionApprove, Rule: "a"}
	approveDeny := policy.Decision{PolicyDecision: types.DecisionApprove, EffectiveDecision: types.DecisionDeny, Rule: "ad"}
	redirect := policy.Decision{PolicyDecision: types.DecisionRedirect, EffectiveDecision: types.DecisionRedirect, Rule: "r"}
	softDelete := policy.Decision{PolicyDecision: types.DecisionSoftDelete, EffectiveDecision: types.DecisionAllow, Rule: "s"}

	tests := []struct {
		name             string
		primary, second  policy.Decision
		wantEffective    types.Decision
		wantPolicyDec    types.Decision
		wantRuleContains string
	}{
		{"second deny wins", allow, deny, types.DecisionDeny, types.DecisionDeny, ""},
		{"primary deny kept", deny, allow, types.DecisionDeny, types.DecisionDeny, ""},
		{"second approve", allow, approve, types.DecisionApprove, types.DecisionApprove, ""},
		{"second shadow approve (effective deny)", allow, approveDeny, types.DecisionDeny, types.DecisionApprove, ""},
		{"primary approve kept", approve, allow, types.DecisionApprove, types.DecisionApprove, ""},
		{"second redirect fails closed", allow, redirect, types.DecisionDeny, types.DecisionRedirect, "unsupported in ptrace"},
		{"second soft_delete fails closed", allow, softDelete, types.DecisionDeny, types.DecisionSoftDelete, "unsupported in ptrace"},
		{"primary redirect kept", redirect, allow, types.DecisionRedirect, types.DecisionRedirect, ""},
		{"both allow", allow, allow, types.DecisionAllow, types.DecisionAllow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDualPathDecision(tt.primary, tt.second)
			if got.EffectiveDecision != tt.wantEffective || got.PolicyDecision != tt.wantPolicyDec {
				t.Fatalf("got %s/%s, want %s/%s", got.PolicyDecision, got.EffectiveDecision, tt.wantPolicyDec, tt.wantEffective)
			}
			if tt.wantRuleContains != "" && !strings.Contains(got.Rule, tt.wantRuleContains) {
				t.Fatalf("rule %q does not mention %q", got.Rule, tt.wantRuleContains)
			}
		})
	}
}

func dualPathEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "dual-path",
		FileRules: []policy.FileRule{
			{Name: "allow-src", Paths: []string{"/src/**"}, Operations: []string{"*"}, Decision: "allow"},
			{Name: "deny-dest", Paths: []string{"/dest/**"}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "approve-gate", Paths: []string{"/gate/**"}, Operations: []string{"*"}, Decision: "approve"},
		},
	}
	eng, err := policy.NewEngine(p, true, true) // approvals enforced → approve stays approve
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestHandleFile_Path2DeniedDenies(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	sess, err := mgr.CreateWithID("test-dual-path-deny", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(dualPathEngine(t))

	res := router.HandleFile(context.Background(), ptrace.FileContext{
		SessionID: sess.ID,
		PID:       1234,
		Path:      "/src/a",
		Path2:     "/dest/a",
		Operation: "rename",
	})
	if res.Allow {
		t.Fatalf("rename into a denied tree was allowed: %+v", res)
	}
}

func TestHandleFile_Path2ApproveDeniesInPtraceMode(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	sess, err := mgr.CreateWithID("test-dual-path-approve", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(dualPathEngine(t))

	res := router.HandleFile(context.Background(), ptrace.FileContext{
		SessionID: sess.ID,
		PID:       1234,
		Path:      "/src/a",
		Path2:     "/gate/a",
		Operation: "link",
	})
	if res.Allow {
		t.Fatalf("link onto an approve-gated path was allowed without approval: %+v", res)
	}
}

func TestHandleExecve_TruncatedArgvDenies(t *testing.T) {
	router, mgr := newTestRouter(t, "")
	sess, err := mgr.CreateWithID("test-truncated-argv", t.TempDir(), "")
	if err != nil {
		t.Fatalf("CreateWithID: %v", err)
	}
	sess.SetPolicyEngine(dualPathEngine(t))

	res := router.HandleExecve(context.Background(), ptrace.ExecContext{
		SessionID: sess.ID,
		PID:       1234,
		Filename:  "/usr/bin/curl",
		Argv:      []string{"curl", "https://example.test"},
		Truncated: true,
	})
	if res.Allow {
		t.Fatalf("exec with truncated argv was allowed: %+v", res)
	}
}

func TestCheckPolicyNameAllowed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policies.Default = "default"
	app := &App{cfg: cfg}

	if err := app.checkPolicyNameAllowed("default"); err != nil {
		t.Fatalf("default rejected: %v", err)
	}
	if err := app.checkPolicyNameAllowed("bench-allow-all"); err == nil {
		t.Fatal("empty policies.allowed must reject a non-default policy")
	}

	app.cfg.Policies.Allowed = []string{"default", "strict"}
	if err := app.checkPolicyNameAllowed("strict"); err != nil {
		t.Fatalf("allowlisted policy rejected: %v", err)
	}
	if err := app.checkPolicyNameAllowed("bench-allow-all"); err == nil {
		t.Fatal("policy outside policies.allowed was accepted")
	}
}

func TestCheckPolicyAllowlisted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policies.Default = "default"
	app := &App{cfg: cfg}
	// Empty list: profiles/mounts keep working.
	if err := app.checkPolicyAllowlisted("workspace-rw"); err != nil {
		t.Fatalf("empty allowlist rejected a mount policy: %v", err)
	}
	// Non-empty list is enforced.
	app.cfg.Policies.Allowed = []string{"default"}
	if err := app.checkPolicyAllowlisted("workspace-rw"); err == nil {
		t.Fatal("non-empty allowlist accepted a policy outside it")
	}
}
