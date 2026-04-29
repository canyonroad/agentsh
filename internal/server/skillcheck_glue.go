package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/skillcheck"
	"github.com/agentsh/agentsh/internal/skillcheck/provider"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// buildSkillcheckProviders constructs a ProviderEntry map from the config.
func buildSkillcheckProviders(cfgs map[string]config.SkillcheckProviderConfig) map[string]skillcheck.ProviderEntry {
	out := map[string]skillcheck.ProviderEntry{}
	for name, c := range cfgs {
		if !c.Enabled {
			continue
		}
		var p skillcheck.CheckProvider
		switch name {
		case "local":
			p = provider.NewLocalProvider()
		case "snyk":
			p = provider.NewSnykProvider(provider.SnykConfig{BinaryPath: c.BinaryPath})
		case "skills_sh":
			p = provider.NewSkillsShProvider(provider.SkillsShConfig{
				BaseURL:     c.BaseURL,
				ProbeAudits: c.ProbeAudits,
				Timeout:     c.Timeout,
			})
		case "chainguard":
			p = provider.NewChainguardProvider()
		case "repello":
			p = provider.NewRepelloProvider()
		}
		if p == nil {
			continue
		}
		out[name] = skillcheck.ProviderEntry{Provider: p, Timeout: c.Timeout, OnFailure: c.OnFailure}
	}
	return out
}

// buildSkillcheckThresholds converts the string→string YAML map into
// the typed Thresholds map. Unknown keys and values are silently ignored
// so a stale config does not break startup; the defaults cover omitted entries.
func buildSkillcheckThresholds(cfgs map[string]string) skillcheck.Thresholds {
	if len(cfgs) == 0 {
		return skillcheck.DefaultThresholds()
	}
	t := skillcheck.DefaultThresholds()
	for sev, action := range cfgs {
		t[skillcheck.Severity(sev)] = skillcheck.VerdictAction(action)
	}
	return t
}

// skillcheckAuditSink adapts composite.Store to skillcheck.AuditSink.
type skillcheckAuditSink struct {
	store *composite.Store
}

func newSkillcheckAuditSink(store *composite.Store) skillcheck.AuditSink {
	return &skillcheckAuditSink{store: store}
}

func (s *skillcheckAuditSink) Emit(ctx context.Context, ev skillcheck.AuditEvent) {
	fields := map[string]any{
		"skill_name":   ev.Skill.Name,
		"skill_path":   ev.Skill.Path,
		"skill_sha256": ev.Skill.SHA256,
	}
	if ev.Verdict != nil {
		fields["verdict_action"] = string(ev.Verdict.Action)
		fields["verdict_summary"] = ev.Verdict.Summary
	}
	if ev.TrashID != "" {
		fields["trash_id"] = ev.TrashID
	}
	for k, v := range ev.Extra {
		fields[k] = v
	}
	at := ev.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// Encode the full AuditEvent as JSON in the Fields map for structured logging.
	if raw, err := json.Marshal(ev); err == nil {
		fields["_raw"] = string(raw)
	}

	tev := types.Event{
		Timestamp: at,
		Type:      ev.Kind,
		Fields:    fields,
	}
	_ = s.store.AppendEvent(ctx, tev)
}

// skillcheckApproval wraps approvals.Manager as skillcheck.Approver.
// When approvalsMgr is nil (approvals not enabled), every ask returns approved=true
// so that a block verdict is not silently dropped — the daemon will quarantine
// after approval is denied, and with no approval manager we default to allowing
// the user to proceed (fail-open on approval, not fail-open on block).
type skillcheckApproval struct {
	mgr *approvals.Manager
}

func newSkillcheckApproval(mgr *approvals.Manager) skillcheck.Approver {
	return &skillcheckApproval{mgr: mgr}
}

func (a *skillcheckApproval) Ask(ctx context.Context, skill skillcheck.SkillRef, v *skillcheck.Verdict) (bool, error) {
	if a.mgr == nil {
		// No approval manager configured; fall back to allow.
		return true, nil
	}
	sha := skill.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	req := approvals.Request{
		Kind:    "skillcheck",
		Target:  skill.Name,
		Message: "Skill " + skill.Name + " (" + sha + ") requires approval: " + v.Summary,
		Fields: map[string]any{
			"skill_name":   skill.Name,
			"skill_path":   skill.Path,
			"skill_sha256": skill.SHA256,
			"verdict":      string(v.Action),
			"summary":      v.Summary,
		},
	}
	res, err := a.mgr.RequestApproval(ctx, req)
	if err != nil {
		return false, err
	}
	return res.Approved, nil
}
