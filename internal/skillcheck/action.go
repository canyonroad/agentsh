package skillcheck

import (
	"context"
	"fmt"
	"time"
)

// Quarantiner moves a quarantined skill into safe storage and returns a
// restore token. The agentsh implementation wraps internal/trash; tests
// inject a fake.
type Quarantiner interface {
	Quarantine(skill SkillRef, reason string) (token string, err error)
}

// Approver prompts the user for an approve/deny decision on a verdict.
// Returns true if approved.
type Approver interface {
	Ask(ctx context.Context, skill SkillRef, v *Verdict) (bool, error)
}

// AuditSink receives scan/quarantine/approval events.
type AuditSink interface {
	Emit(ctx context.Context, ev AuditEvent)
}

// AuditEvent is the payload emitted by the action layer.
type AuditEvent struct {
	Kind    string            `json:"kind"`
	At      time.Time         `json:"at"`
	Skill   SkillRef          `json:"skill"`
	Verdict *Verdict          `json:"verdict,omitempty"`
	TrashID string            `json:"trash_id,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
}

// Actioner dispatches verdict-driven side effects.
type Actioner struct {
	quarantine Quarantiner
	approval   Approver
	audit      AuditSink
}

// NewActioner creates a new Actioner with the given dependencies.
func NewActioner(q Quarantiner, a Approver, s AuditSink) *Actioner {
	return &Actioner{quarantine: q, approval: a, audit: s}
}

// Apply executes the verdict's action. allow → no-op + audit; warn → audit;
// approve → prompt; on deny escalate to block; block → quarantine + audit.
func (a *Actioner) Apply(ctx context.Context, skill SkillRef, v *Verdict) error {
	a.audit.Emit(ctx, AuditEvent{Kind: "skillcheck.scan_completed", At: time.Now(), Skill: skill, Verdict: v})

	switch v.Action {
	case VerdictAllow, VerdictWarn:
		return nil
	case VerdictApprove:
		approved, err := a.approval.Ask(ctx, skill, v)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("approval: %w", err)
		}
		if approved {
			a.audit.Emit(ctx, AuditEvent{Kind: "skillcheck.user_approved", At: time.Now(), Skill: skill})
			return nil
		}
		// Denied → escalate to block.
		return a.quarantineAndEmit(ctx, skill, v, "user denied approval")
	case VerdictBlock:
		return a.quarantineAndEmit(ctx, skill, v, v.Summary)
	default:
		return fmt.Errorf("skillcheck: unknown verdict action %q", v.Action)
	}
}

func (a *Actioner) quarantineAndEmit(ctx context.Context, skill SkillRef, v *Verdict, reason string) error {
	token, err := a.quarantine.Quarantine(skill, reason)
	if err != nil {
		return fmt.Errorf("quarantine: %w", err)
	}
	a.audit.Emit(ctx, AuditEvent{
		Kind:    "skillcheck.quarantined",
		At:      time.Now(),
		Skill:   skill,
		Verdict: v,
		TrashID: token,
	})
	return nil
}
