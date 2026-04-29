package skillcheck

import (
	"context"
	"errors"
	"testing"
)

type fakeQuarantine struct {
	moved []string
	err   error
}

func (f *fakeQuarantine) Quarantine(skill SkillRef, reason string) (string, error) {
	f.moved = append(f.moved, skill.Path)
	return "trash-token-123", f.err
}

type fakeApproval struct {
	approved bool
	asked    int
}

func (a *fakeApproval) Ask(ctx context.Context, skill SkillRef, v *Verdict) (bool, error) {
	a.asked++
	return a.approved, nil
}

type fakeAudit struct {
	events []AuditEvent
}

func (a *fakeAudit) Emit(ctx context.Context, ev AuditEvent) { a.events = append(a.events, ev) }

func TestApply_Allow_NoOp(t *testing.T) {
	q := &fakeQuarantine{}
	au := &fakeAudit{}
	d := NewActioner(q, &fakeApproval{}, au)
	v := &Verdict{Action: VerdictAllow}
	if err := d.Apply(context.Background(), SkillRef{Name: "x", SHA256: "h"}, v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(q.moved) != 0 {
		t.Errorf("allow should not quarantine")
	}
	if len(au.events) != 1 || au.events[0].Kind != "skillcheck.scan_completed" {
		t.Errorf("expected one scan_completed event, got %+v", au.events)
	}
}

func TestApply_Block_Quarantines(t *testing.T) {
	q := &fakeQuarantine{}
	au := &fakeAudit{}
	d := NewActioner(q, &fakeApproval{}, au)
	skill := SkillRef{Name: "x", Path: "/tmp/x", SHA256: "h"}
	v := &Verdict{Action: VerdictBlock}
	if err := d.Apply(context.Background(), skill, v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(q.moved) != 1 || q.moved[0] != "/tmp/x" {
		t.Errorf("block should quarantine; moved=%v", q.moved)
	}
	if len(au.events) < 2 {
		t.Fatalf("expected scan_completed + quarantined; got %+v", au.events)
	}
	hasQuarantined := false
	for _, e := range au.events {
		if e.Kind == "skillcheck.quarantined" {
			hasQuarantined = true
		}
	}
	if !hasQuarantined {
		t.Errorf("expected skillcheck.quarantined event")
	}
}

func TestApply_Approve_PromptsAndDeniesEscalates(t *testing.T) {
	q := &fakeQuarantine{}
	au := &fakeAudit{}
	app := &fakeApproval{approved: false}
	d := NewActioner(q, app, au)
	skill := SkillRef{Name: "x", Path: "/tmp/x", SHA256: "h"}
	v := &Verdict{Action: VerdictApprove}
	if err := d.Apply(context.Background(), skill, v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if app.asked != 1 {
		t.Errorf("approval asked=%d want 1", app.asked)
	}
	if len(q.moved) != 1 {
		t.Errorf("denied approval should escalate to block")
	}
}

func TestApply_QuarantineErrorIsReturned(t *testing.T) {
	q := &fakeQuarantine{err: errors.New("disk full")}
	d := NewActioner(q, &fakeApproval{}, &fakeAudit{})
	v := &Verdict{Action: VerdictBlock}
	err := d.Apply(context.Background(), SkillRef{Name: "x", Path: "/tmp/x"}, v)
	if err == nil {
		t.Errorf("expected error from failed quarantine")
	}
}
