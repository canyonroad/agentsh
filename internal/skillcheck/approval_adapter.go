package skillcheck

import (
	"context"
	"fmt"
)

// ApprovalBackend is the function signature the adapter delegates to. The
// real wiring (in cmd/agentsh) passes a closure that calls into
// internal/approval/dialog. Tests inject a stub.
type ApprovalBackend func(ctx context.Context, prompt string) (bool, error)

type approvalAdapter struct {
	backend ApprovalBackend
}

// NewApprovalAdapter wraps an ApprovalBackend in an Approver.
func NewApprovalAdapter(backend ApprovalBackend) Approver {
	return &approvalAdapter{backend: backend}
}

func (a *approvalAdapter) Ask(ctx context.Context, skill SkillRef, v *Verdict) (bool, error) {
	sha := skill.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	prompt := fmt.Sprintf("Skill %q (%s) requires approval: %s", skill.Name, sha, v.Summary)
	ok, err := a.backend(ctx, prompt)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, err
	}
	return ok, nil
}
