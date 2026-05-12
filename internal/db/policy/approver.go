package policy

import (
	"context"
	"errors"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ErrApproverNotConfigured is reserved for callers that require an explicit
// approver. The proxy default is NopApprover{}.
var ErrApproverNotConfigured = errors.New("policy: approver not configured")

// Approver decides whether a statement awaiting approval should run.
type Approver interface {
	Decide(ctx context.Context, cs effects.ClassifiedStatement, timeout time.Duration) (approved bool, err error)
}

// NopApprover is the default. It blocks until context cancellation or timeout,
// then denies by returning approved=false.
type NopApprover struct{}

func (NopApprover) Decide(ctx context.Context, _ effects.ClassifiedStatement, timeout time.Duration) (bool, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, nil
	}
}
