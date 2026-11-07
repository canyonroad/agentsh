package api

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/approvals"
)

// approvalsFSAdapter exposes approvals.Manager to the platform/FUSE layer as
// platform.Approver (internal/platform cannot import internal/approvals:
// approvals imports platform). A nil manager or a negative resolution is an
// error, so the filesystem layer fails closed.
type approvalsFSAdapter struct {
	mgr *approvals.Manager
}

func (a approvalsFSAdapter) RequestApproval(ctx context.Context, sessionID, kind, target, rule, message, op string) error {
	if a.mgr == nil {
		return fmt.Errorf("approvals not configured")
	}
	res, err := a.mgr.RequestApproval(ctx, approvals.Request{
		SessionID: sessionID,
		Kind:      kind,
		Target:    target,
		Rule:      rule,
		Message:   message,
		Fields:    map[string]any{"operation": op},
	})
	if err != nil {
		return err
	}
	if !res.Approved {
		return fmt.Errorf("not approved: %s", res.Reason)
	}
	return nil
}
