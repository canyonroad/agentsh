package api

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/platform"
)

// approvalsFSAdapter exposes approvals.Manager to the platform/FUSE layer as
// platform.Approver (internal/platform cannot import internal/approvals:
// approvals imports platform). A nil manager or a negative resolution is an
// error, so the filesystem layer fails closed.
type approvalsFSAdapter struct {
	mgr *approvals.Manager
}

func (a approvalsFSAdapter) RequestApproval(ctx context.Context, preq platform.ApprovalRequest) error {
	if a.mgr == nil {
		return fmt.Errorf("approvals not configured")
	}
	res, err := a.mgr.RequestApproval(ctx, approvals.Request{
		ID:        preq.ID,
		SessionID: preq.SessionID,
		CommandID: preq.CommandID,
		Kind:      preq.Kind,
		Target:    preq.Target,
		Rule:      preq.Rule,
		Message:   preq.Message,
		Fields:    map[string]any{"operation": preq.Op},
	})
	if err != nil {
		return err
	}
	if !res.Approved {
		return fmt.Errorf("not approved: %s", res.Reason)
	}
	return nil
}
