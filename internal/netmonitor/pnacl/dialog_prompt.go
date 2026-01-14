package pnacl

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/approval/dialog"
)

// DialogPromptProvider implements PromptProvider using native OS dialogs.
type DialogPromptProvider struct {
	// FallbackDecision is returned when dialog is unavailable or times out.
	FallbackDecision UserDecision
}

// NewDialogPromptProvider creates a new dialog prompt provider.
func NewDialogPromptProvider(fallback UserDecision) *DialogPromptProvider {
	return &DialogPromptProvider{
		FallbackDecision: fallback,
	}
}

// Prompt displays a native dialog and waits for user response.
func (p *DialogPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
	// Build dialog request
	dialogReq := dialog.Request{
		Title:   "Network Access Request",
		Message: fmt.Sprintf("Process: %s (pid: %d)\nTarget: %s:%d (%s)",
			req.ProcessName, req.PID, req.Target, req.Port, req.Protocol),
		Timeout: time.Until(req.ExpiresAt),
	}

	// Show dialog
	resp, err := dialog.Show(ctx, dialogReq)

	// Handle errors and timeout - return fallback with nil error so caller uses the response
	if err != nil || resp.TimedOut {
		reason := "dialog timed out"
		if err != nil {
			reason = fmt.Sprintf("dialog unavailable: %v", err)
		}
		return ApprovalResponse{
			RequestID: req.ID,
			Decision:  p.FallbackDecision,
			At:        time.Now().UTC(),
			Reason:    reason,
		}, nil // Return nil error so the fallback response is used
	}

	// Convert response
	decision := UserDecisionDenyOnce
	if resp.Allowed {
		decision = UserDecisionAllowOnce
	}

	return ApprovalResponse{
		RequestID: req.ID,
		Decision:  decision,
		At:        time.Now().UTC(),
	}, nil
}
