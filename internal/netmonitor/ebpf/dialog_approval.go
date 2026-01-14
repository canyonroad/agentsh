//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/approval/dialog"
	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

// SetupDialogApproval configures the monitor to use native OS dialogs for approval prompts.
// If dialog is not available (no display, CI environment), returns without setting up.
// The fallbackDecision is used when dialog cannot be shown or times out.
func (m *PNACLMonitor) SetupDialogApproval(approvalConfig *pnacl.ApprovalUIConfig, fallbackDecision pnacl.Decision) {
	mode := "auto"
	if approvalConfig != nil {
		mode = approvalConfig.GetMode()
	}

	if !dialog.IsEnabled(mode) {
		return
	}

	m.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		return showApprovalDialog(pc, approvalConfig, fallbackDecision)
	})
}

// showApprovalDialog displays a native dialog for connection approval.
func showApprovalDialog(pc *PendingConnection, config *pnacl.ApprovalUIConfig, fallback pnacl.Decision) pnacl.Decision {
	// Build the dialog message
	processName := "unknown"
	if pc.Process != nil {
		processName = pc.Process.Name
	}

	message := fmt.Sprintf("Process: %s (pid: %d)\nTarget: %s:%d (%s)",
		processName,
		pc.Event.PID,
		pc.Host,
		pc.Port,
		pc.Protocol,
	)

	// Determine timeout (config.GetTimeout() safely handles nil config)
	timeout := time.Duration(0)
	if config != nil {
		timeout = config.GetTimeout()
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	req := dialog.Request{
		Title:   "Network Access Request",
		Message: message,
		Timeout: timeout,
	}

	resp, err := dialog.Show(context.Background(), req)
	if err != nil || resp.TimedOut {
		return fallback
	}

	if resp.Allowed {
		return pnacl.DecisionAllow
	}
	return pnacl.DecisionDeny
}
