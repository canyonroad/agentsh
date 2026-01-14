//go:build !linux

package ebpf

import "github.com/agentsh/agentsh/internal/netmonitor/pnacl"

// SetupDialogApproval is a no-op on non-Linux platforms.
// On Linux, this configures the monitor to use native OS dialogs for approval prompts.
func (m *PNACLMonitor) SetupDialogApproval(approvalConfig *pnacl.ApprovalUIConfig, fallbackDecision pnacl.Decision) {
	// No-op on non-Linux platforms
}
