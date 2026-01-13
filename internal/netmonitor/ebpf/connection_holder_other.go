//go:build !linux

package ebpf

import (
	"context"
	"errors"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

// ConnectionHolder is not supported on non-Linux platforms.
type ConnectionHolder struct{}

// ConnectionHolderConfig is not supported on non-Linux platforms.
type ConnectionHolderConfig struct {
	ApprovalTimeout  int
	DefaultOnTimeout pnacl.Decision
	EventBufferSize  int
	EnableMetrics    bool
}

// ConnectionHolderStats is not supported on non-Linux platforms.
type ConnectionHolderStats struct {
	EventsReceived  uint64
	EventsProcessed uint64
	EventsAllowed   uint64
	EventsDenied    uint64
	EventsApproved  uint64
	EventsAudited   uint64
	EventsTimedOut  uint64
	Errors          uint64
}

// DefaultConnectionHolderConfig returns nil on non-Linux platforms.
func DefaultConnectionHolderConfig() *ConnectionHolderConfig {
	return nil
}

// NewConnectionHolder returns an error on non-Linux platforms.
func NewConnectionHolder(coll interface{}, filter *ProcessFilter, config *ConnectionHolderConfig) (*ConnectionHolder, error) {
	return nil, errors.New("connection holder not supported on this platform")
}

// Start is not supported on non-Linux platforms.
func (h *ConnectionHolder) Start(ctx context.Context) {}

// GetStats is not supported on non-Linux platforms.
func (h *ConnectionHolder) GetStats() ConnectionHolderStats {
	return ConnectionHolderStats{}
}

// Filter is not supported on non-Linux platforms.
func (h *ConnectionHolder) Filter() *ProcessFilter {
	return nil
}

// Close is not supported on non-Linux platforms.
func (h *ConnectionHolder) Close() error {
	return nil
}

// PNACLMonitor is not supported on non-Linux platforms.
type PNACLMonitor struct{}

// PNACLMonitorConfig is not supported on non-Linux platforms.
type PNACLMonitorConfig struct {
	CgroupPath   string
	HolderConfig *ConnectionHolderConfig
}

// DefaultPNACLMonitorConfig returns nil on non-Linux platforms.
func DefaultPNACLMonitorConfig() *PNACLMonitorConfig {
	return nil
}

// NewPNACLMonitor returns an error on non-Linux platforms.
func NewPNACLMonitor(engine *pnacl.PolicyEngine, config *PNACLMonitorConfig) (*PNACLMonitor, error) {
	return nil, errors.New("PNACL monitor not supported on this platform")
}

// Start is not supported on non-Linux platforms.
func (m *PNACLMonitor) Start(ctx context.Context) error {
	return errors.New("not supported")
}

// SetPolicyEngine is not supported on non-Linux platforms.
func (m *PNACLMonitor) SetPolicyEngine(engine *pnacl.PolicyEngine) {}

// SetOnApprovalNeeded is not supported on non-Linux platforms.
func (m *PNACLMonitor) SetOnApprovalNeeded(fn func(*PendingConnection) pnacl.Decision) {}

// SetOnAudit is not supported on non-Linux platforms.
func (m *PNACLMonitor) SetOnAudit(fn func(*ConnectionEvent)) {}

// SetOnDeny is not supported on non-Linux platforms.
func (m *PNACLMonitor) SetOnDeny(fn func(*ConnectionEvent)) {}

// SetOnAllow is not supported on non-Linux platforms.
func (m *PNACLMonitor) SetOnAllow(fn func(*ConnectionEvent)) {}

// GetPendingConnections is not supported on non-Linux platforms.
func (m *PNACLMonitor) GetPendingConnections() []*PendingConnection {
	return nil
}

// ApproveConnection is not supported on non-Linux platforms.
func (m *PNACLMonitor) ApproveConnection(id uint64) bool {
	return false
}

// DenyConnection is not supported on non-Linux platforms.
func (m *PNACLMonitor) DenyConnection(id uint64) bool {
	return false
}

// GetStats is not supported on non-Linux platforms.
func (m *PNACLMonitor) GetStats() *ConnectionHolderStats {
	return nil
}

// Filter is not supported on non-Linux platforms.
func (m *PNACLMonitor) Filter() *ProcessFilter {
	return nil
}

// Stop is not supported on non-Linux platforms.
func (m *PNACLMonitor) Stop() error {
	return nil
}

// IsRunning is not supported on non-Linux platforms.
func (m *PNACLMonitor) IsRunning() bool {
	return false
}
