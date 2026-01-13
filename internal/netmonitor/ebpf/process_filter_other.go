//go:build !linux

package ebpf

import (
	"context"
	"errors"
	"net"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

// ProcessFilter is not supported on non-Linux platforms.
type ProcessFilter struct{}

// PendingConnection is not supported on non-Linux platforms.
type PendingConnection struct {
	ID        uint64
	Process   *pnacl.ProcessInfo
	Host      string
	IP        net.IP
	Port      int
	Protocol  string
}

// ConnectionEvent is not supported on non-Linux platforms.
type ConnectionEvent struct {
	PID      uint32
	Protocol string
	DstPort  uint16
	DstIP    net.IP
	Host     string
	Process  *pnacl.ProcessInfo
	Decision pnacl.Decision
	Blocked  bool
}

// ProcessFilterConfig is not supported on non-Linux platforms.
type ProcessFilterConfig struct{}

var errNotSupported = errors.New("process filter not supported on this platform")

// NewProcessFilter returns an error on non-Linux platforms.
func NewProcessFilter(engine *pnacl.PolicyEngine) *ProcessFilter {
	return nil
}

// SetPolicyEngine is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetPolicyEngine(engine *pnacl.PolicyEngine) {}

// SetOnApprovalNeeded is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetOnApprovalNeeded(fn func(*PendingConnection) pnacl.Decision) {}

// SetOnAudit is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetOnAudit(fn func(*ConnectionEvent)) {}

// SetOnDeny is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetOnDeny(fn func(*ConnectionEvent)) {}

// SetOnAllow is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetOnAllow(fn func(*ConnectionEvent)) {}

// SetOnApprovalGranted is not supported on non-Linux platforms.
func (pf *ProcessFilter) SetOnApprovalGranted(fn func(*ConnectionEvent)) {}

// ProcessEvent is not supported on non-Linux platforms.
func (pf *ProcessFilter) ProcessEvent(ctx context.Context, ev *ConnectEvent, config *ProcessFilterConfig) pnacl.Decision {
	return pnacl.DecisionDeny
}

// AddDNSMapping is not supported on non-Linux platforms.
func (pf *ProcessFilter) AddDNSMapping(name string, ip net.IP) {}

// ClearProcessCache is not supported on non-Linux platforms.
func (pf *ProcessFilter) ClearProcessCache() {}

// ClearAllowOnceState is not supported on non-Linux platforms.
func (pf *ProcessFilter) ClearAllowOnceState() {}

// GetPendingConnections is not supported on non-Linux platforms.
func (pf *ProcessFilter) GetPendingConnections() []*PendingConnection {
	return nil
}

// ApproveConnection is not supported on non-Linux platforms.
func (pf *ProcessFilter) ApproveConnection(id uint64) bool {
	return false
}

// DenyConnection is not supported on non-Linux platforms.
func (pf *ProcessFilter) DenyConnection(id uint64) bool {
	return false
}

// Close is not supported on non-Linux platforms.
func (pf *ProcessFilter) Close() error {
	return nil
}
