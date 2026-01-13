//go:build linux

package ebpf

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
	"github.com/cilium/ebpf"
)

// ConnectionHolder manages connections that are being held for approval decisions.
// It coordinates between the eBPF collector and the policy filter.
type ConnectionHolder struct {
	mu sync.RWMutex

	// Collection is the eBPF collection
	coll *ebpf.Collection

	// Collector for reading events
	collector *Collector

	// ProcessFilter for policy evaluation
	filter *ProcessFilter

	// Config
	config *ConnectionHolderConfig

	// Metrics
	stats ConnectionHolderStats

	done chan struct{}
}

// ConnectionHolderConfig configures the connection holder.
type ConnectionHolderConfig struct {
	// ApprovalTimeout is how long to wait for user approval
	ApprovalTimeout time.Duration

	// DefaultOnTimeout is the decision when approval times out
	DefaultOnTimeout pnacl.Decision

	// EventBufferSize is the size of the event buffer
	EventBufferSize int

	// EnableMetrics enables metrics collection
	EnableMetrics bool
}

// ConnectionHolderStats contains metrics about connection handling.
type ConnectionHolderStats struct {
	mu              sync.RWMutex
	EventsReceived  uint64
	EventsProcessed uint64
	EventsAllowed   uint64
	EventsDenied    uint64
	EventsApproved  uint64
	EventsAudited   uint64
	EventsTimedOut  uint64
	Errors          uint64
}

// DefaultConnectionHolderConfig returns the default configuration.
func DefaultConnectionHolderConfig() *ConnectionHolderConfig {
	return &ConnectionHolderConfig{
		ApprovalTimeout:  30 * time.Second,
		DefaultOnTimeout: pnacl.DecisionDeny,
		EventBufferSize:  1024,
		EnableMetrics:    true,
	}
}

// NewConnectionHolder creates a new connection holder.
func NewConnectionHolder(coll *ebpf.Collection, filter *ProcessFilter, config *ConnectionHolderConfig) (*ConnectionHolder, error) {
	if coll == nil {
		return nil, errors.New("nil collection")
	}
	if filter == nil {
		return nil, errors.New("nil filter")
	}
	if config == nil {
		config = DefaultConnectionHolderConfig()
	}

	collector, err := StartCollector(coll, config.EventBufferSize)
	if err != nil {
		return nil, err
	}

	h := &ConnectionHolder{
		coll:      coll,
		collector: collector,
		filter:    filter,
		config:    config,
		done:      make(chan struct{}),
	}

	return h, nil
}

// Start begins processing connection events.
func (h *ConnectionHolder) Start(ctx context.Context) {
	go h.processEvents(ctx)
}

// processEvents reads events from the collector and processes them.
func (h *ConnectionHolder) processEvents(ctx context.Context) {
	events := h.collector.Events()

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.done:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}

			h.incEventsReceived()

			// Process the event through the filter
			filterConfig := &ProcessFilterConfig{
				ApprovalTimeout:  h.config.ApprovalTimeout,
				DefaultOnTimeout: h.config.DefaultOnTimeout,
			}

			decision := h.filter.ProcessEvent(ctx, &ev, filterConfig)

			h.incEventsProcessed()

			// Update stats based on decision
			switch decision {
			case pnacl.DecisionAllow:
				h.incEventsAllowed()
			case pnacl.DecisionDeny:
				h.incEventsDenied()
			case pnacl.DecisionApprove:
				h.incEventsApproved()
			case pnacl.DecisionAudit:
				h.incEventsAudited()
			}
		}
	}
}

// GetStats returns a copy of the current stats.
func (h *ConnectionHolder) GetStats() ConnectionHolderStats {
	h.stats.mu.RLock()
	defer h.stats.mu.RUnlock()
	return ConnectionHolderStats{
		EventsReceived:  h.stats.EventsReceived,
		EventsProcessed: h.stats.EventsProcessed,
		EventsAllowed:   h.stats.EventsAllowed,
		EventsDenied:    h.stats.EventsDenied,
		EventsApproved:  h.stats.EventsApproved,
		EventsAudited:   h.stats.EventsAudited,
		EventsTimedOut:  h.stats.EventsTimedOut,
		Errors:          h.stats.Errors,
	}
}

func (h *ConnectionHolder) incEventsReceived() {
	h.stats.mu.Lock()
	h.stats.EventsReceived++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsProcessed() {
	h.stats.mu.Lock()
	h.stats.EventsProcessed++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsAllowed() {
	h.stats.mu.Lock()
	h.stats.EventsAllowed++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsDenied() {
	h.stats.mu.Lock()
	h.stats.EventsDenied++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsApproved() {
	h.stats.mu.Lock()
	h.stats.EventsApproved++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsAudited() {
	h.stats.mu.Lock()
	h.stats.EventsAudited++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incEventsTimedOut() {
	h.stats.mu.Lock()
	h.stats.EventsTimedOut++
	h.stats.mu.Unlock()
}

func (h *ConnectionHolder) incErrors() {
	h.stats.mu.Lock()
	h.stats.Errors++
	h.stats.mu.Unlock()
}

// Filter returns the process filter.
func (h *ConnectionHolder) Filter() *ProcessFilter {
	return h.filter
}

// Collector returns the underlying collector.
func (h *ConnectionHolder) Collector() *Collector {
	return h.collector
}

// Close stops the connection holder.
func (h *ConnectionHolder) Close() error {
	select {
	case <-h.done:
		return nil
	default:
		close(h.done)
	}

	if h.collector != nil {
		h.collector.Close()
	}
	if h.filter != nil {
		h.filter.Close()
	}
	return nil
}

// PNACLMonitor provides the high-level interface for PNACL-based network monitoring.
// It combines eBPF collection with policy evaluation and connection management.
type PNACLMonitor struct {
	mu sync.RWMutex

	// cgroupPath is the cgroup to monitor
	cgroupPath string

	// Engine is the policy engine
	engine *pnacl.PolicyEngine

	// Filter handles policy evaluation
	filter *ProcessFilter

	// Collection and holder
	coll   *ebpf.Collection
	holder *ConnectionHolder

	// Detach function
	detach func() error

	// Config
	config *PNACLMonitorConfig

	// State
	running bool
}

// PNACLMonitorConfig configures the PNACL monitor.
type PNACLMonitorConfig struct {
	// CgroupPath is the cgroup to attach to (default: /sys/fs/cgroup)
	CgroupPath string

	// ConnectionHolderConfig for the connection holder
	HolderConfig *ConnectionHolderConfig
}

// DefaultPNACLMonitorConfig returns the default configuration.
func DefaultPNACLMonitorConfig() *PNACLMonitorConfig {
	return &PNACLMonitorConfig{
		CgroupPath:   "/sys/fs/cgroup",
		HolderConfig: DefaultConnectionHolderConfig(),
	}
}

// NewPNACLMonitor creates a new PNACL monitor.
func NewPNACLMonitor(engine *pnacl.PolicyEngine, config *PNACLMonitorConfig) (*PNACLMonitor, error) {
	if config == nil {
		config = DefaultPNACLMonitorConfig()
	}

	// Check eBPF support
	status := CheckSupport()
	if !status.Supported {
		return nil, errors.New("ebpf not supported: " + status.Reason)
	}

	filter := NewProcessFilter(engine)

	return &PNACLMonitor{
		cgroupPath: config.CgroupPath,
		engine:     engine,
		filter:     filter,
		config:     config,
	}, nil
}

// Start begins monitoring.
func (m *PNACLMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("already running")
	}

	// Attach eBPF programs to cgroup
	coll, detach, err := AttachConnectToCgroup(m.cgroupPath)
	if err != nil {
		return err
	}

	m.coll = coll
	m.detach = detach

	// Create connection holder
	holder, err := NewConnectionHolder(coll, m.filter, m.config.HolderConfig)
	if err != nil {
		detach()
		return err
	}

	m.holder = holder
	m.running = true

	// Start processing events
	holder.Start(ctx)

	return nil
}

// SetPolicyEngine updates the policy engine.
func (m *PNACLMonitor) SetPolicyEngine(engine *pnacl.PolicyEngine) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.engine = engine
	if m.filter != nil {
		m.filter.SetPolicyEngine(engine)
	}
}

// SetOnApprovalNeeded sets the approval callback.
func (m *PNACLMonitor) SetOnApprovalNeeded(fn func(*PendingConnection) pnacl.Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filter != nil {
		m.filter.SetOnApprovalNeeded(fn)
	}
}

// SetOnAudit sets the audit callback.
func (m *PNACLMonitor) SetOnAudit(fn func(*ConnectionEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filter != nil {
		m.filter.SetOnAudit(fn)
	}
}

// SetOnDeny sets the deny callback.
func (m *PNACLMonitor) SetOnDeny(fn func(*ConnectionEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filter != nil {
		m.filter.SetOnDeny(fn)
	}
}

// SetOnAllow sets the allow callback.
func (m *PNACLMonitor) SetOnAllow(fn func(*ConnectionEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filter != nil {
		m.filter.SetOnAllow(fn)
	}
}

// GetPendingConnections returns pending connections awaiting approval.
func (m *PNACLMonitor) GetPendingConnections() []*PendingConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.filter == nil {
		return nil
	}
	return m.filter.GetPendingConnections()
}

// ApproveConnection approves a pending connection.
func (m *PNACLMonitor) ApproveConnection(id uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.filter == nil {
		return false
	}
	return m.filter.ApproveConnection(id)
}

// DenyConnection denies a pending connection.
func (m *PNACLMonitor) DenyConnection(id uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.filter == nil {
		return false
	}
	return m.filter.DenyConnection(id)
}

// GetStats returns connection holder stats.
func (m *PNACLMonitor) GetStats() *ConnectionHolderStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.holder == nil {
		return nil
	}
	stats := m.holder.GetStats()
	return &stats
}

// Filter returns the process filter.
func (m *PNACLMonitor) Filter() *ProcessFilter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.filter
}

// Stop stops monitoring.
func (m *PNACLMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	if m.holder != nil {
		m.holder.Close()
		m.holder = nil
	}

	if m.detach != nil {
		m.detach()
		m.detach = nil
	}

	if m.coll != nil {
		m.coll.Close()
		m.coll = nil
	}

	return nil
}

// IsRunning returns whether the monitor is running.
func (m *PNACLMonitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}
