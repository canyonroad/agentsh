//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
)

// ProcessFilter implements system-wide process network filtering using eBPF.
// It intercepts connection events and evaluates them against PNACL policies.
type ProcessFilter struct {
	mu sync.RWMutex

	// Policy engine for evaluating decisions
	engine *pnacl.PolicyEngine

	// Pending connections awaiting approval
	pending map[uint64]*PendingConnection

	// Callbacks
	onApprovalNeeded func(*PendingConnection) pnacl.Decision
	onAudit          func(*ConnectionEvent)
	onDeny           func(*ConnectionEvent)
	onAllow          func(*ConnectionEvent)

	// Connection tracking
	allowOnceKeys map[string]bool // Tracks allow_once_then_approve state

	// DNS cache for reverse lookups
	dnsCache map[string]string
	dnsMu    sync.RWMutex

	// Process info cache
	processCache   map[uint32]*pnacl.ProcessInfo
	processCacheMu sync.RWMutex

	done chan struct{}
}

// PendingConnection represents a connection awaiting user approval.
type PendingConnection struct {
	ID        uint64
	Event     *ConnectionEvent
	Process   *pnacl.ProcessInfo
	Host      string
	IP        net.IP
	Port      int
	Protocol  string
	CreatedAt time.Time
	Decision  chan pnacl.Decision
}

// ConnectionEvent represents a network connection event.
type ConnectionEvent struct {
	Timestamp time.Time
	PID       uint32
	TGID      uint32
	Protocol  string
	Family    uint8
	SrcPort   uint16
	DstPort   uint16
	DstIP     net.IP
	Host      string
	Process   *pnacl.ProcessInfo
	Decision  pnacl.Decision
	Blocked   bool
}

// ProcessFilterConfig configures the process filter.
type ProcessFilterConfig struct {
	// ApprovalTimeout is how long to wait for user approval (default: 30s)
	ApprovalTimeout time.Duration
	// DefaultOnTimeout is the decision when approval times out (default: deny)
	DefaultOnTimeout pnacl.Decision
}

// NewProcessFilter creates a new process filter with the given policy engine.
func NewProcessFilter(engine *pnacl.PolicyEngine) *ProcessFilter {
	return &ProcessFilter{
		engine:        engine,
		pending:       make(map[uint64]*PendingConnection),
		allowOnceKeys: make(map[string]bool),
		dnsCache:      make(map[string]string),
		processCache:  make(map[uint32]*pnacl.ProcessInfo),
		done:          make(chan struct{}),
	}
}

// SetPolicyEngine updates the policy engine.
func (pf *ProcessFilter) SetPolicyEngine(engine *pnacl.PolicyEngine) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.engine = engine
}

// SetOnApprovalNeeded sets the callback for connections requiring approval.
// The callback should return the user's decision.
func (pf *ProcessFilter) SetOnApprovalNeeded(fn func(*PendingConnection) pnacl.Decision) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.onApprovalNeeded = fn
}

// SetOnAudit sets the callback for audit events.
func (pf *ProcessFilter) SetOnAudit(fn func(*ConnectionEvent)) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.onAudit = fn
}

// SetOnDeny sets the callback for denied connections.
func (pf *ProcessFilter) SetOnDeny(fn func(*ConnectionEvent)) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.onDeny = fn
}

// SetOnAllow sets the callback for allowed connections.
func (pf *ProcessFilter) SetOnAllow(fn func(*ConnectionEvent)) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.onAllow = fn
}

// ProcessEvent processes a connection event from eBPF and returns the decision.
func (pf *ProcessFilter) ProcessEvent(ctx context.Context, ev *ConnectEvent, config *ProcessFilterConfig) pnacl.Decision {
	if config == nil {
		config = &ProcessFilterConfig{
			ApprovalTimeout:  30 * time.Second,
			DefaultOnTimeout: pnacl.DecisionDeny,
		}
	}

	// Build connection event with process info
	connEv := pf.buildConnectionEvent(ev)

	// Evaluate policy
	pf.mu.RLock()
	engine := pf.engine
	pf.mu.RUnlock()

	if engine == nil {
		// No policy engine, allow by default
		connEv.Decision = pnacl.DecisionAllow
		pf.notifyAllow(connEv)
		return pnacl.DecisionAllow
	}

	result := engine.Evaluate(
		*connEv.Process,
		connEv.Host,
		connEv.DstIP,
		int(connEv.DstPort),
		connEv.Protocol,
	)

	connEv.Decision = result.Decision

	switch result.Decision {
	case pnacl.DecisionAllow:
		pf.notifyAllow(connEv)
		return pnacl.DecisionAllow

	case pnacl.DecisionDeny:
		connEv.Blocked = true
		pf.notifyDeny(connEv)
		return pnacl.DecisionDeny

	case pnacl.DecisionAudit:
		pf.notifyAudit(connEv)
		return pnacl.DecisionAllow

	case pnacl.DecisionAllowOnceThenApprove:
		key := pf.makeAllowOnceKey(connEv)
		pf.mu.Lock()
		seen := pf.allowOnceKeys[key]
		if !seen {
			pf.allowOnceKeys[key] = true
		}
		pf.mu.Unlock()

		if !seen {
			// First time - allow
			pf.notifyAllow(connEv)
			return pnacl.DecisionAllow
		}
		// Subsequent - fall through to approve
		fallthrough

	case pnacl.DecisionApprove:
		return pf.handleApprove(ctx, ev, connEv, config)
	}

	return pnacl.DecisionDeny
}

// handleApprove handles connections requiring user approval.
func (pf *ProcessFilter) handleApprove(ctx context.Context, ev *ConnectEvent, connEv *ConnectionEvent, config *ProcessFilterConfig) pnacl.Decision {
	pf.mu.RLock()
	approvalFn := pf.onApprovalNeeded
	pf.mu.RUnlock()

	if approvalFn == nil {
		// No approval handler, deny by default
		connEv.Blocked = true
		pf.notifyDeny(connEv)
		return pnacl.DecisionDeny
	}

	// Create pending connection
	pending := &PendingConnection{
		ID:        ev.Cookie,
		Event:     connEv,
		Process:   connEv.Process,
		Host:      connEv.Host,
		IP:        connEv.DstIP,
		Port:      int(connEv.DstPort),
		Protocol:  connEv.Protocol,
		CreatedAt: time.Now(),
		Decision:  make(chan pnacl.Decision, 1),
	}

	pf.mu.Lock()
	pf.pending[ev.Cookie] = pending
	pf.mu.Unlock()

	defer func() {
		pf.mu.Lock()
		delete(pf.pending, ev.Cookie)
		pf.mu.Unlock()
	}()

	// Request approval (this may block)
	approvalCtx, cancel := context.WithTimeout(ctx, config.ApprovalTimeout)
	defer cancel()

	// Run approval in goroutine to handle timeout
	go func() {
		decision := approvalFn(pending)
		select {
		case pending.Decision <- decision:
		default:
		}
	}()

	select {
	case decision := <-pending.Decision:
		connEv.Decision = decision
		switch decision {
		case pnacl.DecisionAllow:
			pf.notifyAllow(connEv)
			return pnacl.DecisionAllow
		default:
			connEv.Blocked = true
			pf.notifyDeny(connEv)
			return pnacl.DecisionDeny
		}
	case <-approvalCtx.Done():
		connEv.Decision = config.DefaultOnTimeout
		connEv.Blocked = config.DefaultOnTimeout != pnacl.DecisionAllow
		if connEv.Blocked {
			pf.notifyDeny(connEv)
		} else {
			pf.notifyAllow(connEv)
		}
		return config.DefaultOnTimeout
	case <-pf.done:
		connEv.Blocked = true
		pf.notifyDeny(connEv)
		return pnacl.DecisionDeny
	}
}

// buildConnectionEvent creates a ConnectionEvent from a raw eBPF event.
func (pf *ProcessFilter) buildConnectionEvent(ev *ConnectEvent) *ConnectionEvent {
	connEv := &ConnectionEvent{
		Timestamp: time.Now(),
		PID:       ev.PID,
		TGID:      ev.TGID,
		Family:    ev.Family,
		SrcPort:   ev.Sport,
		DstPort:   ev.Dport,
		Blocked:   ev.Blocked == 1,
	}

	// Set protocol
	if ev.Protocol == 6 {
		connEv.Protocol = "tcp"
	} else if ev.Protocol == 17 {
		connEv.Protocol = "udp"
	} else {
		connEv.Protocol = fmt.Sprintf("%d", ev.Protocol)
	}

	// Parse destination IP
	if ev.Family == 2 { // AF_INET
		connEv.DstIP = make(net.IP, 4)
		connEv.DstIP[0] = byte(ev.DstIPv4)
		connEv.DstIP[1] = byte(ev.DstIPv4 >> 8)
		connEv.DstIP[2] = byte(ev.DstIPv4 >> 16)
		connEv.DstIP[3] = byte(ev.DstIPv4 >> 24)
	} else if ev.Family == 10 { // AF_INET6
		connEv.DstIP = make(net.IP, 16)
		copy(connEv.DstIP, ev.DstIPv6[:])
	}

	// Resolve hostname
	connEv.Host = pf.resolveHost(connEv.DstIP)

	// Get process info
	connEv.Process = pf.getProcessInfo(ev.PID)

	return connEv
}

// getProcessInfo retrieves process information for a PID.
func (pf *ProcessFilter) getProcessInfo(pid uint32) *pnacl.ProcessInfo {
	pf.processCacheMu.RLock()
	if info, ok := pf.processCache[pid]; ok {
		pf.processCacheMu.RUnlock()
		return info
	}
	pf.processCacheMu.RUnlock()

	info := &pnacl.ProcessInfo{
		PID: int(pid),
	}

	// Read process name from /proc/<pid>/comm
	commPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "comm")
	if data, err := os.ReadFile(commPath); err == nil {
		info.Name = strings.TrimSpace(string(data))
	}

	// Read process path from /proc/<pid>/exe
	exePath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe")
	if target, err := os.Readlink(exePath); err == nil {
		info.Path = target
	}

	// Read parent PID from /proc/<pid>/stat
	statPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat")
	if data, err := os.ReadFile(statPath); err == nil {
		info.ParentPID = parseParentPID(string(data))
	}

	// Cache the result
	pf.processCacheMu.Lock()
	pf.processCache[pid] = info
	pf.processCacheMu.Unlock()

	return info
}

// parseParentPID extracts the parent PID from /proc/<pid>/stat content.
func parseParentPID(stat string) int {
	// Format: pid (comm) state ppid ...
	// Need to find the closing ) of comm first
	idx := strings.LastIndex(stat, ")")
	if idx < 0 || idx+2 >= len(stat) {
		return 0
	}

	fields := strings.Fields(stat[idx+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// resolveHost attempts to resolve an IP to a hostname.
func (pf *ProcessFilter) resolveHost(ip net.IP) string {
	if ip == nil {
		return ""
	}

	ipStr := ip.String()

	pf.dnsMu.RLock()
	if host, ok := pf.dnsCache[ipStr]; ok {
		pf.dnsMu.RUnlock()
		return host
	}
	pf.dnsMu.RUnlock()

	// Try reverse DNS lookup (with timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var host string
	done := make(chan struct{})
	go func() {
		names, err := net.LookupAddr(ipStr)
		if err == nil && len(names) > 0 {
			host = strings.TrimSuffix(names[0], ".")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		host = ipStr
	}

	if host == "" {
		host = ipStr
	}

	// Cache result
	pf.dnsMu.Lock()
	pf.dnsCache[ipStr] = host
	pf.dnsMu.Unlock()

	return host
}

// makeAllowOnceKey creates a unique key for allow_once_then_approve tracking.
func (pf *ProcessFilter) makeAllowOnceKey(ev *ConnectionEvent) string {
	return fmt.Sprintf("%s:%d:%s:%d",
		ev.Process.Path,
		ev.DstPort,
		ev.DstIP.String(),
		ev.Family,
	)
}

// AddDNSMapping adds a DNS name to IP mapping for reverse lookups.
func (pf *ProcessFilter) AddDNSMapping(name string, ip net.IP) {
	pf.dnsMu.Lock()
	defer pf.dnsMu.Unlock()
	pf.dnsCache[ip.String()] = name
}

// ClearProcessCache clears the process info cache.
func (pf *ProcessFilter) ClearProcessCache() {
	pf.processCacheMu.Lock()
	defer pf.processCacheMu.Unlock()
	pf.processCache = make(map[uint32]*pnacl.ProcessInfo)
}

// ClearAllowOnceState clears the allow_once_then_approve tracking state.
func (pf *ProcessFilter) ClearAllowOnceState() {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.allowOnceKeys = make(map[string]bool)
}

// GetPendingConnections returns a snapshot of pending connections.
func (pf *ProcessFilter) GetPendingConnections() []*PendingConnection {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	result := make([]*PendingConnection, 0, len(pf.pending))
	for _, p := range pf.pending {
		result = append(result, p)
	}
	return result
}

// ApproveConnection approves a pending connection by ID.
func (pf *ProcessFilter) ApproveConnection(id uint64) bool {
	pf.mu.RLock()
	pending, ok := pf.pending[id]
	pf.mu.RUnlock()

	if !ok {
		return false
	}

	select {
	case pending.Decision <- pnacl.DecisionAllow:
		return true
	default:
		return false
	}
}

// DenyConnection denies a pending connection by ID.
func (pf *ProcessFilter) DenyConnection(id uint64) bool {
	pf.mu.RLock()
	pending, ok := pf.pending[id]
	pf.mu.RUnlock()

	if !ok {
		return false
	}

	select {
	case pending.Decision <- pnacl.DecisionDeny:
		return true
	default:
		return false
	}
}

func (pf *ProcessFilter) notifyAllow(ev *ConnectionEvent) {
	pf.mu.RLock()
	fn := pf.onAllow
	pf.mu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

func (pf *ProcessFilter) notifyDeny(ev *ConnectionEvent) {
	pf.mu.RLock()
	fn := pf.onDeny
	pf.mu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

func (pf *ProcessFilter) notifyAudit(ev *ConnectionEvent) {
	pf.mu.RLock()
	fn := pf.onAudit
	pf.mu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// Close stops the process filter.
func (pf *ProcessFilter) Close() error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	select {
	case <-pf.done:
		// Already closed
		return nil
	default:
		close(pf.done)
	}
	return nil
}
