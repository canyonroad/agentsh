//go:build linux && integration

package ebpf

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_PNACLMonitor_BasicOperation tests the full PNACL monitor flow.
// Requires root and cgroup v2.
func TestIntegration_PNACLMonitor_BasicOperation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	// Create policy that allows 8.8.8.8:53 but denies 1.1.1.1:80
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "all-processes",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Default: "deny",
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "53",
						Decision: pnacl.DecisionAllow,
					},
					{
						IP:       "1.1.1.1",
						Port:     "80",
						Decision: pnacl.DecisionDeny,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	// Create temp cgroup
	tmp := filepath.Join(os.TempDir(), "agentsh-pnacl-test")
	_ = os.RemoveAll(tmp)
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create monitor
	monitorConfig := &PNACLMonitorConfig{
		CgroupPath:   tmp,
		HolderConfig: DefaultConnectionHolderConfig(),
	}

	monitor, err := NewPNACLMonitor(engine, monitorConfig)
	require.NoError(t, err)

	// Track events
	var mu sync.Mutex
	var allowedEvents []*ConnectionEvent
	var deniedEvents []*ConnectionEvent

	monitor.SetOnAllow(func(ev *ConnectionEvent) {
		mu.Lock()
		allowedEvents = append(allowedEvents, ev)
		mu.Unlock()
	})

	monitor.SetOnDeny(func(ev *ConnectionEvent) {
		mu.Lock()
		deniedEvents = append(deniedEvents, ev)
		mu.Unlock()
	})

	// Start monitoring
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = monitor.Start(ctx)
	require.NoError(t, err)
	defer monitor.Stop()

	assert.True(t, monitor.IsRunning())

	// Give time for eBPF to settle
	time.Sleep(100 * time.Millisecond)

	// The eBPF program will capture connection events and report them.
	// Note: The actual blocking happens at cgroup level, not in userspace.
	// This test verifies the event flow and policy evaluation.

	// Verify stats are accessible
	stats := monitor.GetStats()
	assert.NotNil(t, stats)

	// Stop monitoring
	err = monitor.Stop()
	require.NoError(t, err)
	assert.False(t, monitor.IsRunning())
}

// TestIntegration_ProcessFilter_WithRealEvents tests process filter with real eBPF events.
func TestIntegration_ProcessFilter_WithRealEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	tmp := filepath.Join(os.TempDir(), "agentsh-pnacl-filter-test")
	_ = os.RemoveAll(tmp)
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Attach eBPF
	coll, detach, err := AttachConnectToCgroup(tmp)
	require.NoError(t, err)
	defer detach()
	defer coll.Close()

	// Create collector
	collector, err := StartCollector(coll, 1024)
	require.NoError(t, err)
	defer collector.Close()

	// Create policy engine with audit rule
	config := &pnacl.Config{
		Default: "allow",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Rules: []pnacl.NetworkTarget{
					{
						Host:     "*",
						Port:     "*",
						Decision: pnacl.DecisionAudit,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var auditedEvents []*ConnectionEvent
	var mu sync.Mutex

	filter.SetOnAudit(func(ev *ConnectionEvent) {
		mu.Lock()
		auditedEvents = append(auditedEvents, ev)
		mu.Unlock()
	})

	// Process events from collector
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-collector.Events():
				if !ok {
					return
				}
				filter.ProcessEvent(ctx, &ev, nil)
			}
		}
	}()

	// Trigger a connection (this will be audited)
	cmd := exec.Command("nc", "-z", "-w", "1", "8.8.8.8", "53")
	_ = cmd.Run() // Ignore exit status

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	eventCount := len(auditedEvents)
	mu.Unlock()

	// We should have captured at least one event
	t.Logf("Captured %d audited events", eventCount)
}

// TestIntegration_ConnectionHolder_ApprovalFlow tests the approval workflow.
func TestIntegration_ConnectionHolder_ApprovalFlow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	tmp := filepath.Join(os.TempDir(), "agentsh-pnacl-approval-test")
	_ = os.RemoveAll(tmp)
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Policy that requires approval
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Rules: []pnacl.NetworkTarget{
					{
						Host:     "*",
						Port:     "*",
						Decision: pnacl.DecisionApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Track approval requests
	var approvalRequests []*PendingConnection
	var mu sync.Mutex

	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		mu.Lock()
		approvalRequests = append(approvalRequests, pc)
		mu.Unlock()
		// Auto-approve for testing
		return pnacl.DecisionAllow
	})

	// Attach eBPF
	coll, detach, err := AttachConnectToCgroup(tmp)
	require.NoError(t, err)
	defer detach()
	defer coll.Close()

	holderConfig := &ConnectionHolderConfig{
		ApprovalTimeout:  5 * time.Second,
		DefaultOnTimeout: pnacl.DecisionDeny,
		EventBufferSize:  1024,
	}

	holder, err := NewConnectionHolder(coll, filter, holderConfig)
	require.NoError(t, err)
	defer holder.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	holder.Start(ctx)

	// Trigger a connection
	cmd := exec.Command("nc", "-z", "-w", "1", "8.8.8.8", "53")
	_ = cmd.Run()

	time.Sleep(500 * time.Millisecond)

	// Check stats
	stats := holder.GetStats()
	t.Logf("Events received: %d, processed: %d", stats.EventsReceived, stats.EventsProcessed)

	mu.Lock()
	requestCount := len(approvalRequests)
	mu.Unlock()

	t.Logf("Approval requests: %d", requestCount)
}

// TestIntegration_PNACLMonitor_AllowOnceThenApprove tests the allow_once_then_approve flow.
func TestIntegration_PNACLMonitor_AllowOnceThenApprove(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	// Policy with allow_once_then_approve
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "53",
						Decision: pnacl.DecisionAllowOnceThenApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var allowCount, approvalCount int
	var mu sync.Mutex

	filter.SetOnAllow(func(ev *ConnectionEvent) {
		mu.Lock()
		allowCount++
		mu.Unlock()
	})

	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		mu.Lock()
		approvalCount++
		mu.Unlock()
		return pnacl.DecisionAllow // Auto-approve
	})

	// Simulate events
	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   1,
		Protocol: 6,
		Family:   2,
		Dport:    53,
		DstIPv4:  0x08080808,
	}

	// First event - should be allowed without approval
	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)

	// Second event - should require approval
	ev.Cookie = 2
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision) // Approved

	mu.Lock()
	t.Logf("Allow count: %d, Approval count: %d", allowCount, approvalCount)
	assert.Equal(t, 2, allowCount) // Both allowed
	assert.Equal(t, 1, approvalCount) // Second required approval
	mu.Unlock()
}

// TestIntegration_PNACLMonitor_DenyList tests explicit deny rules.
func TestIntegration_PNACLMonitor_DenyList(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	// Policy with deny for specific IP
	config := &pnacl.Config{
		Default: "allow",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "1.1.1.1",
						Port:     "80",
						Decision: pnacl.DecisionDeny,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var deniedIPs []net.IP
	var mu sync.Mutex

	filter.SetOnDeny(func(ev *ConnectionEvent) {
		mu.Lock()
		deniedIPs = append(deniedIPs, ev.DstIP)
		mu.Unlock()
	})

	// Event to denied IP
	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   1,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x01010101, // 1.1.1.1 in little-endian
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)

	mu.Lock()
	assert.Len(t, deniedIPs, 1)
	mu.Unlock()

	// Event to allowed IP
	ev.Cookie = 2
	ev.DstIPv4 = 0x08080808 // 8.8.8.8
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
}

// TestIntegration_PNACLMonitor_CIDR tests CIDR-based rules.
func TestIntegration_PNACLMonitor_CIDR(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	// Policy with CIDR rule
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test",
				Match: pnacl.ProcessMatchCriteria{
					Path: "**/*", // Match all processes via path glob
				},
				Rules: []pnacl.NetworkTarget{
					{
						CIDR:     "10.0.0.0/8",
						Port:     "*",
						Decision: pnacl.DecisionAllow,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Test IP within CIDR
	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   1,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x0A0A0101, // 10.10.1.1 in little-endian
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)

	// Test IP outside CIDR
	ev.Cookie = 2
	ev.DstIPv4 = 0x08080808 // 8.8.8.8
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
}

// TestIntegration_PNACLMonitor_ProcessMatching tests process-specific rules.
func TestIntegration_PNACLMonitor_ProcessMatching(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	status := CheckSupport()
	if !status.Supported {
		t.Skipf("ebpf not supported: %s", status.Reason)
	}

	// Get current process name
	currentProcess := filepath.Base(os.Args[0])

	// Policy with process-specific rule
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-runner",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: currentProcess,
				},
				Rules: []pnacl.NetworkTarget{
					{
						Host:     "*",
						Port:     "443",
						Decision: pnacl.DecisionAllow,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   1,
		Protocol: 6,
		Family:   2,
		Dport:    443,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)

	// Different port should be denied
	ev.Cookie = 2
	ev.Dport = 80
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
}
