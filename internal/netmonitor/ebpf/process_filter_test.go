//go:build linux

package ebpf

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/pnacl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getTestProcessName returns the current test process name for matching
func getTestProcessName() string {
	// Get the actual process name from /proc
	commPath := filepath.Join("/proc", "self", "comm")
	if data, err := os.ReadFile(commPath); err == nil {
		return string(data[:len(data)-1]) // Remove trailing newline
	}
	return filepath.Base(os.Args[0])
}

func TestProcessFilter_NewProcessFilter(t *testing.T) {
	engine, err := pnacl.NewPolicyEngine(&pnacl.Config{
		Default: "deny",
	})
	require.NoError(t, err)

	filter := NewProcessFilter(engine)
	require.NotNil(t, filter)
	assert.NotNil(t, filter.pending)
	assert.NotNil(t, filter.allowOnceKeys)
	assert.NotNil(t, filter.dnsCache)
	assert.NotNil(t, filter.processCache)
}

func TestProcessFilter_ProcessEvent_NilEngine(t *testing.T) {
	filter := NewProcessFilter(nil)
	require.NotNil(t, filter)

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		TGID:     uint32(os.Getpid()),
		Protocol: 6, // TCP
		Family:   2, // AF_INET
		Dport:    80,
		DstIPv4:  0x08080808, // 8.8.8.8 in little-endian
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
}

func TestProcessFilter_ProcessEvent_Allow(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName, // Match current test process
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionAllow,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var allowCalled bool
	filter.SetOnAllow(func(ev *ConnectionEvent) {
		allowCalled = true
		assert.Equal(t, uint16(80), ev.DstPort)
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		TGID:     uint32(os.Getpid()),
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
	assert.True(t, allowCalled)
}

func TestProcessFilter_ProcessEvent_Deny(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "allow",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
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

	var denyCalled bool
	filter.SetOnDeny(func(ev *ConnectionEvent) {
		denyCalled = true
		assert.True(t, ev.Blocked)
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
	assert.True(t, denyCalled)
}

func TestProcessFilter_ProcessEvent_Audit(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionAudit,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var auditCalled bool
	filter.SetOnAudit(func(ev *ConnectionEvent) {
		auditCalled = true
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision) // Audit allows but logs
	assert.True(t, auditCalled)
}

func TestProcessFilter_ProcessEvent_AllowOnceThenApprove(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionAllowOnceThenApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// No approval handler - should deny on second attempt
	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   1,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	// First connection should be allowed
	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)

	// Second connection should require approval (but no handler, so denied)
	ev.Cookie = 2
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
}

func TestProcessFilter_ProcessEvent_Approve(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Set up approval handler that approves immediately
	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		return pnacl.DecisionAllow
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   123,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
}

func TestProcessFilter_ProcessEvent_ApproveTimeout(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Set up approval handler that blocks forever
	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		time.Sleep(10 * time.Second)
		return pnacl.DecisionAllow
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   456,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	filterConfig := &ProcessFilterConfig{
		ApprovalTimeout:  100 * time.Millisecond,
		DefaultOnTimeout: pnacl.DecisionDeny,
	}

	decision := filter.ProcessEvent(context.Background(), ev, filterConfig)
	assert.Equal(t, pnacl.DecisionDeny, decision)
}

func TestProcessFilter_ApproveAndDenyConnection(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Set up approval handler that waits for programmatic approval
	approvalChan := make(chan pnacl.Decision, 1)
	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		return <-approvalChan
	})

	// Test approve
	go func() {
		time.Sleep(50 * time.Millisecond)
		approvalChan <- pnacl.DecisionAllow
	}()

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   789,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)

	// Test deny
	go func() {
		time.Sleep(50 * time.Millisecond)
		approvalChan <- pnacl.DecisionDeny
	}()

	ev.Cookie = 790
	decision = filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
}

func TestProcessFilter_GetProcessInfo(t *testing.T) {
	filter := NewProcessFilter(nil)

	info := filter.getProcessInfo(uint32(os.Getpid()))
	require.NotNil(t, info)
	assert.Equal(t, os.Getpid(), info.PID)
	assert.NotEmpty(t, info.Name)

	// Should be cached
	info2 := filter.getProcessInfo(uint32(os.Getpid()))
	assert.Equal(t, info.Name, info2.Name)
}

func TestProcessFilter_DNSMapping(t *testing.T) {
	filter := NewProcessFilter(nil)

	ip := net.ParseIP("1.2.3.4")
	filter.AddDNSMapping("example.com", ip)

	host := filter.resolveHost(ip)
	assert.Equal(t, "example.com", host)
}

func TestProcessFilter_ClearCaches(t *testing.T) {
	filter := NewProcessFilter(nil)

	// Add some data
	filter.getProcessInfo(uint32(os.Getpid()))
	filter.AddDNSMapping("test.com", net.ParseIP("1.2.3.4"))

	// Clear and verify
	filter.ClearProcessCache()
	assert.Empty(t, filter.processCache)

	filter.ClearAllowOnceState()
	assert.Empty(t, filter.allowOnceKeys)
}

func TestProcessFilter_IPv6(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						CIDR:     "2001:db8::/32",
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
		Protocol: 6,
		Family:   10, // AF_INET6
		Dport:    443,
		DstIPv6:  [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
}

func TestParseParentPID(t *testing.T) {
	tests := []struct {
		name     string
		stat     string
		expected int
	}{
		{
			name:     "normal process",
			stat:     "1234 (bash) S 1233 1234 1234 0 -1 4194304",
			expected: 1233,
		},
		{
			name:     "process with parens in name",
			stat:     "5678 (test (prog)) S 5677 5678 5678 0 -1 4194304",
			expected: 5677,
		},
		{
			name:     "invalid format",
			stat:     "invalid",
			expected: 0,
		},
		{
			name:     "empty string",
			stat:     "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseParentPID(tt.stat)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessFilter_Close(t *testing.T) {
	filter := NewProcessFilter(nil)
	err := filter.Close()
	assert.NoError(t, err)

	// Double close should not panic
	err = filter.Close()
	assert.NoError(t, err)
}

func TestProcessFilter_ProcessEvent_UDP(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName, // Match current test process
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "53",
						Decision: pnacl.DecisionAllow,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var allowCalled bool
	filter.SetOnAllow(func(ev *ConnectionEvent) {
		allowCalled = true
		assert.Equal(t, uint16(53), ev.DstPort)
		assert.Equal(t, "udp", ev.Protocol)
	})

	// UDP event (protocol 17)
	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		TGID:     uint32(os.Getpid()),
		Protocol: 17, // UDP
		Family:   2,  // AF_INET
		Dport:    53,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
	assert.True(t, allowCalled)
}

func TestProcessFilter_ProcessEvent_UDP_Deny(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "allow",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "53",
						Decision: pnacl.DecisionDeny,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	var denyCalled bool
	filter.SetOnDeny(func(ev *ConnectionEvent) {
		denyCalled = true
		assert.Equal(t, "udp", ev.Protocol)
		assert.True(t, ev.Blocked)
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Protocol: 17, // UDP
		Family:   2,
		Dport:    53,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionDeny, decision)
	assert.True(t, denyCalled)
}

func TestProcessFilter_OnApprovalGranted(t *testing.T) {
	processName := getTestProcessName()
	config := &pnacl.Config{
		Default: "deny",
		Processes: []pnacl.ProcessConfig{
			{
				Name: "test-process",
				Match: pnacl.ProcessMatchCriteria{
					ProcessName: processName,
				},
				Rules: []pnacl.NetworkTarget{
					{
						IP:       "8.8.8.8",
						Port:     "80",
						Decision: pnacl.DecisionApprove,
					},
				},
			},
		},
	}

	engine, err := pnacl.NewPolicyEngine(config)
	require.NoError(t, err)

	filter := NewProcessFilter(engine)

	// Track approval granted callback
	var approvalGrantedCalled bool
	var approvalGrantedEvent *ConnectionEvent
	filter.SetOnApprovalGranted(func(ev *ConnectionEvent) {
		approvalGrantedCalled = true
		approvalGrantedEvent = ev
	})

	// Set up approval handler that approves immediately
	filter.SetOnApprovalNeeded(func(pc *PendingConnection) pnacl.Decision {
		return pnacl.DecisionAllow
	})

	ev := &ConnectEvent{
		PID:      uint32(os.Getpid()),
		Cookie:   123,
		Protocol: 6,
		Family:   2,
		Dport:    80,
		DstIPv4:  0x08080808,
	}

	decision := filter.ProcessEvent(context.Background(), ev, nil)
	assert.Equal(t, pnacl.DecisionAllow, decision)
	assert.True(t, approvalGrantedCalled, "onApprovalGranted should be called")
	assert.NotNil(t, approvalGrantedEvent)
	assert.Equal(t, uint16(80), approvalGrantedEvent.DstPort)
}
