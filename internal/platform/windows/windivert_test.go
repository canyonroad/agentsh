// internal/platform/windows/windivert_test.go
//go:build windows

package windows

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestWinDivertHandle_SessionPIDs(t *testing.T) {
	natTable := NewNATTable(5 * time.Minute)
	config := platform.NetConfig{
		ProxyPort: 9080,
		DNSPort:   5353,
	}

	handle, err := NewWinDivertHandle(natTable, config, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWinDivertHandle failed: %v", err)
	}

	// Initially no PIDs
	if handle.IsSessionPID(1234) {
		t.Error("PID 1234 should not be in session initially")
	}

	// Add PID
	handle.AddSessionPID(1234)
	if !handle.IsSessionPID(1234) {
		t.Error("PID 1234 should be in session after add")
	}

	// Remove PID
	handle.RemoveSessionPID(1234)
	if handle.IsSessionPID(1234) {
		t.Error("PID 1234 should not be in session after remove")
	}
}

func TestWinDivertHandle_BaseFilter(t *testing.T) {
	natTable := NewNATTable(5 * time.Minute)
	config := platform.NetConfig{
		ProxyPort: 9080,
		DNSPort:   5353,
	}

	handle, _ := NewWinDivertHandle(natTable, config, nil, nil, nil)

	filter := handle.baseFilter()
	expected := "outbound and (tcp or (udp and udp.DstPort == 53))"
	if filter != expected {
		t.Errorf("baseFilter() = %q, want %q", filter, expected)
	}
}

func TestWinDivertHandle_DefaultPorts(t *testing.T) {
	natTable := NewNATTable(5 * time.Minute)

	// Test with zero ports (should use defaults)
	config := platform.NetConfig{
		ProxyPort: 0,
		DNSPort:   0,
	}

	handle, err := NewWinDivertHandle(natTable, config, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWinDivertHandle failed: %v", err)
	}

	if handle.proxyPort != 9080 {
		t.Errorf("default proxyPort = %d, want 9080", handle.proxyPort)
	}
	if handle.dnsPort != 5353 {
		t.Errorf("default dnsPort = %d, want 5353", handle.dnsPort)
	}
}

func TestWinDivertHandle_RemovePIDCleansNAT(t *testing.T) {
	natTable := NewNATTable(5 * time.Minute)
	config := platform.NetConfig{
		ProxyPort: 9080,
		DNSPort:   5353,
	}

	handle, _ := NewWinDivertHandle(natTable, config, nil, nil, nil)

	// Add NAT entries for PID 1234
	natTable.Insert("127.0.0.1:5000", &NATEntry{ProcessID: 1234, OriginalDstPort: 80})
	natTable.Insert("127.0.0.1:5001", &NATEntry{ProcessID: 1234, OriginalDstPort: 443})
	natTable.Insert("127.0.0.1:5002", &NATEntry{ProcessID: 5678, OriginalDstPort: 80})

	// Add and remove PID
	handle.AddSessionPID(1234)
	handle.RemoveSessionPID(1234)

	// NAT entries for PID 1234 should be cleaned up
	if natTable.Lookup("127.0.0.1:5000") != nil {
		t.Error("NAT entry for PID 1234 should be removed")
	}
	if natTable.Lookup("127.0.0.1:5001") != nil {
		t.Error("NAT entry for PID 1234 should be removed")
	}
	// Entry for other PID should remain
	if natTable.Lookup("127.0.0.1:5002") == nil {
		t.Error("NAT entry for PID 5678 should still exist")
	}
}

func TestWinDivertHandle_ConcurrentPIDAccess(t *testing.T) {
	natTable := NewNATTable(5 * time.Minute)
	config := platform.NetConfig{
		ProxyPort: 9080,
		DNSPort:   5353,
	}

	handle, err := NewWinDivertHandle(natTable, config, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWinDivertHandle failed: %v", err)
	}

	done := make(chan bool)

	// Writer goroutine - adds PIDs
	go func() {
		for i := uint32(0); i < 1000; i++ {
			handle.AddSessionPID(i)
		}
		done <- true
	}()

	// Reader goroutine - checks PIDs
	go func() {
		for i := uint32(0); i < 1000; i++ {
			handle.IsSessionPID(i)
		}
		done <- true
	}()

	// Remover goroutine - removes PIDs
	go func() {
		for i := uint32(0); i < 1000; i++ {
			handle.RemoveSessionPID(i)
		}
		done <- true
	}()

	<-done
	<-done
	<-done
	// Test passes if no race detector errors
}
