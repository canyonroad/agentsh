package windows

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNATTable_InsertAndLookup(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	entry := &NATEntry{
		OriginalDstIP:   net.ParseIP("140.82.114.4"),
		OriginalDstPort: 443,
		Protocol:        "tcp",
		ProcessID:       1234,
		CreatedAt:       time.Now(),
	}

	table.Insert("127.0.0.1:54321", entry)

	got := table.Lookup("127.0.0.1:54321")
	if got == nil {
		t.Fatal("expected entry, got nil")
	}
	if !got.OriginalDstIP.Equal(entry.OriginalDstIP) {
		t.Errorf("OriginalDstIP = %v, want %v", got.OriginalDstIP, entry.OriginalDstIP)
	}
	if got.OriginalDstPort != 443 {
		t.Errorf("OriginalDstPort = %d, want 443", got.OriginalDstPort)
	}
}

func TestNATTable_LookupMissing(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	got := table.Lookup("127.0.0.1:99999")
	if got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestNATTable_RemoveByPID(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	table.Insert("127.0.0.1:1001", &NATEntry{ProcessID: 100, OriginalDstPort: 80})
	table.Insert("127.0.0.1:1002", &NATEntry{ProcessID: 100, OriginalDstPort: 443})
	table.Insert("127.0.0.1:1003", &NATEntry{ProcessID: 200, OriginalDstPort: 80})

	removed := table.RemoveByPID(100)
	if removed != 2 {
		t.Errorf("RemoveByPID returned %d, want 2", removed)
	}

	if table.Lookup("127.0.0.1:1001") != nil {
		t.Error("entry for PID 100 should be removed")
	}
	if table.Lookup("127.0.0.1:1003") == nil {
		t.Error("entry for PID 200 should still exist")
	}
}

func TestNATTable_TTLExpiry(t *testing.T) {
	table := NewNATTable(50 * time.Millisecond)

	table.Insert("127.0.0.1:1001", &NATEntry{ProcessID: 100, OriginalDstPort: 80})

	// Should exist immediately
	if table.Lookup("127.0.0.1:1001") == nil {
		t.Fatal("entry should exist immediately after insert")
	}

	// Wait for TTL
	time.Sleep(100 * time.Millisecond)

	// Run cleanup
	table.Cleanup()

	// Should be gone
	if table.Lookup("127.0.0.1:1001") != nil {
		t.Error("entry should be expired after TTL")
	}
}

func TestNATTable_ConcurrentAccess(t *testing.T) {
	table := NewNATTable(5 * time.Minute)
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			table.Insert(fmt.Sprintf("127.0.0.1:%d", i), &NATEntry{ProcessID: uint32(i)})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			table.Lookup(fmt.Sprintf("127.0.0.1:%d", i))
		}
		done <- true
	}()

	<-done
	<-done
	// Test passes if no race detector errors
}
