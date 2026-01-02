# Windows WinDivert Network Interception Implementation Plan

> **Status:** ✅ **COMPLETED** (2026-01-01) - All 9 tasks implemented and merged in PR #48

**Goal:** Implement transparent network interception on Windows using WinDivert, matching Linux's iptables+proxy behavior.

**Architecture:** WinDivert captures outbound TCP/DNS packets from session processes, rewrites destinations to local proxy, proxy looks up original destination from NAT table and connects on behalf of the app.

**Tech Stack:** Go, github.com/williamfhe/godivert, WinDivert 2.2.x, existing mini filter driver for PID tracking

**Design Document:** `docs/plans/2026-01-02-windows-windivert-design.md`

---

## Task 1: Add godivert dependency

**Files:**
- Modify: `go.mod`

**Step 1: Add the godivert dependency**

Run:
```bash
cd /home/eran/work/agentsh/.worktrees/feature-windivert
go get github.com/williamfhe/godivert@latest
```

**Step 2: Verify dependency added**

Run: `grep godivert go.mod`
Expected: `github.com/williamfhe/godivert v0.x.x`

**Step 3: Tidy modules**

Run: `go mod tidy`

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add godivert dependency for WinDivert integration"
```

---

## Task 2: Implement NAT table (pure Go, no Windows deps)

**Files:**
- Create: `internal/platform/windows/nat_table.go`
- Create: `internal/platform/windows/nat_table_test.go`

**Step 1: Write the failing tests**

```go
// internal/platform/windows/nat_table_test.go
package windows

import (
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
			table.Insert("127.0.0.1:"+string(rune(i)), &NATEntry{ProcessID: uint32(i)})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			table.Lookup("127.0.0.1:" + string(rune(i)))
		}
		done <- true
	}()

	<-done
	<-done
	// Test passes if no race detector errors
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/windows/... -run TestNATTable -v`
Expected: FAIL (types not defined)

**Step 3: Write the implementation**

```go
// internal/platform/windows/nat_table.go
package windows

import (
	"net"
	"sync"
	"time"
)

// NATEntry tracks a redirected connection's original destination.
type NATEntry struct {
	OriginalDstIP   net.IP
	OriginalDstPort uint16
	Protocol        string // "tcp" or "udp"
	ProcessID       uint32
	CreatedAt       time.Time
}

// NATTable maps local proxy connections to original destinations.
// Key format: "srcIP:srcPort" (the redirected connection's local source)
type NATTable struct {
	mu      sync.RWMutex
	entries map[string]*NATEntry
	ttl     time.Duration
}

// NewNATTable creates a new NAT table with the given TTL for entries.
func NewNATTable(ttl time.Duration) *NATTable {
	return &NATTable{
		entries: make(map[string]*NATEntry),
		ttl:     ttl,
	}
}

// Insert adds or updates a NAT entry.
func (t *NATTable) Insert(key string, entry *NATEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	t.entries[key] = entry
}

// Lookup retrieves a NAT entry by key.
// Returns nil if not found or expired.
func (t *NATTable) Lookup(key string) *NATEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.entries[key]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Since(entry.CreatedAt) > t.ttl {
		return nil
	}

	return entry
}

// Remove deletes a NAT entry.
func (t *NATTable) Remove(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// RemoveByPID removes all entries for a given process ID.
// Returns the number of entries removed.
func (t *NATTable) RemoveByPID(pid uint32) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for key, entry := range t.entries {
		if entry.ProcessID == pid {
			delete(t.entries, key)
			removed++
		}
	}
	return removed
}

// Cleanup removes all expired entries.
func (t *NATTable) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for key, entry := range t.entries {
		if now.Sub(entry.CreatedAt) > t.ttl {
			delete(t.entries, key)
		}
	}
}

// Len returns the number of entries in the table.
func (t *NATTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/windows/... -run TestNATTable -v`
Expected: PASS

**Step 5: Run with race detector**

Run: `go test ./internal/platform/windows/... -run TestNATTable -race`
Expected: PASS (no race conditions)

**Step 6: Commit**

```bash
git add internal/platform/windows/nat_table.go internal/platform/windows/nat_table_test.go
git commit -m "feat(windows): add NAT table for WinDivert connection tracking"
```

---

## Task 3: Create WinDivert stub for cross-compilation

**Files:**
- Create: `internal/platform/windows/windivert_stub.go`

**Step 1: Create the stub file**

```go
// internal/platform/windows/windivert_stub.go
//go:build !windows

package windows

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// WinDivertHandle is a stub for non-Windows platforms.
type WinDivertHandle struct{}

// NewWinDivertHandle returns an error on non-Windows platforms.
func NewWinDivertHandle(natTable *NATTable, config platform.NetConfig, driver *DriverClient) (*WinDivertHandle, error) {
	return nil, fmt.Errorf("WinDivert is only available on Windows")
}

// Start is a no-op stub.
func (w *WinDivertHandle) Start() error {
	return fmt.Errorf("WinDivert is only available on Windows")
}

// Stop is a no-op stub.
func (w *WinDivertHandle) Stop() error {
	return nil
}

// AddSessionPID is a no-op stub.
func (w *WinDivertHandle) AddSessionPID(pid uint32) {}

// RemoveSessionPID is a no-op stub.
func (w *WinDivertHandle) RemoveSessionPID(pid uint32) {}

// IsSessionPID is a no-op stub.
func (w *WinDivertHandle) IsSessionPID(pid uint32) bool {
	return false
}
```

**Step 2: Verify it compiles on Linux**

Run: `go build ./internal/platform/windows/...`
Expected: Success

**Step 3: Commit**

```bash
git add internal/platform/windows/windivert_stub.go
git commit -m "feat(windows): add WinDivert stub for cross-compilation"
```

---

## Task 4: Implement WinDivert handle (Windows-only)

**Files:**
- Create: `internal/platform/windows/windivert_windows.go`

**Step 1: Create the Windows implementation**

```go
// internal/platform/windows/windivert_windows.go
//go:build windows

package windows

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/williamfhe/godivert"
)

// FailMode controls behavior when WinDivert encounters errors.
type FailMode int

const (
	FailModeOpen   FailMode = 0 // Allow traffic through on failure
	FailModeClosed FailMode = 1 // Block traffic on failure
)

// WinDivertHandle wraps godivert with session-aware filtering.
type WinDivertHandle struct {
	handle    *godivert.WinDivertHandle
	natTable  *NATTable
	proxyPort uint16
	dnsPort   uint16

	// Session PID tracking
	sessionPIDs map[uint32]bool
	pidMu       sync.RWMutex

	// Driver client for process events
	driver *DriverClient

	// Fail mode
	failMode            FailMode
	consecutiveFailures int32
	maxFailures         int32
	inFailMode          int32 // atomic bool

	// Lifecycle
	stopChan chan struct{}
	wg       sync.WaitGroup
	running  int32 // atomic bool
}

// NewWinDivertHandle creates a new WinDivert handle.
func NewWinDivertHandle(natTable *NATTable, config platform.NetConfig, driver *DriverClient) (*WinDivertHandle, error) {
	proxyPort := uint16(config.ProxyPort)
	if proxyPort == 0 {
		proxyPort = 9080
	}
	dnsPort := uint16(config.DNSPort)
	if dnsPort == 0 {
		dnsPort = 5353
	}

	return &WinDivertHandle{
		natTable:    natTable,
		proxyPort:   proxyPort,
		dnsPort:     dnsPort,
		sessionPIDs: make(map[uint32]bool),
		driver:      driver,
		failMode:    FailModeOpen,
		maxFailures: 10,
		stopChan:    make(chan struct{}),
	}, nil
}

// baseFilter returns the WinDivert filter string.
// We capture all outbound TCP and DNS, then filter by PID in user-mode.
func (w *WinDivertHandle) baseFilter() string {
	return "outbound and (tcp or (udp and udp.DstPort == 53))"
}

// Start begins packet capture and redirection.
func (w *WinDivertHandle) Start() error {
	if !atomic.CompareAndSwapInt32(&w.running, 0, 1) {
		return fmt.Errorf("WinDivert already running")
	}

	var err error
	w.handle, err = godivert.NewWinDivertHandle(w.baseFilter())
	if err != nil {
		atomic.StoreInt32(&w.running, 0)
		return fmt.Errorf("failed to open WinDivert handle: %w", err)
	}

	w.stopChan = make(chan struct{})
	w.wg.Add(1)
	go w.captureLoop()

	return nil
}

// Stop halts packet capture.
func (w *WinDivertHandle) Stop() error {
	if !atomic.CompareAndSwapInt32(&w.running, 1, 0) {
		return nil // Already stopped
	}

	close(w.stopChan)
	w.wg.Wait()

	if w.handle != nil {
		return w.handle.Close()
	}
	return nil
}

// AddSessionPID adds a process ID to the session filter.
func (w *WinDivertHandle) AddSessionPID(pid uint32) {
	w.pidMu.Lock()
	defer w.pidMu.Unlock()
	w.sessionPIDs[pid] = true
}

// RemoveSessionPID removes a process ID from the session filter.
func (w *WinDivertHandle) RemoveSessionPID(pid uint32) {
	w.pidMu.Lock()
	defer w.pidMu.Unlock()
	delete(w.sessionPIDs, pid)

	// Also cleanup NAT entries for this PID
	w.natTable.RemoveByPID(pid)
}

// IsSessionPID checks if a PID belongs to a session.
func (w *WinDivertHandle) IsSessionPID(pid uint32) bool {
	w.pidMu.RLock()
	defer w.pidMu.RUnlock()
	return w.sessionPIDs[pid]
}

// captureLoop is the main packet capture goroutine.
func (w *WinDivertHandle) captureLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopChan:
			return
		default:
			packet, err := w.handle.Recv()
			if err != nil {
				w.handleError(err)
				continue
			}
			w.processPacket(packet)
		}
	}
}

// processPacket handles a captured packet.
func (w *WinDivertHandle) processPacket(packet *godivert.Packet) {
	// Check fail mode
	if atomic.LoadInt32(&w.inFailMode) == 1 {
		if w.failMode == FailModeOpen {
			// Let traffic through unmodified
			w.handle.Send(packet)
		}
		// FailModeClosed: drop packet (don't reinject)
		return
	}

	// Get process ID
	pid := packet.Addr.ProcessId

	// Fast path: check if PID belongs to a session
	if !w.IsSessionPID(pid) {
		// Not a session process - reinject unchanged
		w.handle.Send(packet)
		return
	}

	// Session process - apply redirection
	w.redirectPacket(packet)
}

// redirectPacket modifies packet destination to proxy.
func (w *WinDivertHandle) redirectPacket(packet *godivert.Packet) {
	srcIP := packet.SrcIP()
	srcPort := packet.SrcPort()
	dstIP := packet.DstIP()
	dstPort := packet.DstPort()

	key := fmt.Sprintf("%s:%d", srcIP, srcPort)

	// Check if this is a TCP packet
	if packet.NextHeader == 6 { // TCP
		// Check if SYN flag (new connection)
		tcpHeader := packet.Raw[packet.PacketLen-int(packet.PayloadLen):]
		flags := tcpHeader[13]
		isSyn := (flags & 0x02) != 0

		if isSyn {
			// Store original destination in NAT table
			entry := &NATEntry{
				OriginalDstIP:   net.ParseIP(dstIP.String()),
				OriginalDstPort: dstPort,
				Protocol:        "tcp",
				ProcessID:       packet.Addr.ProcessId,
			}
			w.natTable.Insert(key, entry)
		}

		// Rewrite destination to proxy
		packet.SetDstIP(net.ParseIP("127.0.0.1"))
		packet.SetDstPort(w.proxyPort)

	} else if packet.NextHeader == 17 && dstPort == 53 { // UDP DNS
		// Store original destination in NAT table
		entry := &NATEntry{
			OriginalDstIP:   net.ParseIP(dstIP.String()),
			OriginalDstPort: dstPort,
			Protocol:        "udp",
			ProcessID:       packet.Addr.ProcessId,
		}
		w.natTable.Insert(key, entry)

		// Rewrite destination to DNS proxy
		packet.SetDstIP(net.ParseIP("127.0.0.1"))
		packet.SetDstPort(w.dnsPort)
	}

	// Recalculate checksums and reinject
	packet.CalcNewChecksum(w.handle)
	w.handle.Send(packet)
}

// handleError handles packet capture errors.
func (w *WinDivertHandle) handleError(err error) {
	failures := atomic.AddInt32(&w.consecutiveFailures, 1)
	if failures >= w.maxFailures && atomic.LoadInt32(&w.inFailMode) == 0 {
		atomic.StoreInt32(&w.inFailMode, 1)
	}
}

// resetFailMode resets the fail mode after successful operations.
func (w *WinDivertHandle) resetFailMode() {
	atomic.StoreInt32(&w.consecutiveFailures, 0)
	atomic.StoreInt32(&w.inFailMode, 0)
}
```

**Step 2: Verify it compiles (cross-compile check)**

Run: `GOOS=windows GOARCH=amd64 go build ./internal/platform/windows/...`
Expected: Success (or specific WinDivert DLL errors which are expected without the actual DLL)

**Step 3: Commit**

```bash
git add internal/platform/windows/windivert_windows.go
git commit -m "feat(windows): implement WinDivert packet capture and redirection"
```

---

## Task 5: Integrate WinDivert into Network struct

**Files:**
- Modify: `internal/platform/windows/network.go`

**Step 1: Read the existing network.go**

Review: `internal/platform/windows/network.go` (already has stubs)

**Step 2: Update Network struct to use WinDivert**

Add to Network struct:
```go
// Add these fields to the Network struct
windivert    *WinDivertHandle
natTable     *NATTable
driverClient *DriverClient
```

**Step 3: Update setupWinDivert method**

Replace the stub `setupWinDivert()` with:
```go
// setupWinDivert configures WinDivert for packet capture and redirection.
func (n *Network) setupWinDivert() error {
	n.natTable = NewNATTable(5 * time.Minute)

	var err error
	n.windivert, err = NewWinDivertHandle(n.natTable, n.config, n.driverClient)
	if err != nil {
		return fmt.Errorf("failed to create WinDivert handle: %w", err)
	}

	// Start cleanup goroutine for NAT table
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-n.stopChan:
				return
			case <-ticker.C:
				n.natTable.Cleanup()
			}
		}
	}()

	return n.windivert.Start()
}
```

**Step 4: Update Teardown to stop WinDivert**

Update `Teardown()` to call `n.windivert.Stop()`.

**Step 5: Add NAT table getter for proxy**

```go
// NATTable returns the NAT table for proxy lookup.
func (n *Network) NATTable() *NATTable {
	return n.natTable
}
```

**Step 6: Verify it compiles**

Run: `GOOS=windows GOARCH=amd64 go build ./internal/platform/windows/...`
Expected: Success

**Step 7: Commit**

```bash
git add internal/platform/windows/network.go
git commit -m "feat(windows): integrate WinDivert into Network struct"
```

---

## Task 6: Add process event subscription

**Files:**
- Modify: `internal/platform/windows/driver_client.go`
- Modify: `internal/platform/windows/windivert_windows.go`

**Step 1: Add callback fields to DriverClient**

Check if `driver_client.go` already has process event callbacks. If not, add:
```go
// Process event callbacks
OnProcessCreated func(sessionToken uint64, pid uint32)
OnProcessExited  func(sessionToken uint64, pid uint32)
```

**Step 2: Update WinDivert to subscribe to process events**

Add method to WinDivert:
```go
// SubscribeToProcessEvents registers callbacks with the driver client.
func (w *WinDivertHandle) SubscribeToProcessEvents() {
	if w.driver == nil {
		return
	}

	w.driver.OnProcessCreated = func(sessionToken uint64, pid uint32) {
		w.AddSessionPID(pid)
	}

	w.driver.OnProcessExited = func(sessionToken uint64, pid uint32) {
		w.RemoveSessionPID(pid)
	}
}
```

**Step 3: Call subscription in Start()**

Add `w.SubscribeToProcessEvents()` at the beginning of `Start()`.

**Step 4: Commit**

```bash
git add internal/platform/windows/driver_client.go internal/platform/windows/windivert_windows.go
git commit -m "feat(windows): add process event subscription for PID tracking"
```

---

## Task 7: Add WinDivert unit tests (Windows-only)

**Files:**
- Create: `internal/platform/windows/windivert_test.go`

**Step 1: Write tests**

```go
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

	handle, err := NewWinDivertHandle(natTable, config, nil)
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

	handle, _ := NewWinDivertHandle(natTable, config, nil)

	filter := handle.baseFilter()
	expected := "outbound and (tcp or (udp and udp.DstPort == 53))"
	if filter != expected {
		t.Errorf("baseFilter() = %q, want %q", filter, expected)
	}
}
```

**Step 2: Commit**

```bash
git add internal/platform/windows/windivert_test.go
git commit -m "test(windows): add WinDivert unit tests"
```

---

## Task 8: Update documentation

**Files:**
- Modify: `docs/cross-platform.md`
- Modify: `docs/platform-comparison.md`

**Step 1: Update cross-platform.md**

Add WinDivert to the Windows Native section:
```markdown
**Network Interception:**
- WinDivert for transparent TCP/DNS proxy (requires Administrator)
- Falls back to WFP for block-only mode if WinDivert unavailable
```

**Step 2: Update platform-comparison.md**

Change Windows Native network implementation from "WinDivert" (planned) to "WinDivert" (implemented).
Update the score if appropriate.

**Step 3: Commit**

```bash
git add docs/cross-platform.md docs/platform-comparison.md
git commit -m "docs: update Windows documentation for WinDivert implementation"
```

---

## Task 9: Run full test suite and verify

**Step 1: Run all tests**

Run: `go test ./... -race`
Expected: All tests pass

**Step 2: Cross-compile check**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: Success

**Step 3: Build for Linux**

Run: `go build ./...`
Expected: Success (stubs used)

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Add godivert dependency | go.mod |
| 2 | Implement NAT table | nat_table.go, nat_table_test.go |
| 3 | Create WinDivert stub | windivert_stub.go |
| 4 | Implement WinDivert handle | windivert_windows.go |
| 5 | Integrate into Network struct | network.go |
| 6 | Add process event subscription | driver_client.go, windivert_windows.go |
| 7 | Add WinDivert tests | windivert_test.go |
| 8 | Update documentation | cross-platform.md, platform-comparison.md |
| 9 | Final verification | - |
