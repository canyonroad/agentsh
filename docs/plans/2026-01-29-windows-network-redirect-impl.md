# Windows Network Redirect Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Windows network redirect support using existing WinDivert infrastructure.

**Architecture:** Extend NAT table with redirect fields, wire policy engine to Windows network interceptor, add redirect evaluation in DNS and TCP paths.

**Tech Stack:** Go, WinDivert, existing policy engine

---

### Task 1: Extend NAT Table with Redirect Fields

**Files:**
- Modify: `internal/platform/windows/nat_table.go`

**Step 1: Add redirect fields to NATEntry struct**

Find the `NATEntry` struct and add:

```go
type NATEntry struct {
	OriginalDst  net.IP
	OriginalPort uint16
	Protocol     uint8
	ProcessID    uint32
	CreatedAt    time.Time
	// Redirect fields
	RedirectTo  string // "host:port" if redirect matched, empty otherwise
	RedirectTLS string // "passthrough" or "rewrite_sni"
	RedirectSNI string // SNI to use if rewrite_sni
}
```

**Step 2: Add helper method to check if redirected**

```go
// IsRedirected returns true if this entry has a redirect destination
func (e *NATEntry) IsRedirected() bool {
	return e.RedirectTo != ""
}

// GetConnectTarget returns the destination to connect to (redirect or original)
func (e *NATEntry) GetConnectTarget() string {
	if e.RedirectTo != "" {
		return e.RedirectTo
	}
	return net.JoinHostPort(e.OriginalDst.String(), strconv.Itoa(int(e.OriginalPort)))
}
```

**Step 3: Run build**

Run: `GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/windows/nat_table.go
git commit -m "feat(windows): extend NAT table with redirect fields"
```

---

### Task 2: Add Redirect Fields to NAT Table Methods

**Files:**
- Modify: `internal/platform/windows/nat_table.go`

**Step 1: Update Add method signature**

Update the `Add` method to accept redirect parameters:

```go
// AddWithRedirect adds a NAT entry with optional redirect destination
func (t *NATTable) AddWithRedirect(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16,
	protocol uint8, pid uint32, redirectTo, redirectTLS, redirectSNI string) {
	key := t.makeKey(srcIP, srcPort)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = &NATEntry{
		OriginalDst:  dstIP,
		OriginalPort: dstPort,
		Protocol:     protocol,
		ProcessID:    pid,
		CreatedAt:    time.Now(),
		RedirectTo:   redirectTo,
		RedirectTLS:  redirectTLS,
		RedirectSNI:  redirectSNI,
	}
}
```

Keep the original `Add` method for backwards compatibility:

```go
func (t *NATTable) Add(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8, pid uint32) {
	t.AddWithRedirect(srcIP, srcPort, dstIP, dstPort, protocol, pid, "", "", "")
}
```

**Step 2: Run build**

Run: `GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add internal/platform/windows/nat_table.go
git commit -m "feat(windows): add AddWithRedirect method to NAT table"
```

---

### Task 3: Wire Policy Engine to Windows Network Interceptor

**Files:**
- Modify: `internal/platform/windows/network.go`

**Step 1: Read the existing network.go to understand the structure**

Look for where the network interceptor is created and how dependencies are passed.

**Step 2: Add policy engine and correlation map fields**

Add imports and fields for policy engine and correlation map:

```go
import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/netmonitor/redirect"
)

// In the network interceptor struct, add:
policyEngine   *policy.Engine
correlationMap *redirect.CorrelationMap
```

**Step 3: Add setter methods**

```go
func (n *NetworkInterceptor) SetPolicyEngine(engine *policy.Engine) {
	n.policyEngine = engine
}

func (n *NetworkInterceptor) SetCorrelationMap(cm *redirect.CorrelationMap) {
	n.correlationMap = cm
}
```

**Step 4: Run build**

Run: `GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 5: Commit**

```bash
git add internal/platform/windows/network.go
git commit -m "feat(windows): wire policy engine and correlation map to network interceptor"
```

---

### Task 4: Add Connect Redirect Evaluation in WinDivert

**Files:**
- Modify: `internal/platform/windows/windivert_windows.go`

**Step 1: Read the existing code to find where TCP SYN packets are handled**

Look for the packet handling loop and where NAT entries are created.

**Step 2: Add redirect evaluation before NAT entry creation**

When a TCP SYN is captured:
1. Look up hostname from correlation map using destination IP
2. Build host:port string
3. Call `engine.EvaluateConnectRedirect(hostPort)`
4. If matched, use `AddWithRedirect` with redirect destination
5. Emit event if visibility != "silent"

```go
// After extracting destination IP and port from packet
var redirectTo, redirectTLS, redirectSNI string
if n.policyEngine != nil && n.correlationMap != nil {
	hostname, found := n.correlationMap.LookupHostname(dstIP)
	if !found {
		hostname = dstIP.String()
	}
	hostPort := net.JoinHostPort(hostname, strconv.Itoa(int(dstPort)))
	result := n.policyEngine.EvaluateConnectRedirect(hostPort)
	if result.Matched {
		redirectTo = result.RedirectTo
		redirectTLS = result.TLSMode
		redirectSNI = result.SNI
		// Emit event if visibility != "silent"
		if result.Visibility != "silent" {
			// emit ConnectRedirectEvent
		}
	}
}
n.natTable.AddWithRedirect(srcIP, srcPort, dstIP, dstPort, protocol, pid,
	redirectTo, redirectTLS, redirectSNI)
```

**Step 3: Run build**

Run: `GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/windows/windivert_windows.go
git commit -m "feat(windows): add connect redirect evaluation in WinDivert"
```

---

### Task 5: Update TCP Proxy to Use Redirect Destination

**Files:**
- Modify: `internal/platform/windows/windivert_windows.go` or relevant proxy file

**Step 1: Find where TCP proxy connects to upstream**

Look for where the proxy reads from NAT table and connects to the destination.

**Step 2: Use GetConnectTarget instead of original destination**

```go
entry := n.natTable.Lookup(srcIP, srcPort)
if entry == nil {
	// handle error
	return
}

// Connect to redirect target (or original if not redirected)
target := entry.GetConnectTarget()
conn, err := net.Dial("tcp", target)
```

**Step 3: Run build**

Run: `GOOS=windows go build ./internal/platform/windows/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/windows/windivert_windows.go
git commit -m "feat(windows): use redirect destination in TCP proxy"
```

---

### Task 6: Ensure DNS Redirect Works on Windows

**Files:**
- Check: `internal/netmonitor/dns.go`
- Modify: `internal/platform/windows/network.go` if needed

**Step 1: Verify DNS interceptor is used on Windows**

Check if the DNS interceptor with redirect support is wired up for Windows.

**Step 2: Ensure correlation map is passed to DNS interceptor**

The DNS interceptor needs the correlation map to record hostname→IP mappings.

**Step 3: Run build**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds

**Step 4: Commit if changes made**

```bash
git add <files>
git commit -m "feat(windows): ensure DNS redirect integration"
```

---

### Task 7: Add Windows-Specific Tests

**Files:**
- Create: `internal/platform/windows/nat_table_test.go` (extend if exists)

**Step 1: Add tests for redirect fields**

```go
func TestNATTableWithRedirect(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.0.1")

	// Test without redirect
	table.Add(srcIP, 12345, dstIP, 443, 6, 1234)
	entry := table.Lookup(srcIP, 12345)
	if entry.IsRedirected() {
		t.Error("expected not redirected")
	}
	if entry.GetConnectTarget() != "10.0.0.1:443" {
		t.Errorf("expected 10.0.0.1:443, got %s", entry.GetConnectTarget())
	}

	// Test with redirect
	table.AddWithRedirect(srcIP, 12346, dstIP, 443, 6, 1234,
		"proxy.internal:443", "rewrite_sni", "proxy.internal")
	entry = table.Lookup(srcIP, 12346)
	if !entry.IsRedirected() {
		t.Error("expected redirected")
	}
	if entry.GetConnectTarget() != "proxy.internal:443" {
		t.Errorf("expected proxy.internal:443, got %s", entry.GetConnectTarget())
	}
	if entry.RedirectTLS != "rewrite_sni" {
		t.Errorf("expected rewrite_sni, got %s", entry.RedirectTLS)
	}
	if entry.RedirectSNI != "proxy.internal" {
		t.Errorf("expected proxy.internal, got %s", entry.RedirectSNI)
	}
}
```

**Step 2: Run tests**

Run: `GOOS=windows go test ./internal/platform/windows/... -v`
Expected: Tests pass (or skip on non-Windows)

**Step 3: Commit**

```bash
git add internal/platform/windows/nat_table_test.go
git commit -m "test(windows): add NAT table redirect tests"
```

---

### Task 8: Update Documentation

**Files:**
- Modify: `docs/plans/2026-01-29-windows-network-redirect-design.md`

**Step 1: Add implementation status**

Add to the top:

```markdown
**Status:** Implemented
**Branch:** feature/windows-network-redirect
```

**Step 2: Commit**

```bash
git add docs/plans/2026-01-29-windows-network-redirect-design.md
git commit -m "docs: mark Windows network redirect as implemented"
```

---

## Summary

**Tasks 1-2:** NAT table extension with redirect fields
**Tasks 3-5:** WinDivert integration with policy engine
**Task 6:** DNS redirect verification
**Tasks 7-8:** Tests and documentation
