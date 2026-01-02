# Windows WinDivert Network Interception Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement transparent network interception on Windows using WinDivert, matching Linux's iptables+proxy behavior.

**Architecture:** WinDivert captures outbound packets, rewrites destinations to local proxy, proxy connects to original destination on behalf of the app.

**Tech Stack:** Go, godivert library, WinDivert 2.2.x driver, existing mini filter driver for PID tracking

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     agentsh Session Process                      │
│                                                                  │
│   App makes connection to api.github.com:443                    │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      WinDivert Driver                            │
│                                                                  │
│   Filter: "outbound and (tcp or udp.DstPort == 53)"             │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   WinDivert Capture Goroutine                    │
│                                                                  │
│   1. Receive packet from WinDivert                              │
│   2. Check if PID belongs to agentsh session (user-mode filter) │
│   3. Non-session traffic: reinject unchanged                    │
│   4. Session traffic:                                            │
│      - TCP SYN → Store in NAT table, rewrite dst to proxy       │
│      - UDP :53 → Store in NAT table, rewrite dst to DNS proxy   │
│   5. Reinject modified packet                                    │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              TCP Proxy (existing) / DNS Proxy (existing)         │
│                                                                  │
│   - Accepts redirected connections                               │
│   - Looks up original destination from NAT table                │
│   - Applies policy, logs events                                  │
│   - Connects to real destination                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

1. **Transparent proxy** - Full MITM capability, matches Linux behavior
2. **DNS redirection included** - Full visibility into DNS queries
3. **Process ID filtering** - Leverages existing mini filter driver process tracking
4. **User-mode PID check** - Avoids constant WinDivert handle recreation on process churn
5. **godivert library** - Battle-tested, good documentation, handles packet manipulation

---

## Components & Data Structures

### New files in `internal/platform/windows/`

| File | Purpose |
|------|---------|
| `windivert.go` | WinDivert handle management, packet capture loop |
| `windivert_windows.go` | Build-tagged implementation (actual WinDivert calls) |
| `windivert_stub.go` | Stub for cross-compilation on non-Windows |
| `nat_table.go` | Thread-safe NAT table mapping redirected connections to original destinations |

### Core data structures

```go
// NATEntry tracks a redirected connection's original destination
type NATEntry struct {
    OriginalDstIP   net.IP
    OriginalDstPort uint16
    Protocol        string    // "tcp" or "udp"
    ProcessID       uint32
    CreatedAt       time.Time
}

// NATTable maps local proxy connections to original destinations
// Key: "srcIP:srcPort" (the redirected connection's source)
type NATTable struct {
    mu      sync.RWMutex
    entries map[string]*NATEntry
    ttl     time.Duration // cleanup stale entries
}

// WinDivertHandle wraps godivert with session-aware filtering
type WinDivertHandle struct {
    handle       *godivert.WinDivertHandle
    natTable     *NATTable
    proxyPort    uint16
    dnsPort      uint16
    sessionPIDs  map[uint32]bool  // processes to intercept
    pidMu        sync.RWMutex
    stopChan     chan struct{}
    driver       *DriverClient    // existing mini filter client
}
```

### Integration with existing code

- `DriverClient` already tracks session processes via mini filter
- `WinDivertHandle` subscribes to process events from driver
- When process spawns in session → add PID to set
- When process exits → remove PID from set

---

## Packet Capture & Redirection Flow

### Capture loop

```go
func (w *WinDivertHandle) captureLoop() {
    for {
        select {
        case <-w.stopChan:
            return
        default:
            packet, err := w.handle.Recv()
            if err != nil {
                continue
            }
            w.processPacket(packet)
        }
    }
}
```

### Packet processing logic

```
┌─────────────────────────────────────────────────────────────┐
│                    processPacket(packet)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Parse packet headers (IP + TCP/UDP)                     │
│                                                              │
│  2. Get PID from packet.Addr.ProcessId                      │
│     Check if PID in sessionPIDs map                         │
│     ├─ NO: Reinject unchanged, return                       │
│     └─ YES: Continue to redirection                         │
│                                                              │
│  3. Is TCP SYN? (new connection)                            │
│     ├─ YES: Store in NAT table:                             │
│     │       key = srcIP:srcPort                              │
│     │       value = {originalDstIP, originalDstPort, PID}   │
│     │       Rewrite dstIP → 127.0.0.1                       │
│     │       Rewrite dstPort → proxyPort                     │
│     │       Recalculate checksums                           │
│     │                                                        │
│     └─ NO (established): Rewrite dst same as SYN entry      │
│                                                              │
│  4. Is UDP port 53? (DNS)                                   │
│     ├─ Store in NAT table (for response matching)           │
│     │  Rewrite dst → 127.0.0.1:dnsPort                      │
│     │  Recalculate checksums                                │
│                                                              │
│  5. Reinject packet: w.handle.Send(packet)                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Checksum handling

WinDivert requires recalculating IP and TCP/UDP checksums after modifying packets:

```go
packet.CalcNewChecksum(w.handle)
```

### NAT table lookup by proxy

When the TCP proxy accepts a connection from `127.0.0.1:54321`, it queries:

```go
original := natTable.Lookup("127.0.0.1:54321")
// Returns: {OriginalDstIP: "140.82.114.4", OriginalDstPort: 443, ...}
```

---

## Dynamic PID Filtering & Driver Integration

### Two-tier filtering approach

**Tier 1 - WinDivert filter (coarse):**

```go
// Broad filter - capture all outbound TCP/DNS
// PID filtering happens in user-mode for flexibility
baseFilter := "outbound and (tcp or (udp and udp.DstPort == 53))"
```

**Tier 2 - User-mode PID check (precise):**

```go
func (w *WinDivertHandle) processPacket(packet *godivert.Packet) {
    // Get process ID from packet address info
    pid := packet.Addr.ProcessId

    // Fast path: check if PID belongs to a session
    w.pidMu.RLock()
    isSession := w.sessionPIDs[pid]
    w.pidMu.RUnlock()

    if !isSession {
        // Not a session process - reinject unchanged
        w.handle.Send(packet)
        return
    }

    // Session process - apply redirection
    w.redirectPacket(packet)
}
```

### Subscribing to process events from mini filter

```go
func (w *WinDivertHandle) Start(driver *DriverClient) error {
    // Subscribe to process create/exit events
    driver.OnProcessCreated = func(sessionToken uint64, pid uint32) {
        w.pidMu.Lock()
        w.sessionPIDs[pid] = true
        w.pidMu.Unlock()
    }

    driver.OnProcessExited = func(sessionToken uint64, pid uint32) {
        w.pidMu.Lock()
        delete(w.sessionPIDs, pid)
        w.pidMu.Unlock()

        // Cleanup NAT entries for this PID
        w.natTable.RemoveByPID(pid)
    }

    return nil
}
```

### Why user-mode PID filtering?

- WinDivert PID filters in kernel require handle recreation on change
- Process churn (spawning npm, git, etc.) would cause constant handle recreation
- User-mode check is ~microseconds, negligible overhead
- Simpler, more maintainable code

---

## Error Handling & Proxy Integration

### Fail modes (matching mini filter driver)

```go
type WinDivertHandle struct {
    // ... existing fields
    failMode            FailMode  // FAIL_OPEN or FAIL_CLOSED
    consecutiveFailures int32
    maxFailures         int32
    inFailMode          bool
}

func (w *WinDivertHandle) processPacket(packet *godivert.Packet) {
    if w.inFailMode {
        if w.failMode == FAIL_OPEN {
            // Let traffic through unmodified
            w.handle.Send(packet)
            return
        }
        // FAIL_CLOSED: drop packet (don't reinject)
        return
    }

    // Normal processing...
}
```

### Integration with existing TCP/DNS proxy

The existing proxy architecture expects:

1. Accept connection on `proxyPort`
2. Look up original destination
3. Check policy
4. Connect to destination (or block)

### Required proxy changes

```go
// internal/proxy/tcp_proxy.go

func (p *TCPProxy) handleConnection(conn net.Conn) {
    clientAddr := conn.RemoteAddr().String()

    // Platform-specific NAT lookup
    var originalDst *OriginalDestination
    if runtime.GOOS == "windows" {
        // Query WinDivert NAT table
        originalDst = p.windivertNAT.Lookup(clientAddr)
    } else {
        // Linux: use SO_ORIGINAL_DST socket option
        originalDst = getOriginalDst(conn)
    }

    if originalDst == nil {
        conn.Close()
        return
    }

    // Rest of proxy logic unchanged...
    p.policyCheck(originalDst)
    p.connectAndRelay(conn, originalDst)
}
```

### NAT table passed to proxy

```go
// In network.go Setup()
func (n *Network) Setup(config NetConfig) error {
    n.natTable = NewNATTable(5 * time.Minute)
    n.windivert = NewWinDivertHandle(n.natTable, config)

    // Pass NAT table to proxy via config
    config.NATTable = n.natTable

    return n.windivert.Start(n.driverClient)
}
```

---

## Testing & Deployment

### Unit tests (run on any platform)

```go
// nat_table_test.go - pure Go, no Windows deps
func TestNATTable_InsertLookup(t *testing.T)
func TestNATTable_TTLExpiry(t *testing.T)
func TestNATTable_RemoveByPID(t *testing.T)
func TestNATTable_ConcurrentAccess(t *testing.T)
```

### Integration tests (Windows only, require admin)

```go
//go:build windows && integration

func TestWinDivert_CapturePacket(t *testing.T)
func TestWinDivert_RedirectTCP(t *testing.T)
func TestWinDivert_RedirectDNS(t *testing.T)
func TestWinDivert_PIDFiltering(t *testing.T)
func TestWinDivert_FailMode(t *testing.T)
```

### CI considerations

| Environment | What runs |
|-------------|-----------|
| Linux CI | NAT table unit tests, cross-compile check |
| Windows CI | Unit tests + integration tests (needs admin runner) |
| Local dev | Full manual testing with real WinDivert driver |

### Deployment requirements

```
agentsh/
├── agentsh.exe           # Main binary
├── WinDivert.dll         # WinDivert user-mode library (x64)
├── WinDivert64.sys       # WinDivert kernel driver (x64)
└── agentsh.sys           # Mini filter driver (existing)
```

### Installation steps

1. Copy `WinDivert.dll` and `WinDivert64.sys` alongside `agentsh.exe`
2. WinDivert auto-installs driver on first use (requires admin)
3. Mini filter driver installed separately (existing process)
4. No persistent driver installation needed - WinDivert loads on demand

### Version compatibility

- WinDivert 2.2.x supports Windows 7 through Windows 11
- godivert uses WinDivert 2.2
- Our mini filter targets Windows 10+ (compatible)

---

## Security Considerations

### Administrator requirement

WinDivert requires administrator privileges to:
- Load the kernel driver
- Capture network packets
- Modify packet contents

This aligns with existing agentsh requirements (mini filter driver also needs admin).

### Attack surface

- WinDivert driver is signed by Microsoft (WHQL certified)
- User-mode code runs as admin but in agentsh process
- NAT table is internal, not exposed via API
- Fail modes prevent traffic leakage on errors

### Comparison with Linux

| Aspect | Linux | Windows |
|--------|-------|---------|
| Privilege | root | Administrator |
| Kernel component | iptables (built-in) | WinDivert (3rd party, signed) |
| Isolation | Network namespaces | PID filtering |
| Driver signing | N/A | WHQL certified |

---

## Future Enhancements

1. **TLS inspection** - Proxy can terminate TLS, inspect content, re-encrypt (requires cert injection)
2. **Per-connection policy caching** - Cache policy decisions by destination to reduce lookups
3. **Metrics** - Track packets captured, redirected, passed through, dropped
4. **WFP fallback** - If WinDivert unavailable, fall back to WFP for block-only mode
