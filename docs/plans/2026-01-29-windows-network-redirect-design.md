# Windows Network Redirect Design

**Status:** Implemented (Infrastructure)
**Branch:** feature/windows-network-redirect

DNS and connect-level redirect for agentsh-wrapped processes on Windows.

## Overview

Extend the existing WinDivert infrastructure to support DNS and connect-level redirects using the same policy rules as Linux (`dns_redirects`, `connect_redirects`).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Shared Components                         │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────┐ │
│  │ policy.Engine   │  │ CorrelationMap   │  │ Event Types │ │
│  │ (evaluation)    │  │ (hostname↔IP)    │  │ (audit)     │ │
│  └────────┬────────┘  └────────┬─────────┘  └──────┬──────┘ │
└───────────┼────────────────────┼───────────────────┼────────┘
            │                    │                   │
     ┌──────┴────────────────────┴───────────────────┴──────┐
     │              Platform-Specific Interception           │
     ├───────────────────────┬───────────────────────────────┤
     │        Linux          │           Windows             │
     │  ┌─────────────────┐  │  ┌─────────────────────────┐  │
     │  │ eBPF + uprobe   │  │  │ WinDivert packet loop   │  │
     │  │ (dns.go,        │  │  │ (windivert_windows.go)  │  │
     │  │  collector.go)  │  │  │                         │  │
     │  └─────────────────┘  │  └─────────────────────────┘  │
     └───────────────────────┴───────────────────────────────┘
```

**Key principle:** Policy evaluation is shared. Only packet capture/rewrite is platform-specific.

## DNS Redirect Flow

1. Capture outbound DNS query (UDP:53) via WinDivert
2. Redirect to local DNS proxy
3. DNS proxy calls `engine.EvaluateDnsRedirect(hostname)`
4. If matched:
   - Build synthetic DNS response with `result.ResolveTo` IP
   - Update correlation map: `hostname → redirectIP`
   - Emit `EventDNSRedirect` if visibility != "silent"
   - Return synthetic response (skip upstream)
5. If not matched: query upstream as normal

## Connect Redirect Flow

1. Capture TCP SYN packet via WinDivert
2. Extract destination IP and port
3. Lookup hostname from correlation map
4. Call `engine.EvaluateConnectRedirect(hostname:port)`
5. If matched:
   - Store redirect destination in NAT table
   - Emit `EventConnectRedirect` if visibility != "silent"
   - Rewrite packet destination to local proxy
   - Reinject packet
6. TCP proxy connects to redirect destination from NAT table
7. If `TLSMode == "rewrite_sni"`: modify TLS ClientHello SNI extension
8. If not matched: existing flow (proxy connects to original destination)

## Code Changes

### Files to Modify

| File | Changes |
|------|---------|
| `internal/platform/windows/network.go` | Add `policyEngine` and `correlationMap` fields |
| `internal/platform/windows/windivert_windows.go` | Update NAT entry with redirect destination |
| `internal/platform/windows/nat_table.go` | Add redirect fields to NAT entry |
| `internal/netmonitor/dns.go` | Ensure Windows path uses existing redirect logic |

### NAT Table Entry Extension

```go
type NATEntry struct {
    OriginalDst    net.IP
    OriginalPort   uint16
    RedirectTo     string  // "host:port" if redirect matched
    RedirectTLS    string  // "passthrough" or "rewrite_sni"
    RedirectSNI    string  // SNI for rewrite_sni mode
    Protocol       uint8
    ProcessID      uint32
    CreatedAt      time.Time
}
```

### TCP Proxy Changes

When connecting upstream:
- If `RedirectTo` is set: connect to redirect destination
- If `RedirectTLS == "rewrite_sni"`: modify SNI in TLS ClientHello
- Otherwise: connect to original destination

## SNI Rewriting

For `tls.mode: rewrite_sni`:
1. TCP proxy receives connection
2. Read TLS ClientHello from client
3. Parse SNI extension
4. Replace SNI with `RedirectSNI` value
5. Forward modified ClientHello to redirect destination
6. Relay remaining traffic bidirectionally

## Testing

**Unit tests:**
- NAT table with redirect fields
- Correlation map (already tested, shared)

**Integration tests:**
- DNS redirect returns synthetic response
- Connect redirect routes to redirect destination
- SNI rewrite modifies ClientHello

**Manual testing:**
```powershell
# With policy redirecting api.anthropic.com
curl -v https://api.anthropic.com
# Verify traffic goes to redirect destination
```

## Implementation Order

1. Extend NAT table with redirect fields
2. Wire policy engine and correlation map to Windows network interceptor
3. Add redirect evaluation in DNS proxy path
4. Add redirect evaluation in TCP SYN capture path
5. Implement SNI rewriting in TCP proxy
6. Add Windows-specific tests

## Future Work

- WinDivert 2.x upgrade for per-packet ProcessId
- WFP fallback for systems without WinDivert
- IPv6 redirect support
- SNI rewriting in TCP proxy
- Full connect_redirects policy schema in policy.Engine

## Implementation Notes

The following infrastructure has been implemented:

1. **NAT Table** (`internal/platform/windows/nat_table.go`):
   - Added `RedirectTo`, `RedirectTLS`, `RedirectSNI` fields to `NATEntry`
   - Added `IsRedirected()` and `GetConnectTarget()` helper methods
   - Added `InsertWithRedirect()` method

2. **Network Interceptor** (`internal/platform/windows/network.go`):
   - Added `policyEngine` and `dnsCache` fields
   - Added `SetPolicyEngine()` and `SetDNSCache()` setter methods

3. **WinDivert** (`internal/platform/windows/windivert_windows.go`):
   - Added `policyEngine` and `dnsCache` fields to `WinDivertHandle`
   - Added `evaluateConnectRedirect()` method with hostname lookup from DNS cache
   - Updated `redirectPacket()` to use `InsertWithRedirect()` for TCP SYN packets

4. **Tests** (`internal/platform/windows/nat_table_test.go`):
   - Added tests for `IsRedirected()`, `GetConnectTarget()`, `InsertWithRedirect()`

**Not yet implemented:**
- `connect_redirects` policy schema in `policy.Engine` (placeholder in `evaluateConnectRedirect`)
- SNI rewriting in TCP proxy
- Full API layer integration to start DNS/TCP proxies and wire DNS cache
