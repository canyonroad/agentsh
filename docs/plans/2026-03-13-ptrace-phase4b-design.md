# Ptrace Phase 4b: DNS Redirect, SNI Rewrite, TracerPid Masking — Design

**Date:** 2026-03-13
**Author:** Eran / Canyon Road
**Status:** Design Complete

---

## Overview

Phase 4b adds three features to the ptrace backend, all building on Phase 4a's syscall injection engine:

1. **DNS Redirect** — An in-process DNS proxy intercepts and steers DNS queries per policy
2. **SNI Rewrite** — In-place ClientHello rewrite on TLS-watched sockets
3. **TracerPid Masking** — Hide ptrace relationship by patching `/proc/*/status` reads

## 1. DNS Redirect

### Architecture

An in-process DNS proxy runs as a goroutine in the tracer process. It binds to `127.0.0.1:0` (OS-assigned port) on both UDP and TCP. The assigned port is stored on the `Tracer` struct.

When a tracee connects to any destination on port 53 (or 853 for DoT), the existing connect redirect from Phase 4a rewrites the sockaddr to `127.0.0.1:<proxyPort>`. The proxy receives the query, consults policy, and returns or relays the response.

### Connect Redirect Integration

In the existing `handleNetwork()` path, after `parseSockaddr()` resolves the destination, add a check: if the destination port is 53 or 853 and the family is AF_INET/AF_INET6, redirect the connect to `127.0.0.1:<proxyPort>`. This uses the same connect redirect mechanism from Phase 4a — rewrite the sockaddr in tracee memory.

### Query Processing Flow

```
Tracee sendto(53) → connect redirected to proxy → proxy receives DNS query
  1. Parse DNS question (domain, type)
  2. Look up tracee PID from connection source port (tracked on redirect)
  3. Call NetworkHandler.HandleNetwork() with:
     - Operation: "dns"
     - Domain: query name
     - Address: original resolver IP
     - Port: 53
     - PID/SessionID from tracked connection
  4. Based on NetworkResult:
     - Allow            → forward to original resolver, relay response
     - Deny             → respond with NXDOMAIN (RCODE 3)
     - RedirectUpstream → forward to result.RedirectUpstream resolver
     - SyntheticRecords → build response with result.Records
  5. Return DNS response to tracee
```

### PID Tracking

When connect redirect fires for a DNS socket, the proxy needs to know which tracee PID owns the connection. The tracer records `{srcPort → PID, sessionID, originalResolver}` at redirect time. The proxy looks this up when a query arrives on that source port.

### Proxy Lifecycle

Starts when the tracer starts (if `TraceNetwork` is enabled). Stops when the tracer shuts down. No external dependencies.

## 2. SNI Rewrite

### Fd Tracking

When a `connect` syscall completes successfully (syscall-exit, return value 0) and the destination port is 443 or 853, the tracer adds the fd to a per-TGID `tlsWatchedFds` set. The entry stores the destination domain — known from the prior DNS resolution (the DNS proxy's PID tracking maps IP back to the domain that resolved to it).

Cleared on `close(fd)`, `dup2` over the fd, and `exec` (fd table reset).

### Write Interception

`SYS_WRITE`, `SYS_SENDTO`, and `SYS_SENDMSG` are added to syscall dispatch. On syscall-enter, check if the fd (arg0) is in `tlsWatchedFds`. If not, allow immediately — near-zero overhead for non-TLS writes.

If the fd is watched:

1. Read the first 5 bytes from the write buffer (TLS record header)
2. Check: content type 0x16 (handshake), version 0x0301–0x0303, then record length
3. Read byte 6: handshake type 0x01 (ClientHello)
4. Parse to find SNI extension (type 0x0000) within extensions list
5. If no SNI or SNI matches policy target → allow, remove fd from watch set
6. If SNI needs rewriting → rewrite in tracee memory

### Rewrite Mechanics

- **Same length or shorter:** overwrite in-place, pad SNI value with trailing bytes if needed (SNI length field updated)
- **Longer:** allocate from scratch page, write modified ClientHello there, update write buffer pointer register (arg1) and length register (arg2)
- After rewrite, remove fd from watch set (SNI only appears in the first ClientHello)

### TLS Record Length Fixup

If the SNI length changes, three length fields need updating in the buffer:

1. TLS record length (bytes 3–4)
2. Handshake length (bytes 6–8)
3. SNI extension length + server name list length + name length

All are at known offsets once parsed. The tracer writes the corrected lengths back to tracee memory.

### Edge Cases

| Case | Behavior |
|------|----------|
| Partial write (buffer split across syscalls) | Only inspect first write per fd; if header incomplete, remove from watch and allow |
| TLS 1.3 with encrypted ClientHello (ECH) | SNI not visible — allow, can't rewrite |
| Non-TLS traffic on port 443 (HTTP, WebSocket upgrade) | First bytes won't match TLS record header — allow |
| `sendmsg` with scatter/gather iovec | Read first iovec only; if too small for header, allow |

## 3. TracerPid Masking

### Openat Tracking

In the existing `handleFile()` path, after path resolution, check if the resolved path matches `/proc/<N>/status` or `/proc/self/status` or `/proc/thread-self/status`. If so, allow the open but record the returned fd on syscall-exit: add to a per-TGID `maskedStatusFds` map keyed by fd number.

No handler call needed — unconditional stealth behavior when `TracerConfig.MaskTracerPid` is true.

### Read Interception

`SYS_READ` and `SYS_PREAD64` are added to syscall dispatch. On syscall-exit (after the kernel has written data to the buffer):

1. Check if the fd is in `maskedStatusFds` — if not, skip immediately
2. Read the buffer from tracee memory (up to return value bytes)
3. Scan for `TracerPid:\t` (bytes: `54 72 61 63 65 72 50 69 64 3a 09`)
4. If found, overwrite the PID number with `0` followed by spaces to fill the original width (preserving newline position)
5. Write patched buffer back to tracee memory

### Fd Lifecycle

| Event | Action |
|-------|--------|
| `openat` returns fd for `/proc/*/status` | Add fd to `maskedStatusFds` |
| `close(fd)` where fd is tracked | Remove from `maskedStatusFds` |
| `dup2(old, new)` where new is tracked | Remove new (overwritten) |
| `exec` | Clear all tracked fds for the TGID |

### Performance

The `read` syscall is extremely hot. The fd check is a map lookup on syscall-exit, which is cheap. The actual buffer scan only happens for reads on tracked fds (only `/proc/*/status` files), which is rare.

### What This Doesn't Cover

- `/proc/<pid>/stat` — TracerPid is not in this file
- `PTRACE_TRACEME` detection via `ptrace(PTRACE_TRACEME)` returning `EPERM`
- `PR_SET_PTRACER` / prctl-based detection

## 4. Handler Interface Changes

### NetworkContext Additions

```go
type NetworkContext struct {
    // ... existing fields ...
    Domain    string // DNS query name (set when Operation == "dns")
    QueryType uint16 // DNS query type: A=1, AAAA=28, CNAME=5, etc.
}
```

### NetworkResult Additions

```go
type NetworkResult struct {
    // ... existing fields ...
    RedirectUpstream string      // Forward DNS query to this resolver (ip:port)
    Records          []DNSRecord // Synthetic DNS response records
}

type DNSRecord struct {
    Type  uint16 // A, AAAA, CNAME
    Value string // IP address or domain name
    TTL   uint32
}
```

When `Operation == "dns"`:
- `Allow` → forward to original resolver
- `Deny` → return NXDOMAIN
- `Action == Redirect` + `RedirectUpstream` set → forward to different resolver
- `Action == Redirect` + `Records` set → return synthetic response

When `Operation == "connect"` — unchanged from Phase 4a.

### TracerConfig Addition

```go
type TracerConfig struct {
    // ... existing fields ...
    MaskTracerPid bool // Enable TracerPid masking on /proc/*/status reads
}
```

## 5. Syscall Dispatch Changes

### New Classifications

```
isWriteSyscall(nr):  SYS_WRITE, SYS_SENDTO, SYS_SENDMSG
isReadSyscall(nr):   SYS_READ, SYS_PREAD64
isCloseSyscall(nr):  SYS_CLOSE
```

### Updated Dispatch

```
dispatchSyscall(tid, nr):
  isExecveSyscall   → handleExecve()
  isFileSyscall     → handleFile()
  isNetworkSyscall  → handleNetwork()    // connect, bind — unchanged
  isSignalSyscall   → handleSignal()
  isWriteSyscall    → handleWrite()      // NEW: SNI rewrite
  isReadSyscall     → handleRead()       // NEW: TracerPid masking (exit only)
  isCloseSyscall    → handleClose()      // NEW: fd tracking cleanup
  else              → allowSyscall()
```

### Fast-Path Guards

- `handleWrite()`: check `tlsWatchedFds[fd]` → miss? `allowSyscall()` immediately
- `handleRead()`: only acts on syscall-exit; check `maskedStatusFds[fd]` → miss? skip
- `handleClose()`: check if fd is in either tracking map → miss? `allowSyscall()` immediately

### Syscall-Exit Handling

Phase 4b adds two exit-time behaviors:

1. **Read masking**: on exit, if fd tracked → scan and patch buffer
2. **Openat fd capture**: on exit, if path was `/proc/*/status` → record returned fd

Both need the exit return value from registers.

## 6. Testing Strategy

Integration tests behind `//go:build integration && linux`, following the existing pattern.

### DNS Redirect Tests

| Test | What it validates |
|------|-------------------|
| `TestIntegration_DNSProxyAllow` | Tracee resolves domain, proxy forwards to real resolver, valid response |
| `TestIntegration_DNSProxyDeny` | Handler returns deny, tracee gets NXDOMAIN |
| `TestIntegration_DNSProxyRedirectUpstream` | Handler returns redirect, query forwarded to alternate resolver |
| `TestIntegration_DNSProxySyntheticRecords` | Handler returns synthetic A/AAAA records, tracee gets those IPs |
| `TestIntegration_DNSConnectRedirect` | Tracee's connect to `8.8.8.8:53` transparently redirected to proxy |

### SNI Rewrite Tests

| Test | What it validates |
|------|-------------------|
| `TestIntegration_SNIRewriteSameLength` | SNI rewritten to same-length name, TLS handshake succeeds |
| `TestIntegration_SNIRewriteShorter` | SNI rewritten to shorter name, length fields updated correctly |
| `TestIntegration_SNIRewriteLonger` | SNI rewritten to longer name via scratch page, length fields correct |
| `TestIntegration_SNINoRewrite` | Non-matching SNI passes through unchanged |
| `TestIntegration_SNINonTLSPort443` | HTTP on port 443 — no crash, allowed through |

### TracerPid Masking Tests

| Test | What it validates |
|------|-------------------|
| `TestIntegration_TracerPidMasked` | Tracee reads `/proc/self/status`, sees `TracerPid: 0` |
| `TestIntegration_TracerPidMaskedByPid` | Tracee reads `/proc/<own-pid>/status`, sees `TracerPid: 0` |
| `TestIntegration_TracerPidDisabled` | `MaskTracerPid: false`, tracee sees real TracerPid |
| `TestIntegration_TracerPidFdClose` | After close+reopen of unrelated file with same fd, no false masking |

All runnable via `docker run --cap-add SYS_PTRACE`.

## 7. Files

| File | Action | Description |
|------|--------|-------------|
| `internal/ptrace/dns_proxy.go` | Create | In-process DNS proxy — UDP+TCP listener, query parsing, response building |
| `internal/ptrace/dns_proxy_test.go` | Create | Unit tests for DNS parsing/response building |
| `internal/ptrace/sni.go` | Create | ClientHello parser, SNI extraction and rewrite logic |
| `internal/ptrace/sni_test.go` | Create | Unit tests for TLS parsing |
| `internal/ptrace/handle_write.go` | Create | Write/sendto/sendmsg handler — TLS fd check, SNI rewrite dispatch |
| `internal/ptrace/handle_read.go` | Create | Read/pread64 handler — TracerPid masking on syscall-exit |
| `internal/ptrace/handle_close.go` | Create | Close handler — fd tracking cleanup |
| `internal/ptrace/fd_tracker.go` | Create | Per-TGID fd tracking for TLS-watched fds and masked status fds |
| `internal/ptrace/syscalls.go` | Modify | Add `isWriteSyscall`, `isReadSyscall`, `isCloseSyscall` |
| `internal/ptrace/tracer.go` | Modify | Wire new handlers into dispatch, start DNS proxy, add exit-time handling |
| `internal/ptrace/handle_network.go` | Modify | Add DNS connect redirect (port 53/853 → proxy), PID tracking |
| `internal/ptrace/args.go` | Modify | Add `Domain`, `QueryType` to NetworkContext; extend NetworkResult |
| `internal/ptrace/integration_test.go` | Modify | Add Phase 4b integration tests |

## 8. What's NOT in Phase 4b

- DoH (DNS-over-HTTPS) interception — would require HTTPS MITM
- Full TLS proxy / certificate management
- `PTRACE_TRACEME` detection masking
- Encrypted ClientHello (ECH) rewrite — not feasible without TLS proxy
- Multi-resolver chaining (single upstream per redirect)
