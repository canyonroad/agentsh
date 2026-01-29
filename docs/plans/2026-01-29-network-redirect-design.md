# Network Redirect Design

DNS and connect-level redirect for agentsh-wrapped processes.

## Overview

Intercept DNS resolution and TCP connections from processes running under agentsh, redirecting them to different destinations based on policy rules. Primary use case: route Anthropic API calls through GCP Vertex without application changes.

## Scope

- **Processes**: agentsh-wrapped only (not system-wide)
- **Layers**: DNS resolution and connect-level redirect
- **Platform**: Linux first (eBPF), macOS/Windows later

## Configuration Schema

```yaml
dns_redirects:
  - name: anthropic-to-vertex-dns
    match: ".*\\.anthropic\\.com"        # regex, full string match
    resolve_to: 10.0.0.50
    visibility: audit_only               # silent | audit_only | warn
    on_failure: fail_closed              # fail_closed | fail_open | retry_original

connect_redirects:
  - name: anthropic-to-vertex
    match: "api\\.anthropic\\.com:443"   # regex, host:port or host (any port)
    redirect_to: vertex-proxy.internal:443
    tls:
      mode: passthrough                  # passthrough | rewrite_sni
      sni: null                          # required if rewrite_sni
    visibility: warn
    message: "Routed through Vertex AI"
    on_failure: fail_closed
```

Rules evaluated in order; first match wins.

## Implementation

### DNS Interception

**Primary: uprobe on getaddrinfo**

1. Attach uprobe to `getaddrinfo` entry point
2. Capture hostname argument
3. Match against `dns_redirects` rules
4. If match: attach uretprobe to modify returned `addrinfo` struct with `resolve_to` IP
5. Emit audit event

**Secondary: raw DNS (UDP:53)**

- Intercept `sendto`/`sendmsg` syscalls to port 53
- Parse DNS query packet, extract hostname
- Redirect to local resolver or modify response packet

The uprobe approach covers 95%+ of cases.

### Connect Redirect

**eBPF on sys_connect**

1. Attach to `sys_connect` entry
2. Extract destination from `sockaddr` (IP and port)
3. Reverse-lookup hostname from DNS correlation map
4. Match against `connect_redirects` rules
5. If match: modify `sockaddr` in-place, store original in BPF map
6. Emit audit event

**Hostname correlation:**

DNS interception populates `hostname → IP` map. Connect interception does reverse lookup. Fallback: match on IP directly.

**SNI rewriting (when `tls.mode: rewrite_sni`):**

- Intercept `send`/`write` on socket
- Detect TLS ClientHello (bytes 0x16 0x03)
- Parse and rewrite SNI extension
- Forward modified packet

### Failure Handling

| `on_failure` | Behavior |
|--------------|----------|
| `fail_closed` | Return error to application |
| `fail_open` | Retry connect to original destination |
| `retry_original` | Same as `fail_open` |

Detection via eBPF on connect return value (`ECONNREFUSED`, `ETIMEDOUT`, `ENETUNREACH`).

### Visibility

| Setting | Behavior |
|---------|----------|
| `silent` | No event, no output |
| `audit_only` | Event to audit log only |
| `warn` | Event + message to stderr |

## Audit Events

**DNS redirect:**

```json
{
  "type": "dns_redirect",
  "timestamp": "2026-01-29T10:23:45Z",
  "pid": 12345,
  "process": "python",
  "rule": "anthropic-to-vertex-dns",
  "original_host": "api.anthropic.com",
  "resolved_to": "10.0.0.50",
  "visibility": "audit_only"
}
```

**Connect redirect:**

```json
{
  "type": "connect_redirect",
  "timestamp": "2026-01-29T10:23:45Z",
  "pid": 12345,
  "process": "python",
  "rule": "anthropic-to-vertex",
  "original": "api.anthropic.com:443",
  "redirected_to": "vertex-proxy.internal:443",
  "tls_mode": "passthrough",
  "visibility": "warn",
  "message": "Routed through Vertex AI"
}
```

**Fallback event:**

```json
{
  "type": "connect_redirect_fallback",
  "rule": "anthropic-to-vertex",
  "original": "api.anthropic.com:443",
  "redirect_attempted": "vertex-proxy.internal:443",
  "error": "ECONNREFUSED",
  "action": "fail_open",
  "status": "connected_to_original"
}
```

## Code Organization

```
internal/
├── policy/
│   └── network_redirect.go     # Rule parsing, matching, config types
├── interceptor/
│   ├── dns_redirect.go         # Userspace DNS redirect logic
│   └── connect_redirect.go     # Userspace connect redirect logic
├── ebpf/
│   ├── dns_redirect.bpf.c      # DNS interception (uprobe + UDP)
│   ├── connect_redirect.bpf.c  # Connect syscall interception
│   ├── sni_rewrite.bpf.c       # TLS SNI rewriting
│   └── redirect_maps.h         # Shared BPF maps definitions
└── audit/
    └── events.go               # Add new redirect event types
```

**BPF maps (via cilium/ebpf):**

- `hostnameToIP` - correlates DNS lookups to resolved IPs
- `socketOriginal` - stores original destinations per socket fd

## Future Work

- macOS implementation (ESF-based)
- Windows implementation (minifilter-based)
- Full MITM with custom CA (for deep inspection scenarios)
- Pattern-based IP matching (CIDR blocks)
