# macOS ESF+NE Architecture

This document describes the technical architecture of the macOS ESF (Endpoint Security Framework) + NE (Network Extension) implementation.

## Overview

ESF+NE provides enterprise-tier (90% security score) enforcement on macOS by leveraging Apple's kernel-level security frameworks:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         macOS Host                                   │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    AgentSH.app Bundle                           │ │
│  │                                                                  │ │
│  │  ┌──────────────┐    XPC     ┌──────────────────────────────┐  │ │
│  │  │              │◄──────────►│                              │  │ │
│  │  │  Go Binary   │            │      XPC Service             │  │ │
│  │  │  (agentsh)   │            │  (PolicyBridge.swift)        │  │ │
│  │  │              │            │                              │  │ │
│  │  │  - Policy    │  Unix      │  - JSON protocol over        │  │ │
│  │  │    Engine    │  Socket    │    Unix socket               │  │ │
│  │  │  - Session   │◄──────────►│  - Bridges XPC ↔ Go          │  │ │
│  │  │    Manager   │            │                              │  │ │
│  │  │  - API       │            └──────────────────────────────┘  │ │
│  │  │    Server    │                         ▲                     │ │
│  │  └──────────────┘                         │ XPC                 │ │
│  │                                           ▼                     │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │              System Extension                              │  │ │
│  │  │              (com.agentsh.sysext)                          │  │ │
│  │  │                                                            │  │ │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐ │  │ │
│  │  │  │   ESFClient    │  │ FilterData     │  │ DNSProxy     │ │  │ │
│  │  │  │                │  │ Provider       │  │ Provider     │ │  │ │
│  │  │  │  - AUTH_OPEN   │  │                │  │              │ │  │ │
│  │  │  │  - AUTH_EXEC   │  │  - IP/Port     │  │  - DNS       │ │  │ │
│  │  │  │  - NOTIFY_*    │  │    filtering   │  │    filtering │ │  │ │
│  │  │  └────────────────┘  └────────────────┘  └──────────────┘ │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ════════════════════════════════════════════════════════════════   │
│                           Kernel Boundary                            │
│  ════════════════════════════════════════════════════════════════   │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Kernel (XNU)                                 │ │
│  │                                                                  │ │
│  │  ┌────────────────┐              ┌────────────────────────────┐ │ │
│  │  │ Endpoint       │              │ Network Extension          │ │ │
│  │  │ Security       │              │ Framework                  │ │ │
│  │  │ Framework      │              │                            │ │ │
│  │  │                │              │  - Packet filtering        │ │ │
│  │  │  - File events │              │  - DNS interception        │ │ │
│  │  │  - Exec events │              │                            │ │ │
│  │  │  - Fork events │              │                            │ │ │
│  │  └────────────────┘              └────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### Go Policy Server

The Go binary (`agentsh`) runs the policy engine and API server:

- **Policy Engine** (`internal/policy/`) - Evaluates file, network, and command rules
- **Session Manager** (`internal/session/`) - Tracks agent sessions and workspaces
- **XPC Socket Server** (`internal/platform/darwin/xpc/`) - Handles policy queries from Swift

### XPC Service

The XPC Service (`com.agentsh.xpc`) bridges between Swift and Go:

- **PolicyBridge.swift** - Connects to Go server via Unix socket
- **XPCServiceDelegate.swift** - Handles XPC connection lifecycle
- **JSON Protocol** - Serializes policy requests/responses

### System Extension

The System Extension (`com.agentsh.sysext`) provides kernel-level interception:

#### ESFClient.swift

Handles Endpoint Security Framework events:

| Event Type | Mode | Purpose |
|------------|------|---------|
| `AUTH_OPEN` | Block | File access authorization |
| `AUTH_EXEC` | Block | Process execution authorization |
| `NOTIFY_FORK` | Observe | Process tree tracking |
| `NOTIFY_EXIT` | Observe | Process cleanup |
| `NOTIFY_WRITE` | Observe | Write auditing |
| `NOTIFY_CLOSE` | Observe | Close auditing |

**AUTH Mode:** Blocks the operation until policy decision received.
**NOTIFY Mode:** Observes the operation without blocking.

#### FilterDataProvider.swift

Network Extension for IP/port filtering:

- Intercepts TCP/UDP flows at the socket level
- Queries policy for each new connection
- Allows, blocks, or redirects based on policy

#### DNSProxyProvider.swift

Network Extension for DNS filtering:

- Intercepts all DNS queries
- Queries policy for domain allowlists
- Blocks or redirects disallowed domains

## Communication Flow

### File Access Request

```
1. User process attempts file open
   │
   ▼
2. ESF intercepts → AUTH_OPEN event
   │
   ▼
3. ESFClient receives event (with PID)
   │
   ├─► Copy es_message_t for async handling
   │
   ▼
4. XPC call to PolicyBridge
   │
   ▼
5. PolicyBridge queries Go server via Unix socket
   │
   ├─► JSON: {"type":"file","path":"/...","operation":"read","pid":1234}
   │
   ▼
6. Go Policy Engine evaluates rules
   │
   ├─► JSON: {"allow":true,"rule":"allow-workspace"}
   │
   ▼
7. Response flows back through XPC
   │
   ▼
8. ESFClient calls es_respond_auth_result()
   │
   ▼
9. File operation proceeds (or blocks)
```

### Session Tracking

The session tracker maps PIDs to agentsh sessions:

```
1. agentsh exec creates session
   │
   ├─► Registers shell PID with session ID
   │
   ▼
2. Shell spawns child process (fork)
   │
   ├─► NOTIFY_FORK captured by ESF
   │
   ▼
3. Session tracker records parent→child
   │
   ▼
4. Child makes file access
   │
   ├─► Policy query includes PID
   │
   ▼
5. SessionTracker.SessionForPID(pid)
   │
   ├─► Walks parent chain to find session
   │
   ▼
6. Policy evaluated in session context
```

## XPC Protocol

Messages use JSON over Unix socket:

### Request Types

```json
// File access
{"type": "file", "path": "/workspace/file.txt", "operation": "read", "pid": 1234}

// Network connection
{"type": "network", "ip": "1.2.3.4", "port": 443, "domain": "api.example.com", "pid": 1234}

// Command execution
{"type": "command", "path": "/bin/curl", "args": ["https://..."], "pid": 1234}

// Session lookup
{"type": "session", "pid": 1234}

// Event emission
{"type": "event", "event_data": "<base64>"}
```

### Response Format

```json
{"allow": true, "rule": "allow-workspace"}
{"allow": false, "rule": "deny-ssh", "message": "SSH keys access denied"}
{"allow": true, "session_id": "session-abc123"}
```

## Thread Safety

### ESF Message Handling

ESF events must be responded to synchronously, but policy queries are async:

```swift
// WRONG: es_message_t invalid after callback returns
es_respond_auth_result(client, event, ...)  // Crash!

// CORRECT: Copy message for async handling
guard let messageCopy = es_copy_message(event) else { ... }
// ... async XPC call ...
es_respond_auth_result(client, messageCopy, ...)
es_free_message(messageCopy)
```

### Session Tracker

Thread-safe with `sync.RWMutex`:

```go
type SessionTracker struct {
    mu            sync.RWMutex
    pidToSession  map[int32]string
    pidToParent   map[int32]int32
    sessionToPids map[string]map[int32]struct{}
}
```

### XPC Connections

XPC connections use serial dispatch queues for thread safety:

```swift
private let queue = DispatchQueue(label: "com.agentsh.xpc")

queue.sync {
    self.xpcProxy = connection.remoteObjectProxy as? AgentSHXPCProtocol
}
```

## Entitlements Required

### System Extension Entitlement

```xml
<key>com.apple.developer.system-extension.install</key>
<true/>
```

### Endpoint Security Entitlement

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

### Network Extension Entitlement

```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>content-filter-provider</string>
    <string>dns-proxy</string>
</array>
```

These entitlements must be provisioned by Apple for your Developer ID.

## Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| ESF event handling | 1-5ms | In-kernel, minimal overhead |
| XPC round-trip | 0.5-2ms | Local IPC |
| Policy lookup (cached) | <1ms | Go policy engine |
| Network filter | 0.1-0.5ms | Per-flow, not per-packet |
| DNS proxy | 1-5ms | Per-query |

**Target:** <10ms total latency for policy decisions.

## Graceful Fallback

At startup, the Go binary detects available enforcement mechanisms:

```go
// Check if ESF+NE is available
if sysext.IsAvailable() && sysext.IsApproved() {
    // Use ESF+NE for full enforcement
    startXPCServer()
} else if fusetAvailable() {
    // Fall back to FUSE-T
    mountFUSE()
} else {
    // Observation only
    startFSEvents()
}
```

## Deployment Checklist

1. [ ] Apple Developer Program membership active
2. [ ] ESF + NE entitlements provisioned
3. [ ] Code signing identity configured
4. [ ] App bundle built and signed
5. [ ] System Extension approved by user
6. [ ] Network Extension activated
7. [ ] Go server running and accepting XPC connections

## See Also

- [macOS Build Guide](macos-build.md) - Build instructions
- [Platform Comparison](platform-comparison.md) - Feature comparison
- [SECURITY.md](../SECURITY.md) - Security threat model
