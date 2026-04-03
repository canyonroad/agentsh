# macOS ESF+NE Architecture

> **Alpha Status:** The ESF+NE implementation is in active development and should be considered Alpha-quality. The architecture described here is functional end-to-end but expect rough edges, manual setup steps, and breaking changes between releases.

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
│  │  │              (ai.canyonroad.agentsh.sysext)                          │  │ │
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

The XPC Service (`ai.canyonroad.agentsh.xpc`) bridges between Swift and Go:

- **PolicyBridge.swift** - Connects to Go server via Unix socket
- **XPCServiceDelegate.swift** - Handles XPC connection lifecycle
- **JSON Protocol** - Serializes policy requests/responses

### System Extension

The System Extension (`ai.canyonroad.agentsh.sysext`) provides kernel-level interception:

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
private let queue = DispatchQueue(label: "ai.canyonroad.agentsh.xpc")

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

### Endpoint Security Entitlement (Requires Apple Approval)

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

**Note:** ESF requires Apple approval. Submit a business justification via the Apple Developer Portal.

### Network Extension Entitlement (Standard Capability)

```xml
<key>com.apple.developer.networking.networkextension</key>
<array>
    <string>content-filter-provider-systemextension</string>
    <string>dns-proxy-systemextension</string>
</array>
```

**Note:** Network Extension is a standard capability since November 2016. Enable in Xcode Signing & Capabilities - no Apple approval needed. Use the `-systemextension` suffix values for Developer ID distribution.

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
    startPolicySocketServer()
} else {
    // Observation only
    startFSEvents()
}
```

## Deployment Checklist

1. [ ] Apple Developer Program membership active
2. [ ] ESF entitlement approved by Apple (submit business justification)
3. [ ] Network Extension capability enabled in Xcode (standard, no approval needed)
4. [ ] Code signing identity configured
5. [ ] App bundle built and signed
6. [ ] System Extension approved by user
7. [ ] Network Extension activated
8. [ ] Go server running and accepting XPC connections

## Event Stream

In addition to the request-response connection used for policy queries, the system extension maintains a persistent **event stream** connection to the Go server. This stream delivers file and process events for audit, attribution, and real-time monitoring.

### Connection Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                  System Extension (Swift)                            │
│                                                                      │
│  PolicySocketClient                                                  │
│  ┌──────────────────────────┐  ┌──────────────────────────────────┐ │
│  │  Request-Response Conn   │  │  Event Stream Conn (persistent)  │ │
│  │  (short-lived per query) │  │  (fire-and-forget, one-way)      │ │
│  │                          │  │                                   │ │
│  │  file/command/network    │  │  file_event, process_fork,       │ │
│  │  policy queries          │  │  process_exit notifications      │ │
│  └────────────┬─────────────┘  └──────────────┬───────────────────┘ │
│               │                                │                     │
└───────────────┼────────────────────────────────┼─────────────────────┘
                │                                │
    ────────────┼────────────────────────────────┼─── Unix Socket ───
                │  /tmp/agentsh-policy.sock      │
                ▼                                ▼
┌───────────────┼────────────────────────────────┼─────────────────────┐
│               │                                │                     │
│  ┌────────────┴─────────────┐  ┌──────────────┴───────────────────┐ │
│  │  handlePolicyQuery()     │  │  handleEventStream()             │ │
│  │  (per-request goroutine) │  │  (long-lived goroutine)          │ │
│  └──────────────────────────┘  └──────────────┬───────────────────┘ │
│                                                │                     │
│                                                ▼                     │
│                                   ┌────────────────────────┐        │
│                                   │  ESFEventHandler       │        │
│                                   │  .HandleESFEvent()     │        │
│                                   └────────────┬───────────┘        │
│                                                │                     │
│                              ┌─────────────────┼──────────────┐     │
│                              ▼                 ▼              ▼     │
│                   ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│                   │ Command      │  │ Session      │  │ Event    │ │
│                   │ Resolver     │  │ Tracker      │  │ Store    │ │
│                   │ PID→cmd_id   │  │ PID→sess_id  │  │ (SQLite) │ │
│                   └──────────────┘  └──────────────┘  └──────────┘ │
│                                                                      │
│                         Go Policy Server (policysock)                │
└─────────────────────────────────────────────────────────────────────┘
```

### Two Connection Types

1. **Request-response** (existing): Short-lived connections for policy queries. The Swift client sends a JSON request (file, command, or network query), the Go server evaluates policy and responds with allow/deny. One connection per query.

2. **Event stream** (persistent): A long-lived connection for delivering events. The client writes newline-delimited JSON events in one direction (fire-and-forget). The server reads and processes them but does not send responses per event.

### Event Stream Lifecycle

1. The Swift `PolicySocketClient` connects to `/tmp/agentsh-policy.sock`
2. Client sends `{"type":"event_stream_init"}` to identify this as an event stream connection
3. Server acknowledges with `{"status":"ok"}`
4. Client writes events as newline-delimited JSON, one event per line:
   ```json
   {"type":"file_event","event_type":"file_open","path":"/workspace/main.go","pid":1234,"access":"read","timestamp":"..."}\n
   {"type":"file_event","event_type":"file_create","path":"/workspace/out.bin","pid":1234,"timestamp":"..."}\n
   {"type":"file_event","event_type":"file_delete","path":"/workspace/tmp.log","pid":1235,"timestamp":"..."}\n
   ```
5. Events flow one-directionally from Swift to Go (fire-and-forget)

### Ring Buffer and Reconnection

When the event stream connection is unavailable, events are buffered in a ring buffer:

- **Buffer size:** 1024 events maximum
- **Overflow policy:** Drop-oldest -- when the buffer is full, the oldest event is discarded to make room for the newest
- **Reconnection:** Exponential backoff starting at 1 second, doubling on each failed attempt, capped at 30 seconds maximum
- **On reconnect:** Buffered events are drained and sent before new events

### ESF Event Types

The system extension subscribes to the following ESF events for file I/O monitoring:

| ESF Event | agentsh Event Type | Mode | Description |
|-----------|-------------------|------|-------------|
| `AUTH_OPEN` | `file_open` | AUTH | File open with read/write determined from fflag |
| `AUTH_CREATE` | `file_create` | AUTH | New file creation |
| `AUTH_UNLINK` | `file_delete` | AUTH | File deletion |
| `AUTH_RENAME` | `file_rename` | AUTH | File rename (includes destination path as path2) |
| `NOTIFY_CLOSE` (modified) | `file_write` | NOTIFY | File write (detected on close when file was modified) |
| `NOTIFY_FORK` | `process_fork` | NOTIFY | Process fork (for command_id propagation) |
| `NOTIFY_EXIT` | `process_exit` | NOTIFY | Process exit (cleanup) |
| `NOTIFY_SETATTRLIST` | `file_chmod` / `file_chown` | NOTIFY | Attribute changes (macOS 26+) |

### Event Processing Pipeline

Events flow through the following pipeline on the Go server side:

1. **policysock.Server.handleEventStream()** -- reads newline-delimited JSON from the event stream connection
2. **ESFEventHandler.HandleESFEvent()** -- processes each raw event, enriching it with session and command context
3. **CommandResolver** -- maps PID to `command_id`. PIDs are registered when exec starts. Fork events propagate the parent's `command_id` to the child PID. Exit events clean up the mapping.
4. **SessionTracker** -- maps PID to `session_id` by walking the process parent chain
5. The enriched event is built as a `types.Event` and stored in the **SQLite event store**

### PID-to-Command Resolution

The Go server maintains a `CommandResolver` that tracks the relationship between PIDs and command IDs:

- **Registration:** When a command execution starts (via `agentsh exec`), the PID is registered with its `command_id`
- **Fork propagation:** When `NOTIFY_FORK` is received, the parent's `command_id` is copied to the child PID. This ensures subprocesses inherit attribution.
- **Exit cleanup:** When `NOTIFY_EXIT` is received, the PID entry is removed from the resolver to prevent stale mappings
- **Lookup:** For every file event, the resolver is queried with the event's PID to attach the correct `command_id`

## See Also

- [macOS Build Guide](macos-build.md) - Build instructions
- [Platform Comparison](platform-comparison.md) - Feature comparison
- [SECURITY.md](../SECURITY.md) - Security threat model
