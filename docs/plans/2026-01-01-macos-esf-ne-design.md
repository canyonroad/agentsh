# macOS ESF + Network Extension Design

**Status:** Approved
**Created:** 2026-01-01
**Author:** Claude + Eran

## Overview

This document describes the architecture for implementing Apple's Endpoint Security Framework (ESF) and Network Extension (NE) on macOS. This provides the highest security tier (`TierEnterprise`, 95% security score) with system-wide visibility and blocking capabilities.

## Goals

- **Replace FUSE-T when entitled**: ESF becomes preferred file interception when Apple entitlements are present
- **Graceful fallback**: Automatically fall back to FUSE-T (`TierFull`) if entitlements are missing
- **Hybrid AUTH/NOTIFY**: Use AUTH for blocking, NOTIFY for high-volume observation
- **Minimal latency**: Target <10ms policy decision time

## Requirements

### Entitlements

| Entitlement | Purpose | Apple Approval |
|-------------|---------|----------------|
| `com.apple.developer.endpoint-security.client` | ESF client for file/process monitoring | **Required** - submit business justification |
| `com.apple.developer.networking.networkextension` | Network Extension for traffic filtering | **Not required** - standard capability since Nov 2016 |

**Note:** For Developer ID distribution, use the `-systemextension` suffix values for Network Extension entitlements (e.g., `content-filter-provider-systemextension`).

### Runtime Requirements

- macOS 11.0+ (Big Sur or later)
- System Extension approval from user (one-time)
- Notarized and signed app bundle

## Architecture Overview

The ESF/NE implementation adds a System Extension that runs as a separate privileged process, communicating with the agentsh server via XPC.

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgentSH.app bundle                       │
├─────────────────────────────────────────────────────────────────┤
│  Contents/                                                       │
│  ├── MacOS/                                                      │
│  │   └── agentsh              ← Main CLI binary (Go)            │
│  ├── Library/SystemExtensions/                                   │
│  │   └── com.agentsh.sysext.systemextension/                    │
│  │       └── Contents/MacOS/                                     │
│  │           └── com.agentsh.sysext  ← ESF + NE extension       │
│  ├── XPCServices/                                                │
│  │   └── com.agentsh.xpc.xpc  ← XPC bridge service              │
│  └── Info.plist                                                  │
└─────────────────────────────────────────────────────────────────┘
         │
         │ symlink
         ▼
/usr/local/bin/agentsh
```

### Component Responsibilities

| Component | Language | Role |
|-----------|----------|------|
| `agentsh` CLI | Go | Server, session management, policy engine (unchanged) |
| System Extension | Swift | ESF client + NE providers, runs with elevated privileges |
| XPC Service | Swift | Bridges CLI ↔ System Extension, handles policy queries |

### Flow

1. System Extension intercepts file/network/process operations
2. Extension queries policy via XPC
3. XPC service forwards to Go policy engine via Unix socket
4. Policy engine evaluates and returns decision
5. Extension allows/denies the operation

## Endpoint Security Framework (ESF) Component

The ESF component subscribes to file and process events, using AUTH for blocking and NOTIFY for observation.

### Event Subscriptions

| Event Type | Mode | Purpose |
|------------|------|---------|
| `ES_EVENT_TYPE_AUTH_OPEN` | AUTH | Block/allow file opens based on policy |
| `ES_EVENT_TYPE_AUTH_CREATE` | AUTH | Block file/directory creation |
| `ES_EVENT_TYPE_AUTH_UNLINK` | AUTH | Block file deletion (or redirect to soft-delete) |
| `ES_EVENT_TYPE_AUTH_RENAME` | AUTH | Block file moves |
| `ES_EVENT_TYPE_AUTH_EXEC` | AUTH | Block command execution |
| `ES_EVENT_TYPE_NOTIFY_WRITE` | NOTIFY | Log write completions (high volume) |
| `ES_EVENT_TYPE_NOTIFY_CLOSE` | NOTIFY | Log file close with write flag |
| `ES_EVENT_TYPE_NOTIFY_EXIT` | NOTIFY | Log process exits |

### Decision Flow

```
ESF Event → Extract path/process info → XPC query to agentsh
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    ▼                                                   ▼
              policy.CheckFile()                              policy.CheckCommand()
                    │                                                   │
                    └─────────────────────────┬─────────────────────────┘
                                              ▼
                                    Decision (allow/deny/approve)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            ES_AUTH_RESULT_ALLOW    ES_AUTH_RESULT_DENY         Hold for approval
                                                                (with deadline)
```

### Session Scoping

ESF sees all system events. The extension filters by checking if the process belongs to an active agentsh session. Non-session processes are allowed through immediately (no policy check).

## Network Extension (NE) Component

The NE component uses two providers: DNS Proxy for domain-based filtering and Content Filter for connection-level control.

### NEDNSProxyProvider

Intercepts all DNS queries for domain-based policy enforcement.

```
DNS Query → Extract domain → XPC query to agentsh
                                    │
                          policy.CheckNetwork(domain, 53)
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
                 Allow          Deny            Redirect
                    │               │               │
            Forward to       Return NXDOMAIN   Return custom
            upstream DNS     or REFUSED        IP (sinkhole)
```

### NEFilterDataProvider

Intercepts at the flow/socket level, filtering by IP address and port regardless of whether DNS was used.

| Hook | Purpose |
|------|---------|
| `handleNewFlow()` | First packet - check destination IP/port against policy |
| `handleInboundData()` | Inspect incoming payload (optional deep inspection) |
| `handleOutboundData()` | Inspect outgoing payload (optional deep inspection) |

### Flow Verdict Mapping

| Policy Decision | NE Verdict |
|-----------------|------------|
| `allow` | `.allow()` |
| `deny` | `.drop()` |
| `approve` | `.pause()` → wait for XPC approval → `.allow()` or `.drop()` |
| `audit` | `.allow()` + emit event |

### Direct IP Access

The Content Filter operates at the IP level, so direct IP connections (without DNS) are always filtered. Policy rules with CIDRs apply:

```yaml
network_rules:
  - name: block-external-direct
    cidrs:
      - "0.0.0.0/0"
    decision: deny

  - name: allow-internal
    cidrs:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    decision: allow
```

## XPC Communication Layer

XPC bridges the Swift System Extension and the Go agentsh server. Since Go can't directly use XPC, we use a small Swift XPC service that communicates with Go via a Unix socket.

### Architecture

```
┌──────────────────────┐     XPC      ┌──────────────────────┐
│   System Extension   │◄────────────►│    XPC Service       │
│   (Swift, ESF+NE)    │              │    (Swift, bridge)   │
└──────────────────────┘              └──────────┬───────────┘
                                                 │ Unix Socket
                                                 │ (JSON messages)
                                      ┌──────────▼───────────┐
                                      │   agentsh server     │
                                      │   (Go, policy engine)│
                                      └──────────────────────┘
```

### XPC Protocol (Swift)

```swift
@objc protocol AgentshXPCProtocol {
    func checkFile(path: String, operation: String, pid: pid_t,
                   sessionID: String?, reply: @escaping (Bool, String?) -> Void)

    func checkNetwork(ip: String, port: Int, domain: String?, pid: pid_t,
                      sessionID: String?, reply: @escaping (Bool, String?) -> Void)

    func checkCommand(executable: String, args: [String], pid: pid_t,
                      sessionID: String?, reply: @escaping (Bool, String?) -> Void)

    func resolveSession(pid: pid_t, reply: @escaping (String?) -> Void)

    func emitEvent(event: Data, reply: @escaping (Bool) -> Void)
}
```

### Go Socket Server

New endpoint for policy queries from XPC service:

| Endpoint | Purpose |
|----------|---------|
| `/var/run/agentsh/policy.sock` | Policy queries from XPC service |
| Request format | JSON: `{"type":"file","path":"/x","op":"read","pid":123}` |
| Response format | JSON: `{"allow":true,"rule":"allow-workspace"}` |

### Latency Budget

- ESF AUTH deadline: ~60s
- Target response time: <10ms
- Unix socket overhead: ~0.1ms
- Policy evaluation: <1ms

## Session Scoping and Process Tracking

The System Extension sees all system events but must only enforce policy on processes within agentsh sessions.

### Process Tree Tracking

```
Session created (workspace=/Users/dev/project)
    │
    └── agentsh exec $SID -- zsh
            │ pid=1234, tracked
            │
            ├── zsh (child)
            │   │ pid=1235, inherit session
            │   │
            │   ├── git status
            │   │   pid=1236, inherit session
            │   │
            │   └── npm install
            │       pid=1237, inherit session
            │       │
            │       └── node
            │           pid=1238, inherit session
```

### Tracking Mechanism

| Method | How it works |
|--------|--------------|
| Process tree | Track `fork()`/`exec()` via ESF NOTIFY events, maintain parent→child map |
| Audit token | Each process has unique audit token, cached in session→tokens map |
| Environment marker | Child processes inherit `AGENTSH_SESSION_ID` env var (backup check) |

### Lookup Flow

```
Event arrives (pid=1238)
    │
    ▼
Check audit token cache ──found──► Return session ID
    │
    not found
    │
    ▼
Walk parent chain (ppid lookup) ──found parent in cache──► Add to cache, return session ID
    │
    not found
    │
    ▼
Not an agentsh process → Allow immediately (no policy check)
```

### Performance

- Cache lookup: O(1)
- Parent walk: rare (only for new processes), limited to ~10 levels
- Non-session processes: bypass policy entirely

## Error Handling and Failure Modes

The System Extension must handle failures gracefully without blocking the system.

### XPC Communication Failures

| Failure | Behavior | Rationale |
|---------|----------|-----------|
| XPC service unreachable | Allow + log warning | Fail-open prevents system lockup |
| Socket timeout (>5s) | Allow + log error | ESF deadline is 60s, but UX matters |
| Malformed response | Allow + log error | Don't block on bugs |
| agentsh server not running | Allow all + periodic retry | Extension survives server restarts |

### ESF-Specific Errors

| Failure | Behavior |
|---------|----------|
| `es_respond_auth_result` deadline missed | macOS auto-allows (we log this) |
| Too many pending AUTH events | Start allowing oldest to drain queue |
| `es_new_client` fails | Fall back to FUSE-T tier |
| Mute/unmute path fails | Log and continue |

### Network Extension Errors

| Failure | Behavior |
|---------|----------|
| DNS upstream unreachable | Return SERVFAIL |
| Filter verdict timeout | `.allow()` to prevent hang |
| Extension crash | macOS restarts automatically |

### Recovery and Health

```
┌─────────────────────────────────────────────────────────┐
│ Extension Health Monitor (runs every 30s)               │
├─────────────────────────────────────────────────────────┤
│ 1. Ping XPC service                                     │
│ 2. Check pending AUTH queue depth                       │
│ 3. Verify session cache isn't stale                     │
│ 4. Report metrics to agentsh server                     │
│ 5. If unhealthy for 5min → restart extension            │
└─────────────────────────────────────────────────────────┘
```

### Fail-Open vs Fail-Closed

Default: **Fail-open** for availability, log everything for forensics.

Security-critical environments can configure fail-closed via policy:

```yaml
esf:
  fail_mode: closed  # deny on communication failure
```

## Build and Packaging

### Directory Structure

```
build/
├── AgentSH.app/
│   └── Contents/
│       ├── Info.plist
│       ├── MacOS/
│       │   └── agentsh                 ← Go binary (main CLI)
│       ├── Library/
│       │   └── SystemExtensions/
│       │       └── com.agentsh.sysext.systemextension/
│       │           └── Contents/
│       │               ├── Info.plist
│       │               └── MacOS/
│       │                   └── com.agentsh.sysext   ← Swift binary
│       ├── XPCServices/
│       │   └── com.agentsh.xpc.xpc/
│       │       └── Contents/
│       │           ├── Info.plist
│       │           └── MacOS/
│       │               └── com.agentsh.xpc         ← Swift XPC bridge
│       └── Resources/
│           └── embedded.provisionprofile
└── pkg/
    └── AgentSH-1.0.0.pkg               ← Installer package
```

### Build Steps

| Step | Tool | Output |
|------|------|--------|
| 1. Build Go CLI | `go build` | `agentsh` binary |
| 2. Build Swift extension | `xcodebuild` | `com.agentsh.sysext` |
| 3. Build Swift XPC service | `xcodebuild` | `com.agentsh.xpc` |
| 4. Assemble bundle | shell script | `AgentSH.app` |
| 5. Sign extension | `codesign` | Signed with entitlements |
| 6. Sign app | `codesign` | Signed bundle |
| 7. Notarize | `notarytool` | Apple-approved |
| 8. Package installer | `pkgbuild` | `.pkg` for distribution |

### Makefile Target

```makefile
build-macos-enterprise: build-go build-swift assemble sign notarize package
```

### Non-Entitled Builds

When building without Apple entitlements, skip Swift components. The CLI detects missing extension and falls back to FUSE-T automatically.

## Testing Strategy

### Layer 1: Unit Tests (no entitlements needed)

| Component | Test approach |
|-----------|---------------|
| XPC protocol parsing | Mock XPC messages, verify serialization |
| Policy bridge logic | Mock policy engine responses |
| Session cache | Test lookup, expiry, parent-walk logic |
| Event filtering | Test session scoping decisions |

### Layer 2: Integration Tests with Mocks

```
┌─────────────────┐      ┌─────────────────┐
│  Test harness   │─────►│  Mock ESF API   │
│  (Swift)        │      │  (sends fake    │
│                 │◄─────│   events)       │
└────────┬────────┘      └─────────────────┘
         │
         ▼
┌─────────────────┐
│  Real XPC +     │
│  Real Go server │
└─────────────────┘
```

### Layer 3: Entitled Integration Tests

| Requirement | Solution |
|-------------|----------|
| Apple entitlements | Separate CI pipeline with signing certs |
| System Extension approval | Use `systemextensionsctl developer on` in test VM |
| Clean state | Fresh macOS VM per test run |
| Test isolation | Dedicated test user account |

### Layer 4: Manual Smoke Tests

```bash
# Extension activation
agentsh sysext install
agentsh sysext status

# File blocking
agentsh session create --workspace /tmp/test
echo "test" > /tmp/test/blocked.txt  # Should be denied by policy

# Network blocking
curl http://blocked-domain.com  # Should fail
```

### Test Matrix

| Scenario | Expected behavior |
|----------|-------------------|
| Entitled + extension active | ESF/NE enforcement |
| Entitled + extension missing | Fallback to FUSE-T |
| No entitlements | FUSE-T only (no extension attempt) |
| Extension crash | Auto-restart, brief allow-all window |

## File Structure (Implementation)

```
internal/platform/darwin/
├── esf/
│   ├── client.swift          # ESF client setup and event handling
│   ├── events.swift          # Event type definitions
│   └── mute.swift            # Path muting for performance
├── ne/
│   ├── dns_provider.swift    # NEDNSProxyProvider implementation
│   ├── filter_provider.swift # NEFilterDataProvider implementation
│   └── extension.swift       # System Extension entry point
├── xpc/
│   ├── protocol.swift        # XPC protocol definition
│   ├── service.swift         # XPC service implementation
│   └── bridge.go             # Go-side Unix socket handler
├── session_tracker.swift     # Process tree tracking
└── sysext.go                 # Go CLI commands for extension management
```

## CLI Commands

```bash
# Install/uninstall System Extension
agentsh sysext install      # Request user approval, activate extension
agentsh sysext uninstall    # Deactivate and remove extension
agentsh sysext status       # Show extension state and health

# Included in existing commands
agentsh server              # Starts policy socket for XPC
agentsh session create      # Extension auto-scopes new session
```

## Security Considerations

1. **XPC validation**: Extension validates XPC connection is from signed agentsh binary
2. **Socket permissions**: `/var/run/agentsh/policy.sock` restricted to root
3. **No secrets in extension**: All policy logic in Go; extension only asks yes/no
4. **Audit logging**: All decisions logged regardless of allow/deny
5. **Entitlement scope**: Request minimal entitlements needed

## Future Enhancements

1. **TCC integration**: Query Transparency, Consent, and Control for additional context
2. **Per-app rules**: Network Extension can filter by app bundle ID
3. **Kernel event correlation**: Combine ESF events with dtrace for deeper visibility
4. **Remote policy**: Extension could cache policy for offline enforcement

## Changelog

| Date | Change |
|------|--------|
| 2026-01-01 | Initial design document |
