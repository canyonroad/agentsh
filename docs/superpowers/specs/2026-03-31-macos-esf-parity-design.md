# macOS ESF & Network Extension Parity with Linux

## Goal

Bring macOS enforcement and auditing capabilities to parity with Linux using Endpoint Security Framework (ESF) for file/exec enforcement and Network Extension for network enforcement. Target use case: wrapping AI agents (Claude Code, Codex, OpenCode) locally on macOS with the same policy enforcement Linux provides via seccomp + eBPF.

## Architecture

Two enforcement pillars, session-scoped:

- **ESF** replaces Linux's seccomp (file ops, exec interception) and Landlock (path-based restrictions)
- **Network Extension** replaces Linux's eBPF (per-connection network policy) and transparent DNS proxy

Both use a **local policy cache** with Darwin notification-based invalidation, mirroring how Linux uses Landlock (static rules at exec time) and eBPF maps (kernel-side allow/deny lists) for fast-path decisions without userspace round-trips.

## Design

### 1. Local Policy Cache (SessionPolicyCache)

A per-session policy snapshot held in the SysExt process. Populated at session registration, updated on policy changes.

**Structure:**

```
SessionPolicyCache
  sessionID: String
  rootPID: pid_t
  version: UInt64
  sessionPIDs: Set<pid_t>         — maintained by existing NOTIFY_FORK/EXIT handlers

  fileRules: [FileRule]
    each: pathPattern, operations (read|write|create|delete|rename), action (allow|deny)

  networkRules: [NetworkRule]
    each: hostPattern, ports, protocol, action (allow|deny)

  dnsRules: [DNSRule]
    each: domainPattern, action (allow|deny|nxdomain)

  defaults: fileAction, networkAction, dnsAction (all default to allow)
```

**Concurrency:** Single `DispatchQueue` with barrier writes (concurrent reads, exclusive writes). `SessionPolicyCache` replaces ESFClient's existing `activeSessions: [pid_t: String]` dictionary and `sessionQueue` — the cache subsumes session membership tracking with the richer `sessionPIDs` set. ESFClient's `cacheQueue` (for audit tokens) and `clientQueue` remain unchanged.

**Lifecycle:**
- Created on `register_session` — SysExt calls `fetchPolicySnapshot` via XPC (which routes through `PolicyBridge` to the Go server's Unix socket)
- Updated on Darwin notification `ai.canyonroad.agentsh.policy-updated` — SysExt calls `fetchPolicySnapshot` via XPC, atomically replaces if version is higher
- Destroyed on `unregister_session`

All snapshot fetches go through the XPC protocol (`AgentshXPCProtocol.fetchPolicySnapshot`) and `PolicyBridge`, not direct socket access. This keeps the transport consistent with all other SysExt → Go communication.

**Version semantics:** Version is a per-session monotonic counter, initial value 1. On any policy change (file change, runtime update, Watchtower push), the Go server increments the version for ALL active sessions — it does not evaluate which sessions are affected. This is simple and correct; if the snapshot content is unchanged, the Swift side will receive an identical snapshot and the atomic replace is a no-op.

**Session PID tracking:** The cache's `sessionPIDs` set is populated by ESFClient's existing NOTIFY_FORK and NOTIFY_EXIT handlers. On fork: if parent PID is in a session's `sessionPIDs`, add child PID to the same set. On exit: remove PID. The root PID is added when the cache is created at session registration. This gives O(1) session membership lookups in AUTH handlers, avoiding the O(depth) ancestry walk that `ProcessHierarchy.getAncestors` performs. `ProcessHierarchy` remains as a fallback for processes that forked before the session was registered.

**Pattern matching:** All rules use glob patterns, matching the Go policy engine's existing glob syntax. File rules: `*` for single segment, `**` for recursive (e.g., `/home/user/project/**`). Network and DNS domain rules: `*.evil.com` matches `sub.evil.com` (the Go engine compiles these as `domainGlobs` via `g.Match(domain)`). IP rules use exact match. The cache must use the same glob matching algorithm as the Go engine to avoid decision divergence.

**Evaluation order (all AUTH handlers):**
1. PID in any session's `sessionPIDs`? No -> auto-allow
2. Match deny rules -> deny immediately
3. Match allow rules -> allow immediately
4. No match -> apply session default action (allow or deny). Only fall through to XPC round-trip if cache is stale (version mismatch detected) or if the decision type requires server-side logic (approve, redirect, soft_delete)

### 2. Cache Update Mechanism (Darwin Notification + Pull)

Go server posts `notify_post("ai.canyonroad.agentsh.policy-updated")` via cgo when:
- Policy file changes (already watched via fsnotify)
- Session policy updated at runtime
- Watchtower pushes new policy (future)

SysExt receives notification via Darwin notify API, calls `fetchPolicySnapshot(sessionID)` via XPC (routed through `PolicyBridge` to the Go server). If cached version matches, Go returns empty response (no-op).

**Go-side implementation:** `notify_post` is in `libSystem` — single cgo call, no extra linking. The Go server maintains a per-session version counter incremented on every policy change.

### 3. ESF File Enforcement (AUTH Handlers)

Four AUTH handlers, all following the same pattern: session check -> cache -> XPC fallback.

**AUTH_OPEN (existing, needs session scoping):**
Currently calls `checkFile(op: "read")` for every process without session awareness. Retrofit to follow the same evaluation order as all other AUTH handlers: (1) check `sessionPIDs` — not in session = auto-allow, (2) check cache deny/allow rules, (3) apply default, (4) XPC fallback only if cache stale.

**AUTH_CREATE (new — currently auto-allows):**
Session check -> cache -> `checkFile(op: "create")` via XPC.

Path extraction requires branching on `destination_type`:
- `ES_DESTINATION_TYPE_EXISTING_FILE`: read `destination.existing_file.pointee.path.data`
- `ES_DESTINATION_TYPE_NEW_PATH`: combine `destination.new_path.dir.pointee.path.data` + "/" + `destination.new_path.filename.data` to form the full path

**AUTH_UNLINK (new — currently auto-allows):**
Extract target path from `event.pointee.event.unlink.target.pointee.path.data`. Session check -> cache -> `checkFile(op: "delete")` via XPC.

**AUTH_RENAME (new — currently auto-allows):**
Extract source path from `event.pointee.event.rename.source.pointee.path.data`. Destination path extracted from `destination` union (same branching as AUTH_CREATE on `destination_type`). Rename is evaluated as two separate policy checks: `checkFile(path: source, op: "rename")` and `checkFile(path: dest, op: "create")`. If either is denied, deny the rename. This avoids adding a `dest_path` parameter to the existing `checkFile` interface — it reuses the current protocol with two calls. Cache evaluation checks both paths against deny rules. Session check -> cache (both paths) -> XPC fallback (two calls if needed).

All AUTH handlers use `es_retain_message` / `es_release_message` for async XPC callbacks, matching the existing AUTH_OPEN pattern.

### 4. ESF File Auditing (NOTIFY Handlers)

**NOTIFY_WRITE — remove subscription:**
Remove `ES_EVENT_TYPE_NOTIFY_WRITE` from the `notifyEvents` array in `ESFClient.start()`. NOTIFY_WRITE fires on every write syscall and is extremely high-volume. Instead, rely on NOTIFY_CLOSE with the `modified` flag for file-write auditing. This matches the practical audit granularity on Linux (seccomp emits on close, not per-write). Removing the subscription avoids ESF overhead entirely.

**NOTIFY_CLOSE (new — currently empty):**
Extract path from `event.event.close.target.pointee.path.data`. The `modified` flag indicates whether the file was written. Only emit events for `modified == true`. Event type: `"file_write"` (consistent with Linux's file_modified event).

**NOTIFY_SETATTR (new subscription):**
Add `ES_EVENT_TYPE_NOTIFY_SETATTR` to the `notifyEvents` array in `ESFClient.start()` (alongside the existing NOTIFY_CLOSE/EXIT/FORK subscriptions — all are passed in a single `es_subscribe` call). Add `case ES_EVENT_TYPE_NOTIFY_SETATTR` to the `handleEvent` switch statement, routing to a new `handleNotifySetattr` method. Emit event with operation `"chmod"` or `"chown"` based on which attribute changed. Matches Linux's optional `intercept_metadata` seccomp config.

**Event emission path:** Swift encodes a structured JSON payload and sends via existing `xpcProxy.emitEvent(event:reply:)`. The JSON schema for the event `Data`:

```json
{
  "type": "file_write",
  "path": "/home/user/project/file.txt",
  "operation": "close_modified",
  "pid": 1234,
  "session_id": "session-abc",
  "timestamp": "2026-03-31T10:00:00Z"
}
```

Valid types: `file_write` (CLOSE with modified), `file_chmod`, `file_chown`. The Go handler decodes this JSON from the base64 `EventData`, maps it to `types.Event` with source `"esf"`, and calls `EventStore.AppendEvent()` and `Broker.Publish()`.

### 5. Exec Depth Tracking

Add `execDepths: [pid_t: Int]` dictionary to ESFClient, keyed by PID (not session). Synchronized via the `SessionPolicyCache`'s dispatch queue (shared with `sessionPIDs` to avoid ordering issues during cleanup). On AUTH_EXEC within a session:
- Look up parent PID's depth, set child's depth = parent + 1
- Pass depth in `checkExecPipeline` (new field on the XPC request)
- Matches Linux's per-process seccomp exec depth tracking

Depth entries are cleaned up on NOTIFY_EXIT (same lifecycle as `auditTokenCache`). Session unregister iterates the session's `sessionPIDs` and removes each from `execDepths`.

### 6. Network Extension Session Scoping

**FilterDataProvider changes:**

Current: calls `checkNetworkPNACL()` for every flow regardless of session.

New flow:
1. Extract PID from `sourceAppAuditToken` (already done)
2. Check PID against all active sessions' `sessionPIDs` — not in session -> `.allow()` immediately
3. Resolve sessionID from cache
4. Check network rules in cache -> hit -> allow/drop immediately
5. Cache miss -> `checkNetworkPNACL()` with sessionID (new parameter)

FilterDataProvider runs in the same SysExt process as ESFClient, so it reads the `SessionPolicyCache` directly — no extra IPC.

**XPC protocol change:** Add `sessionID` parameter to `checkNetworkPNACL` in `AgentshXPCProtocol`. This requires changes to:
- `xpcProtocol.swift` — add parameter to protocol method signature
- `PolicyBridge.swift` — add `session_id` to the request dictionary, pass through from caller
- `FilterDataProvider.swift` — pass resolved sessionID from cache lookup
- Go `PNACLCheckRequest` struct — add `SessionID string` field
- Go `PNACLHandler.CheckNetwork` interface — add sessionID parameter (all implementations must update)

### 7. DNS Filtering

**DNSProxyProvider changes:**

Current: passthrough — reads datagrams, writes them back unchanged.

New flow:
1. Parse incoming UDP datagram as DNS wire format (header 12 bytes + question section QNAME/QTYPE)
2. Extract queried domain name from QNAME
3. Check domain against union of all active sessions' DNS deny rules
4. Deny match -> synthesize response: copy query ID, set QR=1 (response), RCODE=3 (NXDOMAIN), write back to flow
5. Allow -> write datagram to original endpoint (the NEDNSProxyProvider framework handles the actual upstream forwarding — the provider writes to the flow's remote endpoint and reads the response back via the same `readDatagrams` loop)
6. No match in cache -> apply default DNS action. If default is deny, synthesize NXDOMAIN. If default is allow, forward unchanged. XPC round-trip only if cache is stale.

**Session scoping:** DNS flows (`NEAppProxyUDPFlow`) do not carry audit tokens for source process identification. All DNS queries are filtered against the union of all active sessions' DNS rules. If no sessions are active, passthrough. For conflicting defaults across sessions (e.g., session A has `dnsAction: allow`, session B has `dnsAction: deny`), strictest wins — deny if any active session has a deny default. This is acceptable because DNS volume is low and session-scoped deny lists are typically small.

### 8. Go-Side Changes

**New XPC request type: `fetch_policy_snapshot`**

Request: `{"type": "fetch_policy_snapshot", "session_id": "...", "version": 41}`
Response: Full snapshot JSON (file_rules, network_rules, dns_rules, defaults, version) or empty if version matches.

The Go server builds this via a new `BuildPolicySnapshot(sessionID)` method on `PolicyAdapter`, which reads from the existing `policy.Engine` and flattens matching rules into the cache format. The full policy tree stays on the Go side; the cache is a fast-path subset. The XPC server routes `fetch_policy_snapshot` requests to this method.

**New request type constant** in `protocol.go`: `RequestTypeFetchPolicySnapshot = "fetch_policy_snapshot"`

**Darwin notification posting:** Add `notify_post` cgo wrapper. Called from policy watcher when rules change.

**Protocol extension:** Add `SessionID string` to `PNACLCheckRequest`.

**Event handling for NOTIFY emissions:** The `emitEvent` XPC path exists but the Go handler is currently a no-op (acknowledges but discards the payload). The handler in `server.go` needs to:
1. Decode `EventData` from base64 into a JSON event payload
2. Construct `types.Event` with source `"esf"`, appropriate type (`"file_write"`, `"file_close"`, `"file_chmod"`), session ID, PID, and path
3. Obtain `EventStore` and `Broker` references (passed to the handler at server construction, same pattern as `PolicyHandler`)
4. Call `EventStore.AppendEvent(ctx, event)` for persistent storage
5. Call `Broker.Publish(event)` for real-time subscribers

This requires adding `EventStore` and `Broker` fields to the XPC server (or to a new `EventHandler` interface) and wiring them in during platform initialization.

## Files to Modify

**Swift (SysExt):**
- `ESFClient.swift` — AUTH handler wiring, NOTIFY event emission, cache evaluation, depth tracking, new SETATTR subscription
- `DNSProxyProvider.swift` — DNS wire format parsing, policy check, NXDOMAIN synthesis
- `FilterDataProvider.swift` — session scoping, cache-based fast path, sessionID in PNACL check

**Swift (new file):**
- `SessionPolicyCache.swift` — cache data structure, pattern matching, Darwin notification listener, snapshot fetch

**Swift (XPC protocol):**
- `xpc/xpcProtocol.swift` — add `fetchPolicySnapshot` method, add sessionID to `checkNetworkPNACL`
- `xpc/PolicyBridge.swift` — implement `fetchPolicySnapshot`, add sessionID to `checkNetworkPNACL` request dict

**Go (XPC):**
- `internal/platform/darwin/xpc/protocol.go` — new request type, SessionID on PNACLCheckRequest
- `internal/platform/darwin/xpc/handler.go` — handle `fetch_policy_snapshot`, handle `emitEvent` payload decoding
- `internal/platform/darwin/xpc/server.go` — route new request type

**Go (platform):**
- `internal/platform/darwin/notify.go` (new) — cgo wrapper for `notify_post`
- `internal/platform/darwin/es_exec.go` — pass depth field through exec pipeline

**Xcode project:**
- `agentsh.xcodeproj/project.pbxproj` — add `SessionPolicyCache.swift` to SysExt Sources

## What This Does NOT Cover

- **Resource limits** (cgroups equivalent) — macOS has no kernel mechanism for this. `setrlimit` provides basic per-process limits but no CPU/memory/IO throttling.
- **Namespace isolation** — macOS has no equivalent. `sandbox-exec` is deprecated and weaker than Linux namespaces.
- **FUSE-T** — no longer needed at Enterprise tier since ESF provides file enforcement directly.
- **Watchtower push protocol** — future work; the Darwin notification mechanism is designed to support it but the push channel itself is out of scope.

## Security Considerations

- **Darwin notification spoofing:** Any process can post `notify_post`. This is acceptable because the notification is only a signal — the actual policy data is fetched over the trusted Unix socket. A spoofed notification causes an unnecessary fetch, not a policy bypass.
- **Cache staleness window:** Between policy change and notification receipt, the cache may serve stale decisions. For the `allow` default case, this means a briefly-allowed operation that should have been denied. The window is sub-millisecond in practice (Darwin notifications are delivered synchronously within the process).
- **NOTIFY_WRITE volume:** Addressed by not subscribing to NOTIFY_WRITE. File write auditing uses NOTIFY_CLOSE with `modified == true` only.
- **AUTH event deadlines:** ESF imposes a deadline on AUTH event responses (default ~60s, varies by event type). The cache fast-path responds in microseconds. The XPC fallback path uses `PolicyBridge.timeout` of 5 seconds, well within ESF's deadline. If the Go server is unreachable, `PolicyBridge` returns a fail-open/fail-closed response within the timeout — never blocks indefinitely.
- **Notification constant:** The Darwin notification name `ai.canyonroad.agentsh.policy-updated` must be defined as a shared constant in both Swift (`SessionPolicyCache.swift`) and Go (`notify.go`) to prevent typos.
