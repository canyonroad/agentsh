# ESF AUTH Local Evaluation Design

## Problem

The macOS system extension (SysExt) crashes within seconds of receiving Full Disk Access, causing the system to grind to a halt. Every crash report shows the same termination reason: "EndpointSecurity client terminated because it failed to respond to a message before its deadline."

Root causes:

1. **Dead XPC Service.** The SysExt connects to `ai.canyonroad.agentsh.xpc`, an XPC Service embedded in the app bundle. System extensions run as separate processes in `/Library/SystemExtensions/` and cannot reach app-embedded XPC Services. Every XPC call goes into a dead connection.

2. **AUTH events go unanswered.** When AUTH handlers hit the `.fallthrough_` path (file rules) or the `checkExecPipeline` path (exec), they retain the AUTH message, send an XPC call, and wait for a completion handler. The completion handler never fires because the XPC service is dead. The retained AUTH message never gets a response. The process that triggered the operation blocks. After the deadline, endpointsecurityd kills the extension.

3. **Unsafe callback design.** The `es_new_client` callback uses `[weak self]` and discards the client pointer parameter (`_`). If `self` is nil, `self?.handleEvent(event)` is a no-op — the AUTH event is silently dropped without a response. The `guard let client = client else { return }` at the top of each AUTH handler has the same problem: returns without responding.

4. **Crash-respawn death spiral.** The extension crashes, launchd respawns it, it subscribes to AUTH events again, fails to respond again, crashes again. During each cycle, all system processes are blocked waiting for AUTH responses that never come, causing the system to alternate between frozen and briefly responsive.

## Design

### Core Principle

AUTH handlers never do IPC. They evaluate from in-process cached policy rules and always respond synchronously. The Go server pushes policy rules to the SysExt asynchronously ahead of time; AUTH handlers only read from the local cache.

### Approach: Local-Only AUTH with Async IPC

- All AUTH decisions (allow, deny, redirect-deny) are made locally from `SessionPolicyCache`
- A new `PolicySocketClient` connects directly to the Go server's Unix socket (`/var/run/agentsh/policy.sock`) for async operations only
- The dead XPC Service is bypassed entirely
- Session registration uses Darwin notifications (signal) + socket (data pull)

## Component Design

### 1. AUTH Event Handler Safety

**Use the ES callback's client pointer.** The `es_new_client` callback receives the ES client pointer as its first argument. Use it directly instead of reading `self.client`:

```swift
es_new_client(&newClient) { client, event in
    handleESEvent(client: client, event: event)
}
```

**Make the AUTH fast path a free function** that depends only on the callback's client pointer and `SessionPolicyCache.shared` (a process-lifetime singleton). No instance state required:

```swift
private func handleESEvent(client: OpaquePointer, event: UnsafePointer<es_message_t>) {
    let msg = event.pointee
    let pid = audit_token_to_pid(msg.process.pointee.audit_token)

    switch msg.event_type {
    case ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_CREATE,
         ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME:
        handleAuthFile(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_EXEC:
        handleAuthExec(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_CLOSE:
        ESFClient.shared?.handleNotify(event: event, type: msg.event_type, pid: pid)
    default:
        break
    }
}
```

**Every AUTH code path calls `es_respond_auth_result`.** No `guard ... else { return }` without responding. Fail-open on error:

```swift
private func handleAuthFile(client: OpaquePointer, event: ..., pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let (decision, _) = SessionPolicyCache.shared.evaluateFile(...)
    switch decision {
    case .allow, .fallthrough_:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    case .deny:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    }
}
```

**Handling each `.fallthrough_` file action locally:**

The current `evaluateFile` returns `.fallthrough_` for three file rule actions that previously required server-side logic. Each gets a defined local behavior:

- `"approve"` (requires user approval): **Deny** the operation immediately. Send async notification to Go server. When the user approves, the server pushes a policy update adding an allow rule. Next attempt succeeds.
- `"redirect"` (file access redirection): **Deny** the operation. Send async notification. Go server handles the actual redirect asynchronously.
- `"soft_delete"` (custom deletion behavior): **Deny** the operation. Send async notification. Go server performs the soft-delete and pushes a policy update.

So `.fallthrough_` becomes **deny + async notify**, not allow. The `CacheDecision.fallthrough_` enum case is removed from the file AUTH path. `evaluateFile` returns `.deny` for these actions directly. The `.fallthrough_` case remains only for `evaluateNetwork` in `FilterDataProvider`, which has its own timeout-based handling (NEFilterDataProvider does not kill the extension on missed deadlines like endpointsecurityd does — it falls back to the configured fail-open/fail-closed behavior).

**Rename handler:** The current rename handler makes two sequential XPC calls. With local-only evaluation, both paths are evaluated locally from `evaluateFile`. The rename handler calls `evaluateFile` twice (source path with "rename" operation, dest path with "create" operation), combines the results, and responds. No retained messages, no completion handlers. Same pattern as today's cache-hit path (lines 363-376 of the current code), just without the fallthrough-to-XPC branch.

AUTH events are never retained, never wait for completion handlers, never go unanswered.

### 2. Local Exec Policy Evaluation

**New `ExecRule` struct** in `SessionPolicyCache.swift`:

```swift
struct ExecRule {
    let pattern: String   // glob pattern for executable path
    let action: String    // "allow", "deny", "redirect"
}
```

**New `evaluateExec` method** on `SessionPolicyCache`:

```swift
func evaluateExec(path: String, pid: pid_t) -> (CacheDecision, String?) {
    return queue.sync {
        guard let sid = pidToSession[pid],
              let cache = sessions[sid] else {
            return (.allow, nil)
        }

        for rule in cache.execRules where rule.action == "deny" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.deny, sid)
            }
        }

        for rule in cache.execRules where rule.action == "redirect" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.deny, sid)  // deny the exec; async notify triggers stub spawn
            }
        }

        for rule in cache.execRules where rule.action == "allow" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.allow, sid)
            }
        }

        if cache.defaults.exec == "deny" {
            return (.deny, sid)
        }
        return (.allow, sid)
    }
}
```

**Exec redirect flow:**

1. AUTH_EXEC fires for `/usr/bin/git` from a session PID
2. `evaluateExec` matches a redirect rule, returns `.deny`
3. Handler calls `es_respond_auth_result(DENY)` immediately
4. Handler fires an async notification to the Go server: "PID X tried `/usr/bin/git` with args [...], denied for redirect"
5. Go server receives the notification and spawns `agentsh-stub`
6. If the socket is down, the deny still happened — the stub just won't spawn

**`exec_redirect_notify` request schema** (sent over Unix socket to Go server):

```json
{
  "type": "exec_redirect_notify",
  "path": "/usr/bin/git",
  "args": ["git", "push"],
  "pid": 1234,
  "parent_pid": 1230,
  "session_id": "sess-abc123",
  "tty_path": "/dev/ttys003",
  "cwd_path": "/Users/dev/project"
}
```

This reuses the existing `PolicyRequest` struct fields. The Go server's `handleRequest` switch adds a case for `exec_redirect_notify` that spawns `agentsh-stub`. No response is expected (fire-and-forget)

**Rule evaluation order:** Deny > redirect > allow > default. This is fixed precedence, not dependent on rule ordering in the snapshot. The Go server can send rules in any order; the SysExt always evaluates deny first. This matches the existing `evaluateFile` behavior.

**Exec rules in the policy snapshot JSON:**

```json
{
  "exec_rules": [
    {"pattern": "/usr/bin/git", "action": "redirect"},
    {"pattern": "/usr/bin/curl", "action": "redirect"},
    {"pattern": "/usr/bin/rm", "action": "deny"}
  ],
  "defaults": {
    "file": "allow",
    "network": "allow",
    "dns": "allow",
    "exec": "allow"
  }
}
```

**`SessionCache.from(json:)` parser** extended to parse `exec_rules` and `defaults.exec`, same pattern as existing file/network/dns rule parsing.

### 3. Async IPC Channel (PolicySocketClient)

**New `PolicySocketClient` class** replaces all `xpcProxy` usage in the SysExt. Connects directly to `/var/run/agentsh/policy.sock`, reuses the existing JSON protocol.

```
PolicySocketClient
  connect()                    — async, non-blocking
  disconnect()                 — cleanup
  send(request)                — fire-and-forget (notifications, events)
  request(request, reply)      — async request-response (policy snapshot fetch)
  reconnect logic              — retry on next Darwin notification or periodic timer
```

Design constraints:

- **Never blocks.** All sends are async. If the socket is down, messages are dropped (not queued).
- **Lazy connection.** Don't connect on init. Connect when first needed (Darwin notification received, or session fetch triggered). Avoids errors at startup when the Go server isn't running.
- **Reconnect on disconnect.** When the connection drops, set a disconnected flag. Reconnect when a Darwin notification arrives (signals the Go server is alive) or on a periodic timer (5-10 seconds).
- **Reuse existing protocol.** The Go server's `PolicyRequest`/`PolicyResponse` JSON-over-Unix-socket format is already defined. The encoding/decoding logic from `PolicyBridge.swift` moves into `PolicySocketClient`.

**What uses the socket:**

| Operation | Trigger | Blocking? |
|-----------|---------|-----------|
| Exec redirect notify | AUTH_EXEC denies for redirect | No, fire-and-forget |
| NOTIFY_CLOSE forwarding | File modified event | No, fire-and-forget |
| Policy snapshot fetch | Darwin notification / session signal | No, async callback |
| NOTIFY event emission | Various NOTIFY handlers | No, fire-and-forget |

### 4. Session Lifecycle

Session registration without XPC, using Darwin notifications as signals and the socket for data:

1. Go server starts a session, defines policy rules
2. Go server posts Darwin notification `ai.canyonroad.agentsh.session-registered`
3. SysExt receives the notification
4. SysExt connects to the socket if not already connected (the Darwin notification doubles as a "server is alive" signal, triggering initial connect if needed)
5. SysExt calls `fetchPolicySnapshot` over the Unix socket
6. Response contains session ID, root PID, file rules, exec rules, network rules, DNS rules, defaults. The `root_pid` is included in the snapshot response (added to `PolicySnapshotResponse` on the Go side); the SysExt does not resolve it separately
7. SysExt creates `SessionCache` and registers in `SessionPolicyCache`
8. AUTH handlers now evaluate rules for PIDs in this session

**Policy updates:** Same as today — Go server posts `ai.canyonroad.agentsh.policy-updated`, SysExt pulls updated snapshot, `SessionPolicyCache.updateSession()` replaces rules if version is newer.

**Session end:** Go server posts a notification, SysExt pulls the update, calls `SessionPolicyCache.unregisterSession()`.

**Go server not running:**

- No socket = no sessions = `hasActiveSessions` is false = AUTH fast path allows everything
- If the Go server dies while a session is active, cached rules continue to be enforced locally (allow/deny work as before)
- Exec redirect denials still happen (the exec is blocked), but the stub won't spawn (socket is down). The user sees the command fail. On reconnect, normal behavior resumes.

### 5. Startup Sequence

The extension has never survived startup. The new sequence minimizes work before AUTH events flow:

```swift
// main.swift

// 1. Initialize policy cache BEFORE ES client (avoid lazy init on ES thread)
_ = SessionPolicyCache.shared

// 2. Create ES client (calls es_new_client but does NOT subscribe yet)
guard let esfClient = ESFClient.create() else {
    NSLog("ESF client failed to start — exiting")
    exit(1)
}

// 3. Store strong reference BEFORE subscribing — NOTIFY handlers
//    use ESFClient.shared, so it must be set before events flow
ESFClient.shared = esfClient

// 4. Subscribe to events — now ESFClient.shared is set, safe for NOTIFY handlers
esfClient.subscribe()

// 5. Start async socket connection (lazy, non-blocking, no-op if server is down)
PolicySocketClient.shared.connectWhenReady()

dispatchMain()
```

`ESFClient.create()` is a factory that calls `es_new_client` but does **not** subscribe. It returns the ESFClient instance. Subscription happens via a separate `esfClient.subscribe()` call **after** `ESFClient.shared` is stored. This eliminates the race window where NOTIFY events arrive before the shared reference is set (which would cause child PIDs to not be tracked and their AUTH events to bypass policy).

The callback is a free function that references `ESFClient.shared` for NOTIFY events. Since `shared` is set before `subscribe()`, the reference is guaranteed non-nil when events start flowing. No XPC connection is created. No work that can fail or block.

The existing `activeESFClient` global in `main.swift` is replaced by `ESFClient.shared` (a static property on the class). One canonical strong reference.

### 6. XPC Service Cleanup

**ESFClient:** Remove `xpc`, `xpcProxy` properties. Remove all XPC calls. Remove `.fallthrough_` → XPC completion handler paths.

**FilterDataProvider:** Replace `xpcProxy` calls with `PolicySocketClient`. The PNACL blocking mode (`handleNewFlowBlocking`) currently uses a synchronous XPC call with a semaphore and timeout (100ms default). This is structurally similar to the AUTH problem but is safe: NEFilterDataProvider does not kill the extension on missed deadlines — it falls back to the configured fail-open/fail-closed behavior. The existing timeout-based approach is acceptable when migrated from XPC to socket. No architectural change needed for FilterDataProvider beyond swapping the transport.

**DNSProxyProvider:** Replace `xpcProxy` calls with `PolicySocketClient`. Already does mostly local DNS blocking from `SessionPolicyCache`.

**XPC Service target:** Stays in the Xcode project as dead code. Could be useful later for a GUI settings app. No urgency to remove.

## Files Changed

| File | Change |
|------|--------|
| `ESFClient.swift` | Major rewrite: remove XPC, use callback client pointer, local-only AUTH, async socket notifications |
| `SessionPolicyCache.swift` | Add `ExecRule`, `evaluateExec`, `defaults.exec`, parse `exec_rules` from snapshot |
| `main.swift` | New startup sequence: pre-init cache, create ESFClient, lazy socket |
| `PolicySocketClient.swift` | **New file**: Unix socket client for async IPC to Go server |
| `FilterDataProvider.swift` | Replace `xpcProxy` with `PolicySocketClient` |
| `DNSProxyProvider.swift` | Replace `xpcProxy` with `PolicySocketClient` |

## Unchanged Components

- **`ProcessHierarchy`**: Continues tracking parent-child relationships from NOTIFY_FORK/EXIT. No changes needed.
- **`ProcessIdentifier`**: Cache of PID → process info. No changes needed.
- **`ApprovalManager`** (in XPC service target): Out of scope. Lives in the app bundle, not the SysExt. Can continue using XPC if a GUI app component is added later.
- **XPC Service target**: Stays in the Xcode project. Dead code from SysExt's perspective but no urgency to remove.
- **`PolicySocketClient` is a new class**, not a refactor of `PolicyBridge.swift`. PolicyBridge lives in the XPC Service target; PolicySocketClient lives in the SysExt target. It borrows the socket connection and JSON encoding logic but is a separate implementation.

## Go Server Changes

| File | Change |
|------|--------|
| `internal/platform/darwin/xpc/protocol.go` | Add `exec_redirect_notify` request type |
| `internal/platform/darwin/xpc/server.go` | Handle `exec_redirect_notify` — spawn `agentsh-stub` |
| `internal/platform/darwin/notify.go` | Add `NotifySessionRegistered()` Darwin notification |
| `internal/platform/darwin/xpc/snapshot.go` | Add `exec_rules` array, `defaults.exec`, and `root_pid` to `PolicySnapshotResponse` |

## Trade-offs

**What we gain:**
- Extension survives startup and runs indefinitely
- AUTH events responded to in microseconds (no IPC latency)
- System never freezes from unanswered AUTH events
- Graceful degradation when Go server is absent

**What we lose:**
- Real-time server-side approval for individual operations (the `.fallthrough_` → XPC path). This becomes: deny now, notify server, server updates rules, next attempt is allowed.
- Synchronous exec pipeline check. Redirect decisions are now based on cached patterns, not real-time server logic. The Go server must push exec rules ahead of time.

Both trade-offs are acceptable. Commercial ESF products (CrowdStrike, SentinelOne) all evaluate AUTH locally. Blocking AUTH events on IPC is fundamentally incompatible with system stability.
