# ESF AUTH Local Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the macOS system extension survive startup and handle all AUTH events locally without IPC, fixing the crash-respawn death spiral that makes the system unusable.

**Architecture:** AUTH handlers use the ES callback's client pointer directly (no instance state) and evaluate policy from an in-process cache. A new `PolicySocketClient` replaces the dead XPC Service for async operations (session registration, policy fetches, event forwarding). The Go server adds exec rules to policy snapshots and handles `exec_redirect_notify` for stub spawning.

**Tech Stack:** Swift (SysExt), Go (server), Endpoint Security Framework, Unix domain sockets, Darwin notifications

**Spec:** `docs/superpowers/specs/2026-04-02-esf-auth-local-evaluation-design.md`

---

### Task 1: Add exec rules and local exec evaluation to SessionPolicyCache

**Files:**
- Modify: `macos/AgentSH/SessionPolicyCache.swift`

This is the foundation -- all other tasks depend on the cache having exec evaluation capability.

- [ ] **Step 1: Add ExecRule struct and exec fields**

Add after the `DNSRule` struct (line 23):

```swift
struct ExecRule {
    let pattern: String   // glob pattern for executable path
    let action: String    // "allow", "deny", "redirect"
}
```

Add `exec` field to `PolicyDefaults` (line 29):

```swift
struct PolicyDefaults {
    let file: String     // "allow" or "deny"
    let network: String
    let dns: String
    let exec: String     // "allow" or "deny"
}
```

Add `execRules` to `SessionCache` (after `dnsRules` on line 41):

```swift
var execRules: [ExecRule]
```

Update the `SessionCache.init` to include `execRules` parameter.

- [ ] **Step 2: Add ExecDecision enum and evaluateExec method**

Add the exec-specific decision enum (distinct from CacheDecision to carry redirect info):

```swift
enum ExecDecision {
    case allow
    case deny
    case redirect  // deny the exec + async notify Go server to spawn stub
}
```

Add after `evaluateNetwork` (after line 225):

```swift
func evaluateExec(path: String, pid: pid_t) -> (ExecDecision, String?) {
    return queue.sync {
        guard let sid = pidToSession[pid],
              let cache = sessions[sid] else {
            return (.allow, nil)
        }

        // Deny rules first (highest precedence)
        for rule in cache.execRules where rule.action == "deny" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.deny, sid)
            }
        }

        // Redirect rules -- deny the exec locally; async notify triggers stub
        for rule in cache.execRules where rule.action == "redirect" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.redirect, sid)
            }
        }

        // Explicit allow rules
        for rule in cache.execRules where rule.action == "allow" {
            if globMatch(pattern: rule.pattern, path: path) {
                return (.allow, sid)
            }
        }

        // Default
        if cache.defaults.exec == "deny" {
            return (.deny, sid)
        }
        return (.allow, sid)
    }
}
```

Note: This returns the deny reason in a single lock acquisition, avoiding the TOCTOU race that would occur with separate `evaluateExec` + `isRedirectExec` calls.

- [ ] **Step 4: Update evaluateFile to return .deny for fallthrough actions**

Change the `.fallthrough_` block in `evaluateFile` (lines 174-178) to return `.deny` instead of `.fallthrough_`:

```swift
// Old:
if rule.action == "approve" || rule.action == "redirect" || rule.action == "soft_delete" {
    return (.fallthrough_, sid)
}

// New:
if rule.action == "approve" || rule.action == "redirect" || rule.action == "soft_delete" {
    return (.deny, sid)
}
```

- [ ] **Step 5: Update SessionCache.from(json:) to parse exec rules**

In the `from(json:)` extension (after DNS rules parsing, around line 370), add:

```swift
var execRules: [ExecRule] = []
if let rules = json["exec_rules"] as? [[String: Any]] {
    for r in rules {
        guard let pattern = r["pattern"] as? String,
              let action = r["action"] as? String else { continue }
        execRules.append(ExecRule(pattern: pattern, action: action))
    }
}
```

Update the `PolicyDefaults` parsing to include exec:

```swift
let defaults = PolicyDefaults(
    file: defs["file"] ?? "allow",
    network: defs["network"] ?? "allow",
    dns: defs["dns"] ?? "allow",
    exec: defs["exec"] ?? "allow"
)
```

Update the `SessionCache(...)` constructor call to include `execRules: execRules`.

- [ ] **Step 6: Fix all existing SessionCache constructor calls**

The `SessionCache.init` signature changed (added `execRules`). Update the empty snapshot creation in `ESFClient.swift:registerSession` (line 170):

```swift
let emptySnapshot = SessionCache(
    sessionID: sessionID, rootPID: rootPID, version: 0,
    fileRules: [], networkRules: [], dnsRules: [], execRules: [],
    defaults: PolicyDefaults(file: "allow", network: "allow", dns: "allow", exec: "allow"))
```

- [ ] **Step 7: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED (or at least no errors in SessionPolicyCache.swift)

- [ ] **Step 8: Commit**

```bash
git add macos/AgentSH/SessionPolicyCache.swift macos/AgentSH/ESFClient.swift
git commit -m "feat(sysext): add exec rules and local exec evaluation to SessionPolicyCache"
```

---

### Task 2: Create PolicySocketClient

**Files:**
- Create: `macos/AgentSH/PolicySocketClient.swift`

New Unix socket client for async IPC to the Go server. Replaces the dead XPC Service connection. Based on the socket logic from `macos/AgentSH/xpc/PolicyBridge.swift`.

- [ ] **Step 1: Create PolicySocketClient.swift**

Create `macos/AgentSH/PolicySocketClient.swift`:

```swift
import Foundation

/// Async Unix socket client for communicating with the Go policy server.
/// Replaces the dead XPC Service connection for the SysExt.
/// All operations are non-blocking. If the socket is down, sends are dropped.
class PolicySocketClient {
    static let shared = PolicySocketClient()

    private let socketPath = "/var/run/agentsh/policy.sock"
    private let sendQueue = DispatchQueue(label: "ai.canyonroad.agentsh.policysocket")
    private let timeout: TimeInterval = 5.0

    /// Whether we believe the server is reachable. Updated on connect/disconnect.
    private var _connected: Int32 = 0
    var isConnected: Bool { _connected != 0 }

    private init() {}

    // MARK: - Connection Lifecycle

    /// Attempt to connect when ready. Non-blocking. Called from main.swift at startup.
    /// Actual connection happens lazily on first send or when a Darwin notification arrives.
    func connectWhenReady() {
        // Try an initial connection attempt in the background
        sendQueue.async {
            self.testConnection()
        }
    }

    /// Called when a Darwin notification arrives, signaling the Go server may be alive.
    func onServerNotification() {
        sendQueue.async {
            self.testConnection()
        }
    }

    private func testConnection() {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            socketPath.withCString { cstr in strcpy(ptr, cstr) }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, addrLen)
            }
        }
        if result == 0 {
            if _connected == 0 {
                NSLog("PolicySocketClient: connected to Go server")
            }
            OSAtomicCompareAndSwap32(0, 1, &_connected)
        } else {
            if _connected != 0 {
                NSLog("PolicySocketClient: Go server unreachable")
            }
            OSAtomicCompareAndSwap32(1, 0, &_connected)
        }
    }

    // MARK: - Fire-and-Forget Send

    /// Send a request without waiting for a response. If the socket is down, the message is dropped.
    func send(_ request: [String: Any]) {
        sendQueue.async {
            do {
                _ = try self.sendSync(request)
            } catch {
                // Fire-and-forget: log but don't propagate
                OSAtomicCompareAndSwap32(1, 0, &self._connected)
            }
        }
    }

    // MARK: - Async Request-Response

    /// Send a request and receive a response asynchronously.
    func request(_ request: [String: Any], completion: @escaping ([String: Any]?) -> Void) {
        sendQueue.async {
            do {
                let response = try self.sendSync(request)
                completion(response)
            } catch {
                NSLog("PolicySocketClient: request failed: \(error)")
                OSAtomicCompareAndSwap32(1, 0, &self._connected)
                completion(nil)
            }
        }
    }

    // MARK: - Socket I/O (synchronous, called on sendQueue)

    private func sendSync(_ request: [String: Any]) throws -> [String: Any] {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.creation }
        defer { close(fd) }

        // Connect
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            socketPath.withCString { cstr in strcpy(ptr, cstr) }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, addrLen)
            }
        }
        guard connectResult == 0 else { throw SocketError.connectionFailed }

        // Timeouts
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Send (newline-delimited JSON)
        let requestData = try JSONSerialization.data(withJSONObject: request)
        var dataWithNewline = requestData
        dataWithNewline.append(0x0A)

        var totalWritten = 0
        while totalWritten < dataWithNewline.count {
            let written = dataWithNewline.withUnsafeBytes { ptr in
                write(fd, ptr.baseAddress! + totalWritten, ptr.count - totalWritten)
            }
            if written <= 0 { throw SocketError.writeFailed }
            totalWritten += written
        }

        // Read response
        var responseBuffer = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let bytesRead = read(fd, &buffer, buffer.count)
            if bytesRead < 0 { throw SocketError.readFailed }
            if bytesRead == 0 {
                if responseBuffer.isEmpty { throw SocketError.readFailed }
                break
            }
            responseBuffer.append(contentsOf: buffer[0..<bytesRead])
            if responseBuffer.count > 1024 * 1024 { throw SocketError.readFailed }
            if let lastByte = responseBuffer.last, lastByte == 0x0A { break }
        }

        guard let response = try JSONSerialization.jsonObject(with: responseBuffer) as? [String: Any] else {
            throw SocketError.invalidResponse
        }

        // Mark as connected on success
        OSAtomicCompareAndSwap32(0, 1, &_connected)
        return response
    }

    enum SocketError: Error {
        case creation, connectionFailed, writeFailed, readFailed, invalidResponse
    }
}
```

- [ ] **Step 2: Add the file to the Xcode project**

The file needs to be added to the SysExt target in the Xcode project. Add it alongside the other Swift files in `macos/AgentSH/`. It should be included in the SysExt target's "Compile Sources" build phase.

- [ ] **Step 3: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/AgentSH/PolicySocketClient.swift macos/AgentSH/agentsh.xcodeproj/project.pbxproj
git commit -m "feat(sysext): add PolicySocketClient for direct Unix socket IPC"
```

---

### Task 3: Rewrite ESFClient for local-only AUTH

**Files:**
- Modify: `macos/AgentSH/ESFClient.swift`

This is the critical change. AUTH handlers become free functions using the callback's client pointer. No XPC. No retained messages. Every AUTH event always gets a response.

- [ ] **Step 1: Add static shared property and factory method**

Replace the class header and init (lines 6-42) with:

```swift
class ESFClient {
    /// Singleton reference set before subscribe() in main.swift.
    /// NOTIFY handlers use this; AUTH handlers do NOT depend on it.
    static var shared: ESFClient?

    /// The ES client pointer. Set once in create(), never cleared except in stop()/deinit.
    private var client: OpaquePointer?

    /// Observer token for policy cache refresh notifications
    private var notificationObserver: NSObjectProtocol?

    /// Cache of PID -> audit_token_t for muting
    private var auditTokenCache: [pid_t: audit_token_t] = [:]
    private let cacheQueue = DispatchQueue(label: "ai.canyonroad.agentsh.audittokencache")

    /// Shared ISO8601 formatter for event timestamps (thread-safe)
    private static let isoFormatter = ISO8601DateFormatter()

    private init(client: OpaquePointer) {
        self.client = client

        // Listen for Darwin notification-triggered cache refresh
        notificationObserver = NotificationCenter.default.addObserver(
            forName: .policyCacheNeedsRefresh,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let sessionID = notification.userInfo?["session_id"] as? String else { return }
            self?.refreshCacheForSession(sessionID)
        }
    }

    deinit {
        if let observer = notificationObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        stop()
    }

    /// Factory: creates ES client but does NOT subscribe. Call subscribe() separately.
    static func create() -> ESFClient? {
        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { client, event in
            handleESEvent(client: client, event: event)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient = newClient else {
            NSLog("Failed to create ES client: \(result.rawValue)")
            return nil
        }
        return ESFClient(client: newClient)
    }

    /// Subscribe to ES events. Must be called AFTER ESFClient.shared is set.
    func subscribe() -> Bool {
        guard let client = client else { return false }

        let authEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC
        ]
        let notifyEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
        let allEvents = authEvents + notifyEvents
        let subscribeResult = es_subscribe(client, allEvents, UInt32(allEvents.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            NSLog("Failed to subscribe: \(subscribeResult.rawValue)")
            return false
        }
        NSLog("ESF client subscribed successfully")

        // Mute agentsh binaries to prevent recursion
        if #available(macOS 12.0, *) {
            for path in ["/usr/local/bin/agentsh-stub", "/usr/local/bin/agentsh"] {
                es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL)
            }
        }
        return true
    }
```

- [ ] **Step 2: Replace handleEvent with free function handleESEvent**

Remove the old `handleEvent` instance method. Add this as a **file-level** (module-private) free function, outside the class:

```swift
/// Free function -- no instance state needed for AUTH responses.
/// AUTH handlers use the `client` pointer from the callback (always valid).
/// NOTIFY handlers delegate to ESFClient.shared (best-effort).
private func handleESEvent(client: OpaquePointer, event: UnsafePointer<es_message_t>) {
    let message = event.pointee
    let pid = audit_token_to_pid(message.process.pointee.audit_token)

    switch message.event_type {
    // AUTH events -- MUST always respond via es_respond_auth_result
    case ES_EVENT_TYPE_AUTH_OPEN:
        handleAuthOpen(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_CREATE:
        handleAuthCreate(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_UNLINK:
        handleAuthUnlink(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_RENAME:
        handleAuthRename(client: client, event: event, pid: pid)
    case ES_EVENT_TYPE_AUTH_EXEC:
        handleAuthExec(client: client, event: event, pid: pid)

    // NOTIFY events -- best effort, no response needed
    case ES_EVENT_TYPE_NOTIFY_FORK:
        ESFClient.shared?.handleNotifyFork(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        ESFClient.shared?.handleNotifyExit(message, pid: pid)
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        ESFClient.shared?.handleNotifyClose(message, pid: pid)
    default:
        break
    }
}
```

- [ ] **Step 3: Rewrite AUTH file handlers as free functions**

Replace all four file AUTH handlers with free functions (outside the class). Each follows the same pattern -- no guard-let-client, no retained messages, always responds:

```swift
private func handleAuthOpen(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let path = String(cString: event.pointee.event.open.file.pointee.path.data)
    let (decision, _) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "read", pid: pid)

    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }
}

private func handleAuthCreate(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let create = event.pointee.event.create
    let path: String
    if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        path = String(cString: create.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: create.destination.new_path.filename.data)
        path = dir + "/" + filename
    }

    let (decision, _) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "create", pid: pid)
    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }
}

private func handleAuthUnlink(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let path = String(cString: event.pointee.event.unlink.target.pointee.path.data)
    let (decision, _) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "delete", pid: pid)

    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }
}

private func handleAuthRename(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let sourcePath = String(cString: event.pointee.event.rename.source.pointee.path.data)
    let rename = event.pointee.event.rename
    let destPath: String
    if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        destPath = String(cString: rename.destination.existing_file.pointee.path.data)
    } else {
        let dir = String(cString: rename.destination.new_path.dir.pointee.path.data)
        let filename = String(cString: rename.destination.new_path.filename.data)
        destPath = dir + "/" + filename
    }

    let (srcDecision, _) = SessionPolicyCache.shared.evaluateFile(path: sourcePath, operation: "rename", pid: pid)
    let (dstDecision, _) = SessionPolicyCache.shared.evaluateFile(path: destPath, operation: "create", pid: pid)

    if srcDecision == .deny || dstDecision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }
}
```

- [ ] **Step 4: Rewrite AUTH_EXEC as free function with local evaluation**

```swift
private func handleAuthExec(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    // Check session membership before string extraction
    guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let execPtr = UnsafeRawPointer(event)
        .advanced(by: MemoryLayout.offset(of: \es_message_t.event)!)
        .assumingMemoryBound(to: es_event_exec_t.self)
    let execPath = String(cString: execPtr.pointee.target.pointee.executable.pointee.path.data)

    // Evaluate locally — single call returns allow/deny/redirect in one lock acquisition
    let (decision, _) = SessionPolicyCache.shared.evaluateExec(path: execPath, pid: pid)

    switch decision {
    case .allow:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    case .deny:
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        return
    case .redirect:
        // Deny the exec, then notify Go server to spawn stub
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)

        // Extract args and context for the redirect notification
        do {
            let parentPID = event.pointee.process.pointee.ppid
            // Extract args
            let argc = es_exec_arg_count(execPtr)
            var args: [String] = []
            for i in 0..<argc {
                let arg = es_exec_arg(execPtr, i)
                let len = Int(arg.length)
                if len > 0, let data = arg.data {
                    args.append(String(bytes: UnsafeRawBufferPointer(start: data, count: len),
                                       encoding: .utf8) ?? String(cString: data))
                } else {
                    args.append("")
                }
            }
            var ttyPath: String? = nil
            if let ttyFile = event.pointee.process.pointee.tty {
                ttyPath = String(cString: ttyFile.pointee.path.data)
            }
            let cwdPath = String(cString: execPtr.pointee.cwd.pointee.path.data)

            PolicySocketClient.shared.send([
                "type": "exec_redirect_notify",
                "path": execPath,
                "args": args,
                "pid": Int(pid),
                "parent_pid": Int(parentPID),
                "session_id": sessionID,
                "tty_path": ttyPath ?? "",
                "cwd_path": cwdPath
            ])
        }
    }

    // Track exec depth for recursion monitoring (best-effort, after response)
    let parentPID = event.pointee.process.pointee.ppid
    let _ = SessionPolicyCache.shared.recordExecDepth(pid: pid, parentPID: parentPID)
}
```

- [ ] **Step 5: Remove XPC properties and old instance AUTH handlers**

Remove from the `ESFClient` class:
- `private let xpc: NSXPCConnection` property
- `private var xpcProxy: AgentshXPCProtocol?` property
- All old `handleAuthOpen/Create/Unlink/Rename/Exec` instance methods
- The old `handleEvent` instance method
- The XPC init code from the constructor
- The `registerSession(rootPID:sessionID:)` method (replaced by socket-based registration via Darwin notification)

- [ ] **Step 6: Update refreshCacheForSession to use PolicySocketClient**

```swift
private func refreshCacheForSession(_ sessionID: String) {
    let currentVersion = SessionPolicyCache.shared.versionForSession(sessionID)
    PolicySocketClient.shared.request([
        "type": "fetch_policy_snapshot",
        "session_id": sessionID,
        "version": currentVersion
    ]) { response in
        guard let response = response else { return }
        guard let version = response["version"] as? UInt64 ?? (response["version"] as? Int).map({ UInt64($0) }),
              version > 0 else { return }
        guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
        guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
            NSLog("ESFClient: failed to parse policy snapshot for session \(sessionID)")
            return
        }
        SessionPolicyCache.shared.updateSession(sessionID, snapshot: snapshot)
        NSLog("ESFClient: updated cache for session \(sessionID) to version \(version)")
    }
}
```

- [ ] **Step 7: Keep stop(), mutePath(), muteProcess(), muteProcessByPID() and NOTIFY handlers as instance methods**

These stay as instance methods on `ESFClient`. Update `stop()` to remove the `xpc.invalidate()` call (XPC is gone):

```swift
func stop() {
    if let client = client {
        es_delete_client(client)
        self.client = nil
    }
}
```

The NOTIFY handlers (`handleNotifyFork`, `handleNotifyExit`, `handleNotifyClose`) remain mostly unchanged but update `handleNotifyClose` to use `PolicySocketClient.shared.send(...)` instead of `xpcProxy?.emitEvent(...)`:

```swift
private func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
    guard message.event.close.modified else { return }
    guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

    let path = String(cString: message.event.close.target.pointee.path.data)

    // Build event payload and base64-encode it to match Go's PolicyRequest.EventData ([]byte)
    let eventPayload: [String: Any] = [
        "type": "file_write",
        "path": path,
        "operation": "close_modified",
        "pid": Int(pid),
        "session_id": sessionID,
        "timestamp": Self.isoFormatter.string(from: Date())
    ]
    if let data = try? JSONSerialization.data(withJSONObject: eventPayload) {
        PolicySocketClient.shared.send([
            "type": "event",
            "event_data": data.base64EncodedString()
        ])
    }
}
```

- [ ] **Step 8: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -20`

Expected: BUILD SUCCEEDED.

- [ ] **Step 9: Commit**

```bash
git add macos/AgentSH/ESFClient.swift
git commit -m "feat(sysext): rewrite ESFClient for local-only AUTH evaluation

AUTH handlers are now free functions using the ES callback's client
pointer directly. No XPC, no retained messages, every AUTH event
always gets a response. NOTIFY handlers delegate to ESFClient.shared."
```

---

### Task 4: Update main.swift startup sequence

**Files:**
- Modify: `macos/AgentSH/main.swift`

- [ ] **Step 1: Replace the startup code**

The old `main.swift` had an `ExtensionMain` class implementing `OSSystemExtensionRequestDelegate`. This is removed -- sysextd handles activation externally, the delegate was only logging. Replace the entire content of `main.swift` with:

```swift
import Foundation
import SystemExtensions

// 1. Initialize policy cache BEFORE ES client (avoid lazy init on ES thread)
_ = SessionPolicyCache.shared

// 2. Create ES client (calls es_new_client but does NOT subscribe yet)
var esfClient: ESFClient?
for attempt in 1...3 {
    if let client = ESFClient.create() {
        NSLog("AgentSH SysExt: ES client created on attempt \(attempt)")
        esfClient = client
        break
    }
    if attempt < 3 {
        NSLog("AgentSH SysExt: ES client creation attempt \(attempt) failed, retrying in 2s")
        Thread.sleep(forTimeInterval: 2)
    }
}

guard let esfClient = esfClient else {
    NSLog("AgentSH SysExt: ES client failed to start -- exiting (grant Full Disk Access to enable)")
    exit(1)
}

// 3. Store strong reference BEFORE subscribing
ESFClient.shared = esfClient

// 4. Subscribe to events -- ESFClient.shared is now set, safe for NOTIFY handlers
guard esfClient.subscribe() else {
    NSLog("AgentSH SysExt: Failed to subscribe to ES events -- exiting")
    exit(1)
}

// 5. Start async socket connection (lazy, non-blocking)
PolicySocketClient.shared.connectWhenReady()

dispatchMain()
```

- [ ] **Step 2: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED

- [ ] **Step 3: Commit**

```bash
git add macos/AgentSH/main.swift
git commit -m "feat(sysext): safe startup sequence -- init cache, create client, store ref, then subscribe"
```

---

### Task 5: Update FilterDataProvider to use PolicySocketClient

**Files:**
- Modify: `macos/AgentSH/FilterDataProvider.swift`

- [ ] **Step 1: Remove XPC properties and setup**

Remove `xpc`, `xpcProxy`, `queue`, `getProxy()` properties/methods. Remove XPC connection creation from `startFilter()` and cleanup from `stopFilter()`. Keep `ProcessHierarchy.shared` init.

Simplified `startFilter`:

```swift
override func startFilter(completionHandler: @escaping (Error?) -> Void) {
    _ = ProcessHierarchy.shared
    completionHandler(nil)
}

override func stopFilter(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
) {
    completionHandler()
}
```

- [ ] **Step 2: Update handleNewFlowAuditOnly to use PolicySocketClient**

Replace `getProxy()?.checkNetworkPNACL(...)` with `PolicySocketClient.shared.send(...)`:

```swift
private func handleNewFlowAuditOnly(
    ip: String, port: Int, protocolType: String, domain: String?,
    pid: pid_t, parentPID: pid_t, sessionID: String, processInfo: ProcessInfo
) -> NEFilterNewFlowVerdict {
    PolicySocketClient.shared.send([
        "type": "pnacl_check",
        "ip": ip,
        "port": port,
        "protocol": protocolType,
        "domain": domain ?? "",
        "pid": Int(pid),
        "bundle_id": processInfo.bundleID ?? "",
        "executable_path": processInfo.executablePath ?? "",
        "process_name": processInfo.processName ?? "",
        "parent_pid": Int(parentPID),
        "session_id": sessionID
    ])
    return .allow()
}
```

- [ ] **Step 3: Update handleNewFlowBlocking to use PolicySocketClient**

Replace the XPC proxy call with `PolicySocketClient.shared.request(...)`. Keep the semaphore pattern:

```swift
private func handleNewFlowBlocking(
    ip: String, port: Int, protocolType: String, domain: String?,
    pid: pid_t, parentPID: pid_t, sessionID: String, processInfo: ProcessInfo
) -> NEFilterNewFlowVerdict {
    let semaphore = DispatchSemaphore(value: 0)
    var policyDecision: String?
    var policyRuleID: String?

    PolicySocketClient.shared.request([
        "type": "pnacl_check",
        "ip": ip,
        "port": port,
        "protocol": protocolType,
        "domain": domain ?? "",
        "pid": Int(pid),
        "bundle_id": processInfo.bundleID ?? "",
        "executable_path": processInfo.executablePath ?? "",
        "process_name": processInfo.processName ?? "",
        "parent_pid": Int(parentPID),
        "session_id": sessionID
    ]) { response in
        policyDecision = response?["decision"] as? String
        policyRuleID = response?["rule_id"] as? String
        semaphore.signal()
    }

    let result = semaphore.wait(timeout: .now() + decisionTimeout)

    let verdict: NEFilterNewFlowVerdict
    let wasBlocked: Bool

    switch result {
    case .success:
        if let decision = policyDecision {
            switch decision {
            case "allow", "allow_once", "allow_permanent":
                verdict = .allow(); wasBlocked = false
            case "deny", "deny_once", "deny_forever":
                verdict = .drop(); wasBlocked = true
            case "audit":
                verdict = .allow(); wasBlocked = false
            case "approve", "allow_once_then_approve":
                if failOpen || decision == "allow_once_then_approve" {
                    verdict = .allow(); wasBlocked = false
                } else {
                    verdict = .drop(); wasBlocked = true
                }
            default:
                verdict = failOpen ? .allow() : .drop()
                wasBlocked = !failOpen
            }
        } else {
            verdict = failOpen ? .allow() : .drop()
            wasBlocked = !failOpen
        }
    case .timedOut:
        verdict = failOpen ? .allow() : .drop()
        wasBlocked = !failOpen
    }

    logPNACLDecision(
        decision: policyDecision ?? (failOpen ? "allow_fallback" : "deny_fallback"),
        ruleID: policyRuleID, ip: ip, port: port, pid: pid,
        bundleID: processInfo.bundleID, blocked: wasBlocked)

    // Report event to server asynchronously (fire-and-forget)
    PolicySocketClient.shared.send([
        "type": "pnacl_event",
        "event_type": "connection_\(policyDecision ?? "unknown")",
        "ip": ip,
        "port": port,
        "protocol": protocolType,
        "domain": domain ?? "",
        "pid": Int(pid),
        "bundle_id": processInfo.bundleID ?? "",
        "decision": wasBlocked ? "blocked" : "allowed",
        "rule_id": policyRuleID ?? ""
    ])

    return verdict
}
```

- [ ] **Step 4: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED

- [ ] **Step 5: Commit**

```bash
git add macos/AgentSH/FilterDataProvider.swift
git commit -m "feat(sysext): switch FilterDataProvider from dead XPC to PolicySocketClient"
```

---

### Task 6: Update DNSProxyProvider to remove XPC

**Files:**
- Modify: `macos/AgentSH/DNSProxyProvider.swift`

- [ ] **Step 1: Remove XPC properties and setup**

Remove `xpc`, `xpcProxy`, `queue` properties. Remove XPC setup from `startProxy()` and cleanup from `stopProxy()`. The DNS provider already does all its blocking logic locally via `SessionPolicyCache.shared.evaluateDNS()`.

```swift
class DNSProxyProvider: NEDNSProxyProvider {

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    // ... rest unchanged (handleNewFlow, processQuery, shouldForward, DNS wire format helpers)
}
```

- [ ] **Step 2: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED

- [ ] **Step 3: Commit**

```bash
git add macos/AgentSH/DNSProxyProvider.swift
git commit -m "refactor(sysext): remove dead XPC from DNSProxyProvider"
```

---

### Task 7: Go server -- add exec rules to snapshot and exec_redirect_notify handler

**Files:**
- Modify: `internal/platform/darwin/xpc/snapshot.go`
- Modify: `internal/platform/darwin/xpc/protocol.go`
- Modify: `internal/platform/darwin/xpc/server.go`
- Modify: `internal/platform/darwin/xpc/snapshot_test.go`
- Modify: `internal/platform/darwin/notify.go`

- [ ] **Step 1: Add SnapshotExecRule and update snapshot types**

In `snapshot.go`, add after `SnapshotDNSRule`:

```go
// SnapshotExecRule represents a single exec rule in the snapshot.
type SnapshotExecRule struct {
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "allow", "deny", "redirect"
}
```

Add `RootPID` and `ExecRules` to `PolicySnapshotResponse`:

```go
type PolicySnapshotResponse struct {
	Version      uint64                `json:"version"`
	SessionID    string                `json:"session_id"`
	RootPID      int32                 `json:"root_pid"`
	FileRules    []SnapshotFileRule    `json:"file_rules"`
	NetworkRules []SnapshotNetworkRule `json:"network_rules"`
	DNSRules     []SnapshotDNSRule     `json:"dns_rules"`
	ExecRules    []SnapshotExecRule    `json:"exec_rules"`
	Defaults     *SnapshotDefaults     `json:"defaults"`
}
```

Add `Exec` to `SnapshotDefaults`:

```go
type SnapshotDefaults struct {
	File    string `json:"file"`
	Network string `json:"network"`
	DNS     string `json:"dns"`
	Exec    string `json:"exec"`
}
```

- [ ] **Step 2: Add exec_redirect_notify request type and response fields**

In `protocol.go`, add after `RequestTypeFetchPolicySnapshot`:

```go
// Exec redirect notification (fire-and-forget from SysExt)
RequestTypeExecRedirectNotify RequestType = "exec_redirect_notify"
```

Add to `PolicyResponse`:

```go
ExecRules []SnapshotExecRule `json:"exec_rules,omitempty"`
RootPID   int32              `json:"root_pid,omitempty"`
```

- [ ] **Step 3: Add exec_redirect_notify handler in server.go**

In `handleRequest`, add a case before the `default`:

```go
case RequestTypeExecRedirectNotify:
	return s.handleExecRedirectNotify(req)
```

Add the handler method:

```go
func (s *Server) handleExecRedirectNotify(req *PolicyRequest) PolicyResponse {
	s.mu.Lock()
	h := s.execHandler
	s.mu.Unlock()
	if h != nil {
		go func() {
			h.CheckExec(req.Path, req.Args, req.PID, req.ParentPID, req.SessionID,
				ExecContext{TTYPath: req.TTYPath, CWDPath: req.CWDPath})
		}()
	}
	return PolicyResponse{Allow: true}
}
```

- [ ] **Step 4: Add NotifySessionRegistered to notify.go**

```go
const SessionRegisteredNotification = "ai.canyonroad.agentsh.session-registered"

func NotifySessionRegistered() {
	cname := C.CString(SessionRegisteredNotification)
	defer C.free(unsafe.Pointer(cname))
	status := C.notify_post(cname)
	if status != 0 {
		slog.Warn("notify_post failed", "status", int(status), "name", SessionRegisteredNotification)
	}
}
```

- [ ] **Step 5: Update snapshot_test.go**

Update the test to include exec rules, root_pid, and defaults.exec:

```go
func TestPolicySnapshotResponse_JSON(t *testing.T) {
	snap := PolicySnapshotResponse{
		Version:   1,
		SessionID: "session-abc",
		RootPID:   1234,
		FileRules: []SnapshotFileRule{
			{Pattern: "/home/user/project/**", Operations: []string{"read", "write", "create"}, Action: "allow"},
			{Pattern: "/etc/shadow", Operations: []string{"read"}, Action: "deny"},
		},
		NetworkRules: []SnapshotNetworkRule{
			{Pattern: "*.evil.com", Ports: []int{}, Action: "deny"},
		},
		DNSRules: []SnapshotDNSRule{
			{Pattern: "*.evil.com", Action: "nxdomain"},
		},
		ExecRules: []SnapshotExecRule{
			{Pattern: "/usr/bin/git", Action: "redirect"},
			{Pattern: "/usr/bin/rm", Action: "deny"},
		},
		Defaults: &SnapshotDefaults{File: "allow", Network: "allow", DNS: "allow", Exec: "allow"},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicySnapshotResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 {
		t.Fatalf("expected version 1, got %d", decoded.Version)
	}
	if len(decoded.FileRules) != 2 {
		t.Fatalf("expected 2 file rules, got %d", len(decoded.FileRules))
	}
	if len(decoded.ExecRules) != 2 {
		t.Fatalf("expected 2 exec rules, got %d", len(decoded.ExecRules))
	}
	if decoded.ExecRules[0].Action != "redirect" {
		t.Fatalf("expected redirect, got %s", decoded.ExecRules[0].Action)
	}
	if decoded.RootPID != 1234 {
		t.Fatalf("expected root_pid 1234, got %d", decoded.RootPID)
	}
	if decoded.Defaults == nil || decoded.Defaults.Exec != "allow" {
		t.Fatalf("expected exec default allow, got %v", decoded.Defaults)
	}
}
```

- [ ] **Step 6: Run Go tests**

Run: `cd /Users/eran/work/canyonroad/agentsh && go test ./internal/platform/darwin/xpc/... -v -run TestPolicySnapshot`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/platform/darwin/xpc/snapshot.go internal/platform/darwin/xpc/protocol.go \
       internal/platform/darwin/xpc/server.go internal/platform/darwin/xpc/snapshot_test.go \
       internal/platform/darwin/notify.go
git commit -m "feat(darwin): add exec rules to policy snapshot and exec_redirect_notify handler"
```

**Note:** The `SnapshotBuilder.BuildPolicySnapshot()` implementation (in the policy engine code) must also be updated to populate `ExecRules`, `RootPID`, and `Defaults.Exec` in the response. This is a prerequisite for exec rules to actually flow to the SysExt. If the builder implementation is not in this package, track it as a follow-up.

---

### Task 8: Add session-registered Darwin notification listener

**Files:**
- Modify: `macos/AgentSH/SessionPolicyCache.swift`

The SysExt needs to listen for the new `ai.canyonroad.agentsh.session-registered` notification and fetch session details over the socket.

- [ ] **Step 1: Add session-registered notification listener**

Add the notification name constant near the top of the file (after line 4):

```swift
private let sessionRegisteredNotification = "ai.canyonroad.agentsh.session-registered"
```

In `startListeningForNotifications()`, add a second observer after the existing one:

```swift
let sessionName = CFNotificationName(sessionRegisteredNotification as CFString)
CFNotificationCenterAddObserver(
    center,
    Unmanaged.passUnretained(self).toOpaque(),
    { _, observer, _, _, _ in
        guard let observer = observer else { return }
        let cache = Unmanaged<SessionPolicyCache>.fromOpaque(observer).takeUnretainedValue()
        cache.handleSessionRegisteredNotification()
    },
    sessionName.rawValue,
    nil,
    .deliverImmediately
)
```

Add the handler:

```swift
private func handleSessionRegisteredNotification() {
    PolicySocketClient.shared.onServerNotification()

    PolicySocketClient.shared.request([
        "type": "fetch_policy_snapshot",
        "session_id": "",
        "version": 0
    ]) { response in
        guard let response = response,
              let sessionID = response["session_id"] as? String,
              !sessionID.isEmpty else { return }
        guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
        guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
            NSLog("SessionPolicyCache: failed to parse session snapshot")
            return
        }
        SessionPolicyCache.shared.registerSession(
            sessionID: sessionID, rootPID: rootPID, snapshot: snapshot)
        NSLog("SessionPolicyCache: registered session \(sessionID) from notification")
    }
}
```

- [ ] **Step 2: Signal PolicySocketClient on policy-updated notification too**

Update `handlePolicyUpdateNotification()` to also signal the socket client:

```swift
private func handlePolicyUpdateNotification() {
    PolicySocketClient.shared.onServerNotification()

    let sessionIDs = allSessionIDs()
    for sessionID in sessionIDs {
        NotificationCenter.default.post(
            name: .policyCacheNeedsRefresh,
            object: nil,
            userInfo: ["session_id": sessionID]
        )
    }
}
```

- [ ] **Step 3: Verify build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Debug build 2>&1 | tail -5`

Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/AgentSH/SessionPolicyCache.swift
git commit -m "feat(sysext): listen for session-registered notification and fetch policy over socket"
```

---

### Task 9: Build, sign, and test

**Files:** No code changes -- build and manual verification.

- [ ] **Step 1: Full build**

Run: `cd macos/AgentSH && xcodebuild -scheme AgentSH -configuration Release build 2>&1 | tail -10`

Expected: BUILD SUCCEEDED

- [ ] **Step 2: Bump CURRENT_PROJECT_VERSION**

In `macos/AgentSH/agentsh.xcodeproj/project.pbxproj`, bump `CURRENT_PROJECT_VERSION` from 8 to 9 in all build configurations (Debug and Release for all targets). This is required for sysextd to trigger the replacement flow.

- [ ] **Step 3: Sign and package**

Follow the existing build/sign workflow (codesign with Developer ID, embed provisioning profile, notarize with `xcrun notarytool`).

- [ ] **Step 4: Install and activate**

```bash
# Install the app
cp -R build/Release/AgentSH.app /Applications/
# Activate the extension
/Applications/AgentSH.app/Contents/MacOS/agentsh activate-extension
```

Expected: "replacing 8 -> 9" in activation output.

- [ ] **Step 5: Grant Full Disk Access**

Open System Settings > Privacy & Security > Full Disk Access. Enable it for the AgentSH system extension.

- [ ] **Step 6: Verify extension stays alive**

```bash
# Check the extension process
ps aux | grep agentsh.SysExt

# Check system log for ESF startup
log show --predicate 'process == "ai.canyonroad.agentsh.SysExt"' --last 30s

# Wait 30 seconds, verify no crash
sleep 30 && ps aux | grep agentsh.SysExt
```

Expected: The extension process stays alive. No "failed to respond" messages. No crash reports. System remains responsive.

- [ ] **Step 7: Verify no new crash reports**

```bash
ls -la /Library/Logs/DiagnosticReports/ai.canyonroad.agentsh.SysExt* 2>/dev/null | tail -3
```

Expected: No new crash reports after the v9 installation timestamp.

- [ ] **Step 8: Commit version bump**

```bash
git add macos/AgentSH/agentsh.xcodeproj/project.pbxproj
git commit -m "chore: bump CURRENT_PROJECT_VERSION to 9 for sysext replacement"
```
