// macos/SysExt/ESFClient.swift
import Foundation
import EndpointSecurity

/// Handles Endpoint Security Framework events.
class ESFClient {
    /// The ES client pointer. Written once in start(), read on every event.
    /// No lock needed — set once, only cleared in stop()/deinit.
    private var client: OpaquePointer?
    private let xpc: NSXPCConnection
    private var xpcProxy: AgentshXPCProtocol?

    /// Shared ISO8601 formatter for event timestamps (thread-safe)
    private static let isoFormatter = ISO8601DateFormatter()

    /// Cache of PID -> audit_token_t for muting
    private var auditTokenCache: [pid_t: audit_token_t] = [:]
    private let cacheQueue = DispatchQueue(label: "ai.canyonroad.agentsh.audittokencache")

    /// Observer token for policy cache refresh notifications
    private var notificationObserver: NSObjectProtocol?

    init() {
        // Connect to XPC Service
        xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
        xpc.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        xpc.resume()

        xpcProxy = xpc.remoteObjectProxyWithErrorHandler { error in
            NSLog("XPC error: \(error)")
        } as? AgentshXPCProtocol

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

    func start() -> Bool {
        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] _, event in
            self?.handleEvent(event)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient = newClient else {
            NSLog("Failed to create ES client: \(result.rawValue)")
            return false
        }

        self.client = newClient

        // Subscribe to AUTH events (blocking)
        let authEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC
        ]

        // Subscribe to NOTIFY events (observation)
        // TODO: Add ES_EVENT_TYPE_NOTIFY_SETATTR when macOS 26 SDK is available in CI
        let notifyEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]

        let allEvents = authEvents + notifyEvents
        let subscribeResult = es_subscribe(newClient, allEvents, UInt32(allEvents.count))

        guard subscribeResult == ES_RETURN_SUCCESS else {
            NSLog("Failed to subscribe: \(subscribeResult.rawValue)")
            es_delete_client(newClient)
            self.client = nil
            return false
        }

        NSLog("ESF client started successfully")

        // Mute agentsh binaries to prevent recursion during exec redirect.
        // When the Go server spawns agentsh-stub, the ES client must not
        // intercept it (which would cause infinite redirect loops).
        if #available(macOS 12.0, *) {
            for path in ["/usr/local/bin/agentsh-stub", "/usr/local/bin/agentsh"] {
                es_mute_path(newClient, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL)
            }
            NSLog("ESFClient: muted agentsh binary paths for recursion prevention")
        }

        return true
    }

    func stop() {
        if let client = client {
            es_delete_client(client)
            self.client = nil
        }
        xpc.invalidate()
    }

    // MARK: - Process Muting (Recursion Guard)

    /// Mute a path so ES events are not delivered for processes at that path.
    /// Used for dynamic recursion prevention — the Go server sends the actual
    /// stub binary path during wrap initialization.
    @available(macOS 12.0, *)
    func mutePath(_ path: String) {
        guard let client = client else { return }
        let result = es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL)
        if result != ES_RETURN_SUCCESS {
            NSLog("ESFClient: failed to mute path \(path): \(result.rawValue)")
        } else {
            NSLog("ESFClient: muted path \(path)")
        }
    }

    /// Mute a process and all its descendants so ES events are not delivered for them.
    /// Used for recursion prevention — agentsh-spawned commands must not be re-intercepted.
    func muteProcess(auditToken: audit_token_t) {
        guard let client = client else { return }
        var token = auditToken
        let result = es_mute_process(client, &token)
        if result != ES_RETURN_SUCCESS {
            NSLog("ESFClient: failed to mute process: \(result.rawValue)")
        } else {
            // Muted processes won't emit ES_EVENT_TYPE_NOTIFY_EXIT, so clean up
            // the audit token cache now to prevent stale entries and unbounded growth.
            let pid = audit_token_to_pid(token)
            cacheQueue.sync {
                _ = auditTokenCache.removeValue(forKey: pid)
            }
        }
    }

    /// Mute a process by PID. Looks up the audit_token from the fork event cache.
    /// Called from the Go side via XPC when the server spawns a command.
    func muteProcessByPID(_ pid: pid_t) {
        let token: audit_token_t? = cacheQueue.sync {
            return auditTokenCache[pid]
        }
        guard let token = token else {
            NSLog("ESFClient: cannot mute PID \(pid): no cached audit token")
            return
        }
        muteProcess(auditToken: token)
    }

    // MARK: - Session Management

    /// Register a wrap session — called when agentsh wrap starts an agent.
    /// Fetches initial policy snapshot asynchronously; registers with empty cache if fetch fails.
    func registerSession(rootPID: pid_t, sessionID: String) {
        xpcProxy?.fetchPolicySnapshot(sessionID: sessionID, version: 0) { response in
            guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
                NSLog("ESFClient: failed to fetch initial snapshot for session \(sessionID)")
                let emptySnapshot = SessionCache(
                    sessionID: sessionID, rootPID: rootPID, version: 0,
                    fileRules: [], networkRules: [], dnsRules: [], execRules: [],
                    defaults: PolicyDefaults(file: "allow", network: "allow", dns: "allow", exec: "allow"))
                SessionPolicyCache.shared.registerSession(
                    sessionID: sessionID, rootPID: rootPID, snapshot: emptySnapshot)
                return
            }
            SessionPolicyCache.shared.registerSession(
                sessionID: sessionID, rootPID: rootPID, snapshot: snapshot)
            NSLog("ESFClient: registered session \(sessionID) with policy version \(snapshot.version)")
        }
    }

    /// Unregister a wrap session — called when the agent exits
    func unregisterSession(sessionID: String) {
        SessionPolicyCache.shared.unregisterSession(sessionID: sessionID)
        NSLog("ESFClient: unregistered session \(sessionID)")
    }

    /// Refresh the policy cache for a session after a Darwin notification
    private func refreshCacheForSession(_ sessionID: String) {
        let currentVersion = SessionPolicyCache.shared.versionForSession(sessionID)
        xpcProxy?.fetchPolicySnapshot(sessionID: sessionID, version: currentVersion) { response in
            guard let version = response["version"] as? UInt64 ?? (response["version"] as? Int).map({ UInt64($0) }),
                  version > 0 else { return }  // version 0 = no update available
            guard let rootPID = response["root_pid"] as? Int32 ?? (response["root_pid"] as? Int).map({ Int32($0) }) else { return }
            guard let snapshot = SessionCache.from(json: response, sessionID: sessionID, rootPID: rootPID) else {
                NSLog("ESFClient: failed to parse policy snapshot for session \(sessionID)")
                return
            }
            SessionPolicyCache.shared.updateSession(sessionID, snapshot: snapshot)
            NSLog("ESFClient: updated cache for session \(sessionID) to version \(version)")
        }
    }

    private func handleEvent(_ event: UnsafePointer<es_message_t>) {
        let message = event.pointee
        let pid = audit_token_to_pid(message.process.pointee.audit_token)

        switch message.event_type {
        // AUTH events - must respond
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleAuthOpen(event, pid: pid)
        case ES_EVENT_TYPE_AUTH_CREATE:
            handleAuthCreate(event, pid: pid)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            handleAuthUnlink(event, pid: pid)
        case ES_EVENT_TYPE_AUTH_RENAME:
            handleAuthRename(event, pid: pid)
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleAuthExec(event, pid: pid)

        // NOTIFY events - no response needed
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            handleNotifyClose(message, pid: pid)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleNotifyFork(message, pid: pid)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleNotifyExit(message, pid: pid)
        default:
            break
        }
    }

    // MARK: - AUTH Handlers

    private func handleAuthOpen(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = client else { return }

        // Fast-path: no active sessions means no policy to enforce
        if !SessionPolicyCache.shared.hasActiveSessions {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let path = String(cString: event.pointee.event.open.file.pointee.path.data)

        // Cache fast-path
        let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
            path: path, operation: "read", pid: pid)

        switch decision {
        case .allow:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        case .deny:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        case .fallthrough_:
            // XPC round-trip
            es_retain_message(event)
            xpcProxy?.checkFile(path: path, operation: "read", pid: pid, sessionID: sessionID) {
                [weak self] allow, _ in
                defer { es_release_message(event) }
                guard let client = self?.client else { return }
                let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
                es_respond_auth_result(client, event, result, false)
            }
        }
    }

    private func handleAuthCreate(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = client else { return }

        // Fast-path: no active sessions means no policy to enforce
        if !SessionPolicyCache.shared.hasActiveSessions {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Extract path based on destination_type
        let create = event.pointee.event.create
        let path: String
        if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            path = String(cString: create.destination.existing_file.pointee.path.data)
        } else {
            let dir = String(cString: create.destination.new_path.dir.pointee.path.data)
            let filename = String(cString: create.destination.new_path.filename.data)
            path = dir + "/" + filename
        }

        let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
            path: path, operation: "create", pid: pid)

        switch decision {
        case .allow:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        case .deny:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        case .fallthrough_:
            es_retain_message(event)
            xpcProxy?.checkFile(path: path, operation: "create", pid: pid, sessionID: sessionID) {
                [weak self] allow, _ in
                defer { es_release_message(event) }
                guard let client = self?.client else { return }
                let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
                es_respond_auth_result(client, event, result, false)
            }
        }
    }

    private func handleAuthUnlink(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = client else { return }

        // Fast-path: no active sessions means no policy to enforce
        if !SessionPolicyCache.shared.hasActiveSessions {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let path = String(cString: event.pointee.event.unlink.target.pointee.path.data)

        let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(
            path: path, operation: "delete", pid: pid)

        switch decision {
        case .allow:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        case .deny:
            es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
        case .fallthrough_:
            es_retain_message(event)
            xpcProxy?.checkFile(path: path, operation: "delete", pid: pid, sessionID: sessionID) {
                [weak self] allow, _ in
                defer { es_release_message(event) }
                guard let client = self?.client else { return }
                let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
                es_respond_auth_result(client, event, result, false)
            }
        }
    }

    private func handleAuthRename(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = client else { return }

        // Fast-path: no active sessions means no policy to enforce
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

        // Evaluate both paths
        let (srcDecision, sessionID) = SessionPolicyCache.shared.evaluateFile(
            path: sourcePath, operation: "rename", pid: pid)
        let (dstDecision, _) = SessionPolicyCache.shared.evaluateFile(
            path: destPath, operation: "create", pid: pid)

        // If either is denied by cache, deny immediately
        if srcDecision == .deny || dstDecision == .deny {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
            return
        }
        if srcDecision == .allow && dstDecision == .allow {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Fallthrough — XPC for source then dest
        es_retain_message(event)
        xpcProxy?.checkFile(path: sourcePath, operation: "rename", pid: pid, sessionID: sessionID) {
            [weak self] srcAllow, _ in
            guard srcAllow else {
                defer { es_release_message(event) }
                guard let client = self?.client else { return }
                es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
                return
            }
            self?.xpcProxy?.checkFile(path: destPath, operation: "create", pid: pid, sessionID: sessionID) {
                [weak self] dstAllow, _ in
                defer { es_release_message(event) }
                guard let client = self?.client else { return }
                let result: es_auth_result_t = dstAllow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
                es_respond_auth_result(client, event, result, false)
            }
        }
    }

    private func handleAuthExec(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = client else { return }

        // Fast path: if no active sessions, allow everything immediately.
        // This is the hot path — lock-free atomic read, no allocations.
        if !SessionPolicyCache.shared.hasActiveSessions {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Check if this process is in any active session tree
        let sessionID = SessionPolicyCache.shared.sessionForPID(pid)
        if sessionID == nil {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Process is in a session — do the full pipeline check
        // Retain message for async callback - message only valid during sync callback
        es_retain_message(event)

        // Get a pointer to the exec event within the original message buffer.
        // es_exec_arg/es_exec_arg_count navigate packed data from the event pointer,
        // so we must point into the real allocation — a struct copy would be wrong.
        let execPtr = UnsafeRawPointer(event)
            .advanced(by: MemoryLayout.offset(of: \es_message_t.event)!)
            .assumingMemoryBound(to: es_event_exec_t.self)
        let execPath = String(cString: execPtr.pointee.target.pointee.executable.pointee.path.data)

        // Extract argv using length-aware conversion.
        // es_string_token_t is NOT guaranteed NUL-terminated, so we use the
        // explicit length field to avoid reading past bounds.
        let argc = es_exec_arg_count(execPtr)
        var args: [String] = []
        for i in 0..<argc {
            let arg = es_exec_arg(execPtr, i)
            let len = Int(arg.length)
            if len > 0, let data = arg.data {
                let str = String(
                    bytes: UnsafeRawBufferPointer(start: data, count: len),
                    encoding: .utf8
                ) ?? String(cString: data)  // Fallback for non-UTF8
                args.append(str)
            } else {
                args.append("")
            }
        }

        let parentPID = event.pointee.process.pointee.ppid

        // Extract TTY from the process and CWD from the exec event.
        // These are passed through XPC to the Go server for exec redirect.
        var ttyPath: String? = nil
        if let ttyFile = event.pointee.process.pointee.tty {
            ttyPath = String(cString: ttyFile.pointee.path.data)
        }
        let cwdPath = String(cString: execPtr.pointee.cwd.pointee.path.data)

        let _ = SessionPolicyCache.shared.recordExecDepth(pid: pid, parentPID: parentPID)

        xpcProxy?.checkExecPipeline(
            executable: execPath,
            args: args,
            pid: pid,
            parentPID: parentPID,
            sessionID: sessionID,
            ttyPath: ttyPath,
            cwdPath: cwdPath
        ) { [weak self] decision, action, rule in
            defer { es_release_message(event) }
            guard let client = self?.client else { return }

            switch action {
            case "continue":
                // Allow exec in-place (common case, zero overhead)
                es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)

            case "deny":
                // Block the exec
                es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)

            case "redirect":
                // Deny the exec, then spawn stub (handled server-side via Go exec pipeline)
                es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)

            default:
                // Unknown action — fail-closed to prevent accidental allows
                NSLog("ESFClient: unknown action '\(action)' for exec \(execPath), denying (fail-closed)")
                es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
            }
        }
    }

    // MARK: - NOTIFY Handlers

    private func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
        // Fast-path: skip all work if no active sessions
        guard SessionPolicyCache.shared.hasActiveSessions else { return }

        // Only track forks from processes in active sessions
        guard SessionPolicyCache.shared.sessionForPID(pid) != nil else { return }

        let childToken = message.event.fork.child.pointee.audit_token
        let childPid = audit_token_to_pid(childToken)

        // Cache audit token for muting
        cacheQueue.sync {
            auditTokenCache[childPid] = childToken
        }

        ProcessHierarchy.shared.recordFork(parentPID: pid, childPID: childPid)
        SessionPolicyCache.shared.addPID(childPid, parentPID: pid)
    }

    private func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
        // Fast-path: skip all work if no active sessions
        guard SessionPolicyCache.shared.hasActiveSessions else { return }

        // Only clean up PIDs that are in active sessions
        guard SessionPolicyCache.shared.sessionForPID(pid) != nil else { return }

        // Clean up audit token cache
        cacheQueue.sync {
            _ = auditTokenCache.removeValue(forKey: pid)
        }

        SessionPolicyCache.shared.removePID(pid)

        // Clean up hierarchy tracking and invalidate process info cache
        ProcessHierarchy.shared.recordExit(pid: pid)
        ProcessIdentifier.invalidate(pid: pid)
    }

    private func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
        guard message.event.close.modified else { return }
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

        let path = String(cString: message.event.close.target.pointee.path.data)

        let payload: [String: Any] = [
            "type": "file_write",
            "path": path,
            "operation": "close_modified",
            "pid": Int(pid),
            "session_id": sessionID,
            "timestamp": Self.isoFormatter.string(from: Date())
        ]

        if let data = try? JSONSerialization.data(withJSONObject: payload) {
            xpcProxy?.emitEvent(event: data) { _ in }
        }
    }

    // TODO: Add handleNotifySetattr when macOS 26 SDK is available in CI.
    // It should subscribe to ES_EVENT_TYPE_NOTIFY_SETATTR and emit file_chown/file_chmod events.
}
