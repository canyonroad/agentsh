// macos/SysExt/ESFClient.swift
import Foundation
import EndpointSecurity
import os.log

private let esLog = OSLog(subsystem: "ai.canyonroad.agentsh.SysExt", category: "ESF")

/// Handles Endpoint Security Framework events.
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

        // Subscribe to SETATTRLIST events for chmod/chown tracking (macOS 26+)
        if #available(macOS 26.0, *) {
            let setAttrEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_SETATTRLIST]
            es_subscribe(client, setAttrEvents, UInt32(setAttrEvents.count))
        }

        // Mute agentsh binaries to prevent recursion
        if #available(macOS 12.0, *) {
            for path in ["/usr/local/bin/agentsh-stub", "/usr/local/bin/agentsh"] {
                es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_LITERAL)
            }
        }
        return true
    }

    func stop() {
        if let client = client {
            es_delete_client(client)
            self.client = nil
        }
    }

    // MARK: - Process Muting (Recursion Guard)

    /// Mute a path so ES events are not delivered for processes at that path.
    /// Used for dynamic recursion prevention -- the Go server sends the actual
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
    /// Used for recursion prevention -- agentsh-spawned commands must not be re-intercepted.
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

    /// Refresh the policy cache for a session after a Darwin notification
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

    // MARK: - NOTIFY Handlers

    fileprivate func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
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

        PolicySocketClient.shared.sendEvent([
            "type": "file_event",
            "event_type": "process_fork",
            "pid": Int(pid),
            "child_pid": Int(childPid),
            "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ])
    }

    fileprivate func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
        // Fast-path: skip all work if no active sessions
        guard SessionPolicyCache.shared.hasActiveSessions else { return }

        // Only clean up PIDs that are in active sessions
        guard SessionPolicyCache.shared.sessionForPID(pid) != nil else { return }

        // Clean up audit token cache
        cacheQueue.sync {
            _ = auditTokenCache.removeValue(forKey: pid)
        }

        PolicySocketClient.shared.sendEvent([
            "type": "file_event",
            "event_type": "process_exit",
            "pid": Int(pid),
            "session_id": SessionPolicyCache.shared.sessionForPID(pid) ?? "",
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ])

        SessionPolicyCache.shared.removePID(pid)

        // Clean up hierarchy tracking and invalidate process info cache
        ProcessHierarchy.shared.recordExit(pid: pid)
        ProcessIdentifier.invalidate(pid: pid)
    }

    fileprivate func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
        guard message.event.close.modified else { return }
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else { return }

        let path = String(cString: message.event.close.target.pointee.path.data)

        sendFileEvent(
            eventType: "file_write",
            path: path,
            operation: "close_modified",
            pid: pid,
            sessionID: sessionID,
            decision: "observed",
            rule: nil
        )
    }

    @available(macOS 26.0, *)
    fileprivate func handleNotifySetattr(_ message: es_message_t, pid: pid_t) {
        let sessionID = SessionPolicyCache.shared.sessionForPID(pid)
        guard let sessionID = sessionID else { return }

        let path = String(cString: message.event.setattrlist.target.pointee.path.data)
        let attr = message.event.setattrlist.attrlist

        if attr.commonattr & attrgroup_t(ATTR_CMN_OWNERID) != 0 ||
           attr.commonattr & attrgroup_t(ATTR_CMN_GRPID) != 0 {
            sendFileEvent(eventType: "file_chown", path: path, operation: "chown",
                          pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
        }

        if attr.commonattr & attrgroup_t(ATTR_CMN_ACCESSMASK) != 0 {
            sendFileEvent(eventType: "file_chmod", path: path, operation: "chmod",
                          pid: pid, sessionID: sessionID, decision: "observed", rule: nil)
        }
    }
}

// MARK: - Free Function Helpers

/// Build and send a file event dict via the persistent event stream.
/// This is a free function (not a method on ESFClient) so AUTH handlers can call it.
private func sendFileEvent(
    eventType: String,
    path: String,
    operation: String,
    pid: pid_t,
    sessionID: String?,
    decision: String,
    rule: String?,
    action: String? = nil,
    extraFields: [String: Any]? = nil
) {
    var dict: [String: Any] = [
        "type": "file_event",
        "event_type": eventType,
        "path": path,
        "operation": operation,
        "pid": Int(pid),
        "session_id": sessionID ?? "",
        "decision": decision,
        "rule": rule ?? "",
        "timestamp": ISO8601DateFormatter().string(from: Date())
    ]
    if let action = action {
        dict["action"] = action
    }
    if let extra = extraFields {
        for (k, v) in extra {
            dict[k] = v
        }
    }
    PolicySocketClient.shared.sendEvent(dict)
}

// MARK: - Free Function Event Handlers (AUTH)

/// Free function -- no instance state needed for AUTH responses.
/// AUTH handlers use the `client` pointer from the callback (always valid).
/// NOTIFY handlers delegate to ESFClient.shared (best-effort).
private func handleESEvent(client: OpaquePointer, event: UnsafePointer<es_message_t>) {
    let message = event.pointee
    let eventType = message.event_type.rawValue
    let pid = audit_token_to_pid(message.process.pointee.audit_token)

    os_log(.debug, log: esLog, "handleESEvent: type=%{public}d pid=%{public}d", eventType, pid)

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
    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
        if #available(macOS 26.0, *) {
            ESFClient.shared?.handleNotifySetattr(message, pid: pid)
        }
    default:
        // Safety: respond to any unexpected AUTH event to prevent deadline kill
        if event.pointee.action_type == ES_ACTION_TYPE_AUTH {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            os_log(.error, log: esLog, "UNHANDLED AUTH event type=%{public}d pid=%{public}d — allowed as safety fallback", eventType, pid)
        }
    }
}

private func handleAuthOpen(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    // AUTH_OPEN requires es_respond_flags_result, NOT es_respond_auth_result.
    // Using the wrong function returns ES_RESPOND_RESULT_ERR_EVENT_TYPE and
    // leaves the event unanswered, causing the deadline kill.
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_flags_result(client, event, 0x7FFFFFFF, false)
        return
    }

    let path = String(cString: event.pointee.event.open.file.pointee.path.data)

    // Determine operation from open flags
    let fflag = event.pointee.event.open.fflag
    let operation: String
    if (Int32(fflag) & FWRITE) != 0 {
        operation = "write"
    } else {
        operation = "read"
    }

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: operation, pid: pid)

    if decision == .deny {
        es_respond_flags_result(client, event, 0, false)
    } else {
        es_respond_flags_result(client, event, 0x7FFFFFFF, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_open",
            path: path,
            operation: operation,
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
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

    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "create", pid: pid)
    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_create",
            path: path,
            operation: "create",
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
    }
}

private func handleAuthUnlink(client: OpaquePointer, event: UnsafePointer<es_message_t>, pid: pid_t) {
    if !SessionPolicyCache.shared.hasActiveSessions {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let path = String(cString: event.pointee.event.unlink.target.pointee.path.data)
    let (decision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: path, operation: "delete", pid: pid)

    if decision == .deny {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_delete",
            path: path,
            operation: "delete",
            pid: pid,
            sessionID: sessionID,
            decision: decision == .deny ? "deny" : "allow",
            rule: nil
        )
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

    let (srcDecision, sessionID) = SessionPolicyCache.shared.evaluateFile(path: sourcePath, operation: "rename", pid: pid)
    let (dstDecision, _) = SessionPolicyCache.shared.evaluateFile(path: destPath, operation: "create", pid: pid)

    let denied = srcDecision == .deny || dstDecision == .deny
    if denied {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_DENY, false)
    } else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    // Forward event for PIDs in active sessions
    if let sessionID = sessionID {
        sendFileEvent(
            eventType: "file_rename",
            path: sourcePath,
            operation: "rename",
            pid: pid,
            sessionID: sessionID,
            decision: denied ? "deny" : "allow",
            rule: nil,
            extraFields: ["path2": destPath]
        )
    }
}

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

    // Evaluate locally -- single call returns allow/deny/redirect in one lock acquisition
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
