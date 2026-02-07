// macos/SysExt/ESFClient.swift
import Foundation
import EndpointSecurity

/// Handles Endpoint Security Framework events.
class ESFClient {
    private var client: OpaquePointer?
    private let xpc: NSXPCConnection
    private var xpcProxy: AgentshXPCProtocol?

    // Serial queue for thread-safe access to client
    private let clientQueue = DispatchQueue(label: "com.agentsh.esfclient")

    /// Cache of PID -> audit_token_t for muting
    private var auditTokenCache: [pid_t: audit_token_t] = [:]
    private let cacheQueue = DispatchQueue(label: "com.agentsh.audittokencache")

    /// Active wrap sessions: maps session root PID to session ID
    private var activeSessions: [pid_t: String] = [:]
    private let sessionQueue = DispatchQueue(label: "com.agentsh.sessions")

    init() {
        // Connect to XPC Service
        xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
        xpc.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        xpc.resume()

        xpcProxy = xpc.remoteObjectProxyWithErrorHandler { error in
            NSLog("XPC error: \(error)")
        } as? AgentshXPCProtocol
    }

    deinit {
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

        clientQueue.sync {
            self.client = newClient
        }

        // Subscribe to AUTH events (blocking)
        let authEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_EXEC
        ]

        // Subscribe to NOTIFY events (observation)
        let notifyEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_FORK
        ]

        let allEvents = authEvents + notifyEvents
        let subscribeResult = es_subscribe(newClient, allEvents, UInt32(allEvents.count))

        guard subscribeResult == ES_RETURN_SUCCESS else {
            NSLog("Failed to subscribe: \(subscribeResult.rawValue)")
            clientQueue.sync {
                es_delete_client(newClient)
                self.client = nil
            }
            return false
        }

        NSLog("ESF client started successfully")
        return true
    }

    func stop() {
        clientQueue.sync {
            if let client = client {
                es_delete_client(client)
                self.client = nil
            }
        }
        xpc.invalidate()
    }

    private func getClient() -> OpaquePointer? {
        return clientQueue.sync { client }
    }

    // MARK: - Process Muting (Recursion Guard)

    /// Mute a process and all its descendants so ES events are not delivered for them.
    /// Used for recursion prevention — agentsh-spawned commands must not be re-intercepted.
    func muteProcess(auditToken: audit_token_t) {
        guard let client = getClient() else { return }
        var token = auditToken
        let result = es_mute_process(client, &token)
        if result != ES_RETURN_SUCCESS {
            NSLog("ESFClient: failed to mute process: \(result.rawValue)")
        } else {
            // Muted processes won't emit ES_EVENT_TYPE_NOTIFY_EXIT, so clean up
            // the audit token cache now to prevent stale entries and unbounded growth.
            let pid = audit_token_to_pid(token)
            cacheQueue.sync {
                auditTokenCache.removeValue(forKey: pid)
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

    /// Register a wrap session — called when agentsh wrap starts an agent
    func registerSession(rootPID: pid_t, sessionID: String) {
        sessionQueue.sync {
            activeSessions[rootPID] = sessionID
        }
        NSLog("ESFClient: registered session \(sessionID) for root PID \(rootPID)")
    }

    /// Unregister a wrap session — called when the agent exits
    func unregisterSession(rootPID: pid_t) {
        sessionQueue.sync {
            activeSessions.removeValue(forKey: rootPID)
        }
        NSLog("ESFClient: unregistered session for root PID \(rootPID)")
    }

    /// Find which session (if any) a process belongs to by walking its ancestry.
    private func findSession(forPID pid: pid_t) -> (rootPID: pid_t, sessionID: String)? {
        return sessionQueue.sync {
            // Check if pid is directly a session root
            if let sid = activeSessions[pid] {
                return (pid, sid)
            }
            // Walk ancestors to find session root
            let ancestors = ProcessHierarchy.shared.getAncestors(pid: pid)
            for ancestor in ancestors {
                if let sid = activeSessions[ancestor] {
                    return (ancestor, sid)
                }
            }
            return nil
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
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            handleNotifyWrite(message, pid: pid)
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
        guard let client = getClient() else { return }

        // Copy message for async callback - message only valid during sync callback
        guard let messageCopy = es_copy_message(event) else {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let path = String(cString: event.pointee.event.open.file.pointee.path.data)

        xpcProxy?.checkFile(path: path, operation: "read", pid: pid, sessionID: nil) { [weak self] allow, _ in
            guard let client = self?.getClient() else {
                es_free_message(messageCopy)
                return
            }
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, messageCopy, result, false)
            es_free_message(messageCopy)
        }
    }

    private func handleAuthCreate(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = getClient() else { return }
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthUnlink(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = getClient() else { return }
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthRename(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = getClient() else { return }
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
    }

    private func handleAuthExec(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
        guard let client = getClient() else { return }

        // Fast path: if no active sessions, allow everything immediately.
        // Sessions are populated via registerSession() which is called from the
        // Go server through the register_session XPC request when agentsh wrap starts.
        // Until at least one session is registered, all AUTH_EXEC events pass through
        // without policy checks — this is by design (no wrapping = no interception).
        let hasActiveSessions = sessionQueue.sync { !activeSessions.isEmpty }
        if !hasActiveSessions {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Check if this process is in any active session tree
        let sessionInfo = findSession(forPID: pid)
        if sessionInfo == nil {
            // Not in any active session — allow immediately, no policy check
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        // Process is in a session — do the full pipeline check
        // Copy message for async callback - message only valid during sync callback
        guard let messageCopy = es_copy_message(event) else {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let execEvent = event.pointee.event.exec
        let execPath = String(cString: execEvent.target.pointee.executable.pointee.path.data)

        // Extract argv from the exec event using length-aware conversion.
        // es_string_token_t is NOT guaranteed NUL-terminated, so we use the
        // explicit length field to avoid reading past bounds.
        let argc = es_exec_arg_count(&event.pointee.event.exec)
        var args: [String] = []
        for i in 0..<argc {
            let arg = es_exec_arg(&event.pointee.event.exec, i)
            let len = Int(arg.length)
            if len > 0, let data = arg.data {
                let str = String(
                    bytes: UnsafeBufferPointer(start: data, count: len),
                    encoding: .utf8
                ) ?? String(cString: data)  // Fallback for non-UTF8
                args.append(str)
            } else {
                args.append("")
            }
        }

        let parentPID = event.pointee.process.pointee.ppid

        xpcProxy?.checkExecPipeline(
            executable: execPath,
            args: args,
            pid: pid,
            parentPID: parentPID,
            sessionID: sessionInfo?.sessionID
        ) { [weak self] decision, action, rule in
            guard let client = self?.getClient() else {
                es_free_message(messageCopy)
                return
            }

            switch action {
            case "continue":
                // Allow exec in-place (common case, zero overhead)
                es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_ALLOW, false)

            case "deny":
                // Block the exec
                es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_DENY, false)

            case "redirect":
                // Deny the exec, then spawn stub (handled server-side via Go exec pipeline)
                es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_DENY, false)

            default:
                // Unknown action — fail-closed to prevent accidental allows
                NSLog("ESFClient: unknown action '\(action)' for exec \(execPath), denying (fail-closed)")
                es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_DENY, false)
            }

            es_free_message(messageCopy)
        }
    }

    // MARK: - NOTIFY Handlers

    private func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
        // Track parent-child relationship for session scoping and PNACL inheritance
        let childToken = message.event.fork.child.pointee.audit_token
        let childPid = audit_token_to_pid(childToken)

        // Cache audit token for muting
        cacheQueue.sync {
            auditTokenCache[childPid] = childToken
        }

        ProcessHierarchy.shared.recordFork(parentPID: pid, childPID: childPid)
        NSLog("Fork: \(pid) -> \(childPid)")
    }

    private func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
        // Clean up audit token cache
        cacheQueue.sync {
            auditTokenCache.removeValue(forKey: pid)
        }

        // Clean up session registration if this was a session root
        sessionQueue.sync {
            activeSessions.removeValue(forKey: pid)
        }

        // Clean up hierarchy tracking and invalidate process info cache
        ProcessHierarchy.shared.recordExit(pid: pid)
        ProcessIdentifier.invalidate(pid: pid)
        NSLog("Exit: \(pid)")
    }

    private func handleNotifyWrite(_ message: es_message_t, pid: pid_t) {
        // Log write completions (high volume, observation only)
        // In production, would emit event to agentsh server
    }

    private func handleNotifyClose(_ message: es_message_t, pid: pid_t) {
        // Log file close with write flag (observation only)
        // In production, would emit event to agentsh server
    }
}
