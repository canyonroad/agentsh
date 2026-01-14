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

        // Copy message for async callback
        guard let messageCopy = es_copy_message(event) else {
            es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
            return
        }

        let execPath = String(cString: event.pointee.event.exec.target.pointee.executable.pointee.path.data)

        xpcProxy?.checkCommand(executable: execPath, args: [], pid: pid, sessionID: nil) { [weak self] allow, _ in
            guard let client = self?.getClient() else {
                es_free_message(messageCopy)
                return
            }
            let result: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(client, messageCopy, result, false)
            es_free_message(messageCopy)
        }
    }

    // MARK: - NOTIFY Handlers

    private func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
        // Track parent-child relationship for session scoping and PNACL inheritance
        let childPid = audit_token_to_pid(message.event.fork.child.pointee.audit_token)
        ProcessHierarchy.shared.recordFork(parentPID: pid, childPID: childPid)
        NSLog("Fork: \(pid) -> \(childPid)")
    }

    private func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
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
