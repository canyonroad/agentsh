// macos/XPCService/PolicyBridge.swift
import Foundation

/// Fail behavior when the policy server is unreachable.
enum FailBehavior {
    case failOpen   // Allow connections on error (availability priority)
    case failClosed // Deny connections on error (security priority)
}

/// Bridges XPC calls to the Go policy server via Unix socket.
class PolicyBridge: NSObject, AgentshXPCProtocol {
    private let socketPath = "/var/run/agentsh/policy.sock"
    private let timeout: TimeInterval = 5.0

    /// Configurable fail behavior. Default is failOpen for availability.
    /// Set to failClosed for security-critical deployments.
    var failBehavior: FailBehavior = .failOpen

    func checkFile(
        path: String,
        operation: String,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "file",
            "path": path,
            "operation": operation,
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    func checkNetwork(
        ip: String,
        port: Int,
        domain: String?,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "network",
            "ip": ip,
            "port": port,
            "domain": domain ?? "",
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    func checkCommand(
        executable: String,
        args: [String],
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "command",
            "path": executable,
            "args": args,
            "pid": pid,
            "session_id": sessionID ?? ""
        ]
        sendRequest(request) { response in
            let allow = response["allow"] as? Bool ?? true
            let rule = response["rule"] as? String
            reply(allow, rule)
        }
    }

    // MARK: - Exec Pipeline

    func checkExecPipeline(
        executable: String,
        args: [String],
        pid: pid_t,
        parentPID: pid_t,
        sessionID: String?,
        ttyPath: String?,
        cwdPath: String?,
        reply: @escaping (String, String, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "exec_check",
            "path": executable,
            "args": args,
            "pid": pid,
            "parent_pid": parentPID,
            "session_id": sessionID ?? "",
            "tty_path": ttyPath ?? "",
            "cwd_path": cwdPath ?? ""
        ]
        sendRequest(request) { [weak self] response in
            // Check if this was an error response from sendRequest.
            // On error, sendRequest returns {"allow": bool, "rule": "error-fail*"}.
            // For exec pipeline, we must respect failBehavior for the action too.
            let rule = response["rule"] as? String ?? ""
            if rule == "error-failclosed" {
                // Fail-closed: deny the exec on communication error
                reply("deny", "deny", "error-failclosed")
                return
            } else if rule == "error-failopen" {
                // Fail-open: allow the exec on communication error
                reply("allow", "continue", "error-failopen")
                return
            }

            let decision = response["exec_decision"] as? String ?? "allow"
            let action = response["action"] as? String ?? "continue"
            reply(decision, action, response["rule"] as? String)
        }
    }

    // MARK: - Process Muting (Recursion Guard)

    func muteProcess(pid: pid_t, reply: @escaping (Bool) -> Void) {
        // Route mute request through the Go policy server's Unix socket.
        // The server forwards it to the ESFClient via the session registrar interface.
        // Note: NotificationCenter.default does not cross process boundaries,
        // so we use the socket-based channel instead.
        let request: [String: Any] = [
            "type": "mute_process",
            "pid": pid
        ]
        sendRequest(request) { response in
            let success = response["success"] as? Bool ?? false
            reply(success)
        }
    }

    func resolveSession(pid: pid_t, reply: @escaping (String?) -> Void) {
        let request: [String: Any] = [
            "type": "session",
            "pid": pid
        ]
        sendRequest(request) { response in
            let sessionID = response["session_id"] as? String
            reply(sessionID?.isEmpty == true ? nil : sessionID)
        }
    }

    func emitEvent(event: Data, reply: @escaping (Bool) -> Void) {
        let request: [String: Any] = [
            "type": "event",
            "event_data": event.base64EncodedString()
        ]
        sendRequest(request) { _ in
            reply(true)
        }
    }

    // MARK: - PNACL Methods

    func checkNetworkPNACL(
        ip: String,
        port: Int,
        protocol proto: String,
        domain: String?,
        pid: pid_t,
        bundleID: String?,
        executablePath: String?,
        processName: String?,
        parentPID: pid_t,
        reply: @escaping (String, String?) -> Void
    ) {
        let request: [String: Any] = [
            "type": "pnacl_check",
            "ip": ip,
            "port": port,
            "protocol": proto,
            "domain": domain ?? "",
            "pid": pid,
            "bundle_id": bundleID ?? "",
            "executable_path": executablePath ?? "",
            "process_name": processName ?? "",
            "parent_pid": parentPID
        ]
        sendRequest(request) { [weak self] response in
            // Check if this was an error response - respect fail behavior for PNACL
            let rule = response["rule"] as? String ?? ""
            if rule == "error-failclosed" {
                reply("deny", nil)
                return
            } else if rule == "error-failopen" {
                reply("allow", nil)
                return
            }

            let decision = response["decision"] as? String ?? (self?.failBehavior == .failOpen ? "allow" : "deny")
            let ruleID = response["rule_id"] as? String
            reply(decision, ruleID)
        }
    }

    func reportPNACLEvent(
        eventType: String,
        ip: String,
        port: Int,
        protocol proto: String,
        domain: String?,
        pid: pid_t,
        bundleID: String?,
        decision: String,
        ruleID: String?,
        reply: @escaping (Bool) -> Void
    ) {
        let request: [String: Any] = [
            "type": "pnacl_event",
            "event_type": eventType,
            "ip": ip,
            "port": port,
            "protocol": proto,
            "domain": domain ?? "",
            "pid": pid,
            "bundle_id": bundleID ?? "",
            "decision": decision,
            "rule_id": ruleID ?? ""
        ]
        sendRequest(request) { _ in
            reply(true)
        }
    }

    // MARK: - PNACL Approval Flow (Phase 3)

    func getPendingApprovals(reply: @escaping ([ApprovalRequest]) -> Void) {
        let request: [String: Any] = [
            "type": "get_pending_approvals"
        ]
        sendRequest(request) { response in
            var approvals: [ApprovalRequest] = []

            if let approvalsArray = response["approvals"] as? [[String: Any]] {
                for json in approvalsArray {
                    if let approval = ApprovalRequest.from(json: json) {
                        approvals.append(approval)
                    }
                }
            }

            reply(approvals)
        }
    }

    func submitApprovalDecision(
        requestID: String,
        decision: String,
        permanent: Bool,
        reply: @escaping (Bool) -> Void
    ) {
        let request: [String: Any] = [
            "type": "submit_approval",
            "request_id": requestID,
            "decision": decision,
            "permanent": permanent
        ]
        sendRequest(request) { response in
            let success = response["success"] as? Bool ?? false
            reply(success)
        }
    }

    /// Fetch pending approvals for polling (internal use by ApprovalManager).
    /// Returns (approvals, success) - success is false if server communication failed.
    func fetchPendingApprovals(completion: @escaping ([ApprovalRequest], Bool) -> Void) {
        let request: [String: Any] = [
            "type": "get_pending_approvals"
        ]
        sendRequest(request) { response in
            // Check if this was an error response
            let isError = response["rule"] as? String == "error-failopen" ||
                          response["rule"] as? String == "error-failclosed"

            if isError {
                completion([], false)
                return
            }

            var approvals: [ApprovalRequest] = []
            if let approvalsArray = response["approvals"] as? [[String: Any]] {
                for json in approvalsArray {
                    if let approval = ApprovalRequest.from(json: json) {
                        approvals.append(approval)
                    }
                }
            }
            completion(approvals, true)
        }
    }

    // MARK: - PNACL Configuration (Phase 4)

    /// Current blocking configuration state.
    /// These values are sent to FilterDataProvider when it queries configuration.
    private var pnaclBlockingEnabled: Bool = false
    private var pnaclDecisionTimeout: Double = 0.1
    private var pnaclFailOpen: Bool = true

    func configurePNACLBlocking(
        blockingEnabled: Bool,
        decisionTimeout: Double,
        failOpen: Bool,
        reply: @escaping (Bool) -> Void
    ) {
        // Store configuration locally for FilterDataProvider to query
        pnaclBlockingEnabled = blockingEnabled
        pnaclDecisionTimeout = decisionTimeout
        pnaclFailOpen = failOpen

        // Synchronize failBehavior so error handling respects this config
        failBehavior = failOpen ? .failOpen : .failClosed

        // Also notify the Go server of the configuration change
        let request: [String: Any] = [
            "type": "pnacl_configure",
            "blocking_enabled": blockingEnabled,
            "decision_timeout": decisionTimeout,
            "fail_open": failOpen
        ]
        sendRequest(request) { response in
            let success = response["success"] as? Bool ?? true
            reply(success)
        }
    }

    func getPNACLBlockingConfig(
        reply: @escaping (Bool, Double, Bool) -> Void
    ) {
        reply(pnaclBlockingEnabled, pnaclDecisionTimeout, pnaclFailOpen)
    }

    // MARK: - Socket Communication

    private func sendRequest(
        _ request: [String: Any],
        completion: @escaping ([String: Any]) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else {
                completion(["allow": true])
                return
            }

            do {
                let response = try self.sendSync(request)
                DispatchQueue.main.async {
                    completion(response)
                }
            } catch {
                // Handle error based on configured fail behavior
                let allow = self.failBehavior == .failOpen
                let ruleDesc = allow ? "error-failopen" : "error-failclosed"
                NSLog("PolicyBridge error (fail-\(allow ? "open" : "closed")): \(error)")
                DispatchQueue.main.async {
                    completion(["allow": allow, "rule": ruleDesc])
                }
            }
        }
    }

    private func sendSync(_ request: [String: Any]) throws -> [String: Any] {
        // Create Unix socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw BridgeError.socketCreation
        }
        defer { close(fd) }

        // Connect
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            socketPath.withCString { cstr in
                strcpy(ptr, cstr)
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, addrLen)
            }
        }

        guard result == 0 else {
            throw BridgeError.connectionFailed
        }

        // Set timeout
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Send request
        let requestData = try JSONSerialization.data(withJSONObject: request)
        var dataWithNewline = requestData
        dataWithNewline.append(0x0A) // newline

        // Send request (loop to handle partial writes)
        var totalWritten = 0
        while totalWritten < dataWithNewline.count {
            let written = dataWithNewline.withUnsafeBytes { ptr in
                write(fd, ptr.baseAddress! + totalWritten, ptr.count - totalWritten)
            }
            if written <= 0 {
                throw BridgeError.writeFailed
            }
            totalWritten += written
        }

        // Read response (loop until newline delimiter, handling partial reads)
        var responseBuffer = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        let maxResponseSize = 1024 * 1024  // 1MB limit

        while true {
            let bytesRead = read(fd, &buffer, buffer.count)

            if bytesRead < 0 {
                throw BridgeError.readFailed
            }

            if bytesRead == 0 {
                // Connection closed
                if responseBuffer.isEmpty {
                    throw BridgeError.readFailed
                }
                break
            }

            responseBuffer.append(contentsOf: buffer[0..<bytesRead])

            // Check for response size limit
            if responseBuffer.count > maxResponseSize {
                throw BridgeError.readFailed
            }

            // Check if we've received the complete message (ends with newline)
            if let lastByte = responseBuffer.last, lastByte == 0x0A {
                break
            }
        }

        guard let response = try JSONSerialization.jsonObject(with: responseBuffer) as? [String: Any] else {
            throw BridgeError.invalidResponse
        }

        return response
    }

    enum BridgeError: Error {
        case socketCreation
        case connectionFailed
        case writeFailed
        case readFailed
        case invalidResponse
    }
}
