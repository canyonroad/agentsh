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
        sendRequest(request) { response in
            let decision = response["decision"] as? String ?? "allow"
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

        let written = dataWithNewline.withUnsafeBytes { ptr in
            write(fd, ptr.baseAddress, ptr.count)
        }
        guard written == dataWithNewline.count else {
            throw BridgeError.writeFailed
        }

        // Read response
        var buffer = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(fd, &buffer, buffer.count)
        guard bytesRead > 0 else {
            throw BridgeError.readFailed
        }

        let responseData = Data(bytes: buffer, count: bytesRead)
        guard let response = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
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
