// macos/ApprovalDialog/ServerClient.swift
import Foundation

/// Local struct representing approval request data for the dialog UI.
/// This mirrors the properties from Shared/ApprovalRequest needed for display.
struct ApprovalRequestData {
    let requestID: String
    let processName: String
    let bundleID: String?
    let pid: Int32
    let targetHost: String
    let targetPort: Int
    let targetProtocol: String
    let timestamp: Date
    let timeout: TimeInterval
    let executablePath: String?

    /// Creates an ApprovalRequestData from a JSON dictionary (from Go server).
    static func from(json: [String: Any]) -> ApprovalRequestData? {
        // Validate required fields with detailed logging for debugging
        guard let requestID = json["request_id"] as? String else {
            NSLog("ApprovalRequestData: Missing or invalid 'request_id' in JSON")
            return nil
        }
        guard let processName = json["process_name"] as? String else {
            NSLog("ApprovalRequestData: Missing or invalid 'process_name' in JSON for request \(requestID)")
            return nil
        }
        guard let targetHost = json["target_host"] as? String else {
            NSLog("ApprovalRequestData: Missing or invalid 'target_host' in JSON for request \(requestID)")
            return nil
        }
        guard let targetPort = json["target_port"] as? Int else {
            NSLog("ApprovalRequestData: Missing or invalid 'target_port' in JSON for request \(requestID)")
            return nil
        }
        guard let targetProtocol = json["target_protocol"] as? String else {
            NSLog("ApprovalRequestData: Missing or invalid 'target_protocol' in JSON for request \(requestID)")
            return nil
        }
        guard let timeout = json["timeout"] as? Double else {
            NSLog("ApprovalRequestData: Missing or invalid 'timeout' in JSON for request \(requestID)")
            return nil
        }

        let pid: Int32
        if let pid32 = json["pid"] as? Int32 {
            pid = pid32
        } else if let pidInt = json["pid"] as? Int {
            pid = Int32(pidInt)
        } else {
            pid = 0
        }
        let bundleID = json["bundle_id"] as? String
        let executablePath = json["executable_path"] as? String

        // Parse timestamp (ISO 8601 or Unix timestamp)
        let timestamp: Date
        if let timestampStr = json["timestamp"] as? String {
            let formatter = ISO8601DateFormatter()
            timestamp = formatter.date(from: timestampStr) ?? Date()
        } else if let timestampUnix = json["timestamp_unix"] as? Double {
            timestamp = Date(timeIntervalSince1970: timestampUnix)
        } else {
            timestamp = Date()
        }

        return ApprovalRequestData(
            requestID: requestID,
            processName: processName,
            bundleID: bundleID,
            pid: pid,
            targetHost: targetHost,
            targetPort: targetPort,
            targetProtocol: targetProtocol,
            timestamp: timestamp,
            timeout: timeout,
            executablePath: executablePath
        )
    }
}

/// Client for communicating with the Go policy server via Unix socket.
/// Provides async/await API for fetching approvals and submitting decisions.
actor ServerClient {
    private let socketPath = "/var/run/agentsh/policy.sock"
    private let timeout: TimeInterval = 5.0

    /// Errors that can occur during server communication.
    enum ServerError: Error, LocalizedError {
        case socketCreation
        case connectionFailed
        case writeFailed
        case readFailed
        case invalidResponse
        case timeout
        case serverError(String)

        var errorDescription: String? {
            switch self {
            case .socketCreation:
                return "Failed to create socket"
            case .connectionFailed:
                return "Failed to connect to policy server"
            case .writeFailed:
                return "Failed to send request to server"
            case .readFailed:
                return "Failed to read response from server"
            case .invalidResponse:
                return "Invalid response from server"
            case .timeout:
                return "Request timed out"
            case .serverError(let message):
                return "Server error: \(message)"
            }
        }
    }

    /// Fetch a pending approval request by ID.
    /// - Parameter requestID: The unique identifier of the approval request.
    /// - Returns: The ApprovalRequestData if found, nil otherwise.
    func fetchApproval(requestID: String) async throws -> ApprovalRequestData? {
        let request: [String: Any] = [
            "type": "get_pending_approvals"
        ]

        let response = try await sendRequest(request)

        // Parse approvals array from response
        guard let approvalsArray = response["approvals"] as? [[String: Any]] else {
            return nil
        }

        // Find the approval with matching ID
        for json in approvalsArray {
            if let approval = ApprovalRequestData.from(json: json),
               approval.requestID == requestID {
                return approval
            }
        }

        return nil
    }

    /// Submit a decision for an approval request.
    /// - Parameters:
    ///   - requestID: The unique identifier of the approval request.
    ///   - decision: The decision string (e.g., "allow_once", "deny_once", "allow_always", "deny_always").
    ///   - permanent: Whether this decision should be saved as a permanent rule.
    /// - Returns: True if the decision was successfully submitted.
    func submitDecision(requestID: String, decision: String, permanent: Bool) async throws -> Bool {
        let request: [String: Any] = [
            "type": "submit_approval",
            "request_id": requestID,
            "decision": decision,
            "permanent": permanent
        ]

        let response = try await sendRequest(request)

        // Check for error in response
        if let errorMessage = response["error"] as? String {
            throw ServerError.serverError(errorMessage)
        }

        return response["success"] as? Bool ?? false
    }

    // MARK: - Private Methods

    /// Send a request to the policy server and return the response.
    private func sendRequest(_ request: [String: Any]) async throws -> [String: Any] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                do {
                    let response = try self.sendSync(request)
                    continuation.resume(returning: response)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Synchronously send a request and read the response.
    /// This method blocks and should be called from a background queue.
    private nonisolated func sendSync(_ request: [String: Any]) throws -> [String: Any] {
        // Create Unix socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ServerError.socketCreation
        }
        defer { close(fd) }

        // Connect to socket
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            socketPath.withCString { cstr in
                strcpy(ptr, cstr)
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, addrLen)
            }
        }

        guard connectResult == 0 else {
            throw ServerError.connectionFailed
        }

        // Set socket timeouts (5 seconds)
        var tv = timeval()
        tv.tv_sec = Int(timeout)
        tv.tv_usec = 0
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Serialize request to JSON
        let requestData = try JSONSerialization.data(withJSONObject: request)
        var dataWithNewline = requestData
        dataWithNewline.append(0x0A) // Append newline as message delimiter

        // Send request
        let written = dataWithNewline.withUnsafeBytes { ptr in
            write(fd, ptr.baseAddress, ptr.count)
        }
        guard written == dataWithNewline.count else {
            throw ServerError.writeFailed
        }

        // Read response
        var buffer = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(fd, &buffer, buffer.count)

        guard bytesRead > 0 else {
            if errno == EAGAIN || errno == EWOULDBLOCK {
                throw ServerError.timeout
            }
            throw ServerError.readFailed
        }

        // Parse response JSON
        let responseData = Data(bytes: buffer, count: bytesRead)
        guard let response = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw ServerError.invalidResponse
        }

        return response
    }
}
