// macos/ApprovalDialog/ServerClient.swift
import Foundation

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

        // Send request (loop to handle partial writes)
        var totalWritten = 0
        while totalWritten < dataWithNewline.count {
            let written = dataWithNewline.withUnsafeBytes { ptr in
                write(fd, ptr.baseAddress! + totalWritten, ptr.count - totalWritten)
            }
            if written <= 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw ServerError.timeout
                }
                throw ServerError.writeFailed
            }
            totalWritten += written
        }

        // Read response (loop until newline delimiter, handling partial reads)
        // The Go server sends newline-delimited JSON responses
        var responseBuffer = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        let maxResponseSize = 1024 * 1024  // 1MB limit to prevent memory exhaustion

        while true {
            let bytesRead = read(fd, &buffer, buffer.count)

            if bytesRead < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    throw ServerError.timeout
                }
                throw ServerError.readFailed
            }

            if bytesRead == 0 {
                // Connection closed before receiving complete response
                if responseBuffer.isEmpty {
                    throw ServerError.readFailed
                }
                break  // Try to parse what we have
            }

            responseBuffer.append(contentsOf: buffer[0..<bytesRead])

            // Check for response size limit
            if responseBuffer.count > maxResponseSize {
                throw ServerError.serverError("Response too large")
            }

            // Check if we've received the complete message (ends with newline)
            if let lastByte = responseBuffer.last, lastByte == 0x0A {
                break
            }
        }

        // Parse response JSON
        guard let response = try JSONSerialization.jsonObject(with: responseBuffer) as? [String: Any] else {
            throw ServerError.invalidResponse
        }

        return response
    }
}
