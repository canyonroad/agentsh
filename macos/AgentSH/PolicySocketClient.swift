import Foundation
import Security

/// Async Unix socket client for communicating with the Go policy server.
/// Replaces the dead XPC Service connection for the SysExt.
/// All operations are non-blocking. If the socket is down, sends are dropped.
class PolicySocketClient {
    static let shared = PolicySocketClient()

    private let socketPath = "/tmp/agentsh-policy.sock"
    private let sendQueue = DispatchQueue(label: "ai.canyonroad.agentsh.policysocket")
    private let timeout: TimeInterval = 5.0

    /// Whether we believe the server is reachable. Updated on connect/disconnect.
    private var _connected: Int32 = 0
    var isConnected: Bool { _connected != 0 }

    // MARK: - Event Stream
    private var streamFD: Int32 = -1
    private let streamQueue = DispatchQueue(label: "ai.canyonroad.agentsh.eventstream")
    private var eventBuffer: [[String: Any]] = []
    private let maxBufferSize = 1024
    private var reconnectDelay: TimeInterval = 1.0
    private let maxReconnectDelay: TimeInterval = 30.0
    private var streamConnected = false

    private init() {}

    // MARK: - Connection Lifecycle

    /// Attempt to connect when ready. Non-blocking. Called from main.swift at startup.
    /// Actual connection happens lazily on first send or when a Darwin notification arrives.
    func connectWhenReady() {
        // Try an initial connection attempt in the background
        sendQueue.async {
            self.testConnection()
        }
        connectEventStream()
    }

    /// Called when a Darwin notification arrives, signaling the Go server may be alive.
    func onServerNotification() {
        sendQueue.async {
            self.testConnection()
        }
        streamQueue.async {
            if !self.streamConnected {
                self.doConnectEventStream()
            }
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

    // MARK: - Event Stream (persistent connection for file events)

    /// Opens a persistent connection for event streaming.
    func connectEventStream() {
        streamQueue.async {
            self.doConnectEventStream()
        }
    }

    private func doConnectEventStream() {
        // Close existing connection if any
        if streamFD >= 0 {
            close(streamFD)
            streamFD = -1
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            scheduleReconnect()
            return
        }

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
        guard connectResult == 0 else {
            close(fd)
            scheduleReconnect()
            return
        }

        // Validate server code signing
        guard validateServer(fd: fd) else {
            close(fd)
            scheduleReconnect()
            return
        }

        // Set write timeout
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Send init message
        let initMsg: [String: Any] = ["type": "event_stream_init"]
        guard let initData = try? JSONSerialization.data(withJSONObject: initMsg) else {
            close(fd)
            scheduleReconnect()
            return
        }
        var dataWithNewline = initData
        dataWithNewline.append(0x0A)

        let written = dataWithNewline.withUnsafeBytes { ptr in
            write(fd, ptr.baseAddress!, ptr.count)
        }
        guard written == dataWithNewline.count else {
            close(fd)
            scheduleReconnect()
            return
        }

        // Read ack
        var ackBuf = [UInt8](repeating: 0, count: 256)
        let ackRead = read(fd, &ackBuf, ackBuf.count)
        guard ackRead > 0 else {
            close(fd)
            scheduleReconnect()
            return
        }

        streamFD = fd
        streamConnected = true
        reconnectDelay = 1.0
        NSLog("PolicySocketClient: event stream connected")

        // Flush buffered events
        flushBuffer()
    }

    /// Write a file event to the persistent stream. Fire-and-forget.
    /// If disconnected, buffer up to maxBufferSize events.
    func sendEvent(_ event: [String: Any]) {
        streamQueue.async {
            if self.streamConnected {
                self.writeEvent(event)
            } else {
                self.eventBuffer.append(event)
                if self.eventBuffer.count > self.maxBufferSize {
                    let dropped = self.eventBuffer.count - self.maxBufferSize
                    self.eventBuffer.removeFirst(dropped)
                    NSLog("PolicySocketClient: dropped %d events (buffer full)", dropped)
                }
            }
        }
    }

    private func writeEvent(_ event: [String: Any]) {
        guard streamFD >= 0,
              let data = try? JSONSerialization.data(withJSONObject: event) else {
            return
        }
        var payload = data
        payload.append(0x0A)

        let written = payload.withUnsafeBytes { ptr in
            write(streamFD, ptr.baseAddress!, ptr.count)
        }
        if written <= 0 {
            NSLog("PolicySocketClient: event stream write failed, reconnecting")
            close(streamFD)
            streamFD = -1
            streamConnected = false
            eventBuffer.append(event)
            scheduleReconnect()
        }
    }

    private func flushBuffer() {
        let buffered = eventBuffer
        eventBuffer.removeAll()
        for event in buffered {
            writeEvent(event)
        }
    }

    private func scheduleReconnect() {
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, maxReconnectDelay)
        streamQueue.asyncAfter(deadline: .now() + delay) {
            self.doConnectEventStream()
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

        // Validate the server's code signing
        guard validateServer(fd: fd) else {
            throw SocketError.connectionFailed
        }

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

    /// Validates that the server process at the other end of the socket is signed
    /// by the expected team ID.
    private func validateServer(fd: Int32) -> Bool {
        // Get peer PID via LOCAL_PEERPID
        var peerPID: pid_t = 0
        var peerPIDLen = socklen_t(MemoryLayout<pid_t>.size)
        let result = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &peerPIDLen)
        guard result == 0, peerPID > 0 else {
            NSLog("PolicySocketClient: Failed to get peer PID")
            return false
        }

        // Create SecCode for the peer process
        let attributes = [kSecGuestAttributePid: peerPID] as CFDictionary
        var code: SecCode?
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        guard status == errSecSuccess, let code = code else {
            NSLog("PolicySocketClient: Failed to get SecCode for pid %d: %d", peerPID, status)
            return false
        }

        // Validate code signing against our team ID
        let requirementStr = "anchor apple generic and certificate leaf[subject.OU] = \"WCKWMMKJ35\""
        var requirement: SecRequirement?
        let reqStatus = SecRequirementCreateWithString(requirementStr as CFString, [], &requirement)
        guard reqStatus == errSecSuccess, let requirement = requirement else {
            NSLog("PolicySocketClient: Failed to create requirement: %d", reqStatus)
            return false
        }

        let checkStatus = SecCodeCheckValidityWithErrors(code, [], requirement, nil)
        if checkStatus != errSecSuccess {
            NSLog("PolicySocketClient: Server code signing validation FAILED for pid %d: %d", peerPID, checkStatus)
            return false
        }

        return true
    }

    enum SocketError: Error {
        case creation, connectionFailed, writeFailed, readFailed, invalidResponse
    }
}
