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
