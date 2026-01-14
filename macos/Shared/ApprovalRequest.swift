// macos/Shared/ApprovalRequest.swift
import Foundation

/// Represents a pending network connection approval request.
/// Used to communicate approval requests between XPC service and clients.
@objc class ApprovalRequest: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    /// Unique identifier for this approval request.
    @objc let requestID: String

    /// Name of the process requesting network access.
    @objc let processName: String

    /// Bundle ID of the application (nil for command-line tools).
    @objc let bundleID: String?

    /// Process ID of the requesting process.
    @objc let pid: pid_t

    /// Target host (IP address or resolved hostname).
    @objc let targetHost: String

    /// Target port number.
    @objc let targetPort: Int

    /// Protocol: "tcp" or "udp".
    @objc let targetProtocol: String

    /// Timestamp when the request was created.
    @objc let timestamp: Date

    /// Timeout in seconds until auto-deny.
    @objc let timeout: TimeInterval

    /// Executable path of the requesting process.
    @objc let executablePath: String?

    init(
        requestID: String,
        processName: String,
        bundleID: String?,
        pid: pid_t,
        targetHost: String,
        targetPort: Int,
        targetProtocol: String,
        timestamp: Date,
        timeout: TimeInterval,
        executablePath: String? = nil
    ) {
        self.requestID = requestID
        self.processName = processName
        self.bundleID = bundleID
        self.pid = pid
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.targetProtocol = targetProtocol
        self.timestamp = timestamp
        self.timeout = timeout
        self.executablePath = executablePath
        super.init()
    }

    // MARK: - NSSecureCoding

    private enum CodingKeys {
        static let requestID = "requestID"
        static let processName = "processName"
        static let bundleID = "bundleID"
        static let pid = "pid"
        static let targetHost = "targetHost"
        static let targetPort = "targetPort"
        static let targetProtocol = "targetProtocol"
        static let timestamp = "timestamp"
        static let timeout = "timeout"
        static let executablePath = "executablePath"
    }

    required init?(coder: NSCoder) {
        guard let requestID = coder.decodeObject(of: NSString.self, forKey: CodingKeys.requestID) as String?,
              let processName = coder.decodeObject(of: NSString.self, forKey: CodingKeys.processName) as String?,
              let targetHost = coder.decodeObject(of: NSString.self, forKey: CodingKeys.targetHost) as String?,
              let targetProtocol = coder.decodeObject(of: NSString.self, forKey: CodingKeys.targetProtocol) as String?,
              let timestamp = coder.decodeObject(of: NSDate.self, forKey: CodingKeys.timestamp) as Date? else {
            return nil
        }

        self.requestID = requestID
        self.processName = processName
        self.bundleID = coder.decodeObject(of: NSString.self, forKey: CodingKeys.bundleID) as String?
        self.pid = coder.decodeInt32(forKey: CodingKeys.pid)
        self.targetHost = targetHost
        self.targetPort = coder.decodeInteger(forKey: CodingKeys.targetPort)
        self.targetProtocol = targetProtocol
        self.timestamp = timestamp
        self.timeout = coder.decodeDouble(forKey: CodingKeys.timeout)
        self.executablePath = coder.decodeObject(of: NSString.self, forKey: CodingKeys.executablePath) as String?
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(requestID as NSString, forKey: CodingKeys.requestID)
        coder.encode(processName as NSString, forKey: CodingKeys.processName)
        coder.encode(bundleID as NSString?, forKey: CodingKeys.bundleID)
        coder.encode(pid, forKey: CodingKeys.pid)
        coder.encode(targetHost as NSString, forKey: CodingKeys.targetHost)
        coder.encode(targetPort, forKey: CodingKeys.targetPort)
        coder.encode(targetProtocol as NSString, forKey: CodingKeys.targetProtocol)
        coder.encode(timestamp as NSDate, forKey: CodingKeys.timestamp)
        coder.encode(timeout, forKey: CodingKeys.timeout)
        coder.encode(executablePath as NSString?, forKey: CodingKeys.executablePath)
    }

    // MARK: - JSON Conversion

    /// Creates an ApprovalRequest from a JSON dictionary (from Go server).
    static func from(json: [String: Any]) -> ApprovalRequest? {
        guard let requestID = json["request_id"] as? String,
              let processName = json["process_name"] as? String,
              let targetHost = json["target_host"] as? String,
              let targetPort = json["target_port"] as? Int,
              let targetProtocol = json["target_protocol"] as? String,
              let timeout = json["timeout"] as? Double else {
            return nil
        }

        let pid = json["pid"] as? Int32 ?? 0
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

        return ApprovalRequest(
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

    override var description: String {
        let bundleDesc = bundleID ?? "none"
        return "ApprovalRequest(\(requestID): \(processName) [\(bundleDesc)] -> \(targetHost):\(targetPort)/\(targetProtocol))"
    }
}
