// macos/ApprovalDialog/ApprovalRequestData.swift
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
