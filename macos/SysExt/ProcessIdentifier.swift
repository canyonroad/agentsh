// macos/SysExt/ProcessIdentifier.swift
import Foundation
import Security

/// Information about a process extracted from its audit token or PID.
struct ProcessInfo {
    let pid: pid_t
    let bundleID: String?
    let executablePath: String?
    let processName: String?
    let teamID: String?
    let signingIdentifier: String?
    let isValidlySigned: Bool

    /// Empty process info for when identification fails completely.
    static func empty(pid: pid_t) -> ProcessInfo {
        return ProcessInfo(
            pid: pid,
            bundleID: nil,
            executablePath: nil,
            processName: nil,
            teamID: nil,
            signingIdentifier: nil,
            isValidlySigned: false
        )
    }
}

/// Thread-safe utility for extracting process identification information from audit tokens.
/// Results are cached since process identity doesn't change during its lifetime.
final class ProcessIdentifier {

    // MARK: - Cache

    /// Thread-safe cache for process info lookups.
    private static let cache = ProcessInfoCache()

    // MARK: - Public Interface

    /// Identify a process from its audit token.
    /// - Parameter auditToken: The audit token from an ES or NE event.
    /// - Returns: ProcessInfo containing available identification data.
    static func identify(auditToken: audit_token_t) -> ProcessInfo {
        let pid = audit_token_to_pid(auditToken)

        // Check cache first
        if let cached = cache.get(pid: pid) {
            return cached
        }

        // Get code reference from audit token
        var codeRef: SecCode?
        var tokenCopy = auditToken
        let tokenData = Data(bytes: &tokenCopy, count: MemoryLayout<audit_token_t>.size) as CFData

        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &codeRef)

        guard status == errSecSuccess, let code = codeRef else {
            NSLog("ProcessIdentifier: Failed to get SecCode for pid \(pid): \(status)")
            let info = buildProcessInfo(pid: pid, code: nil)
            cache.set(pid: pid, info: info)
            return info
        }

        let info = buildProcessInfo(pid: pid, code: code)
        cache.set(pid: pid, info: info)
        return info
    }

    /// Identify a process from its PID.
    /// - Parameter pid: The process ID.
    /// - Returns: ProcessInfo if the process exists and can be identified, nil otherwise.
    static func identify(pid: pid_t) -> ProcessInfo? {
        // Check cache first
        if let cached = cache.get(pid: pid) {
            return cached
        }

        // Get code reference from PID
        var codeRef: SecCode?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &codeRef)

        guard status == errSecSuccess, let code = codeRef else {
            NSLog("ProcessIdentifier: Failed to get SecCode for pid \(pid): \(status)")
            // Process might not exist or we can't access it
            return nil
        }

        let info = buildProcessInfo(pid: pid, code: code)
        cache.set(pid: pid, info: info)
        return info
    }

    /// Remove a process from the cache (call when process exits).
    /// - Parameter pid: The process ID to remove from cache.
    static func invalidate(pid: pid_t) {
        cache.remove(pid: pid)
    }

    /// Clear the entire cache.
    static func clearCache() {
        cache.clear()
    }

    // MARK: - Private Implementation

    /// Build ProcessInfo from a SecCode reference.
    private static func buildProcessInfo(pid: pid_t, code: SecCode?) -> ProcessInfo {
        var bundleID: String?
        var executablePath: String?
        var processName: String?
        var teamID: String?
        var signingIdentifier: String?
        var isValidlySigned = false

        // Get executable path from proc_pidpath (more reliable than SecCode for path)
        executablePath = getExecutablePath(pid: pid)

        // Extract process name from path
        if let path = executablePath {
            processName = (path as NSString).lastPathComponent
        }

        // If we have a code reference, extract signing information
        if let code = code {
            // Get static code for validation
            var staticCode: SecStaticCode?
            if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
               let staticCode = staticCode {
                // Check if validly signed
                let validationStatus = SecStaticCodeCheckValidity(staticCode, [], nil)
                isValidlySigned = (validationStatus == errSecSuccess)
            }

            // Get signing information
            var infoRef: CFDictionary?
            let infoStatus = SecCodeCopySigningInformation(
                code,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &infoRef
            )

            if infoStatus == errSecSuccess, let info = infoRef as? [String: Any] {
                // Extract bundle ID from Info.plist if available
                if let plist = info[kSecCodeInfoPList as String] as? [String: Any] {
                    bundleID = plist["CFBundleIdentifier"] as? String
                }

                // Extract team ID
                teamID = info[kSecCodeInfoTeamIdentifier as String] as? String

                // Extract signing identifier
                signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String

                // If we didn't get process name yet, try from signing identifier
                if processName == nil {
                    processName = signingIdentifier
                }
            }
        }

        return ProcessInfo(
            pid: pid,
            bundleID: bundleID,
            executablePath: executablePath,
            processName: processName,
            teamID: teamID,
            signingIdentifier: signingIdentifier,
            isValidlySigned: isValidlySigned
        )
    }

    /// Get executable path using proc_pidpath.
    private static func getExecutablePath(pid: pid_t) -> String? {
        let pathBuffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(MAXPATHLEN))
        defer { pathBuffer.deallocate() }

        let pathLength = proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN))
        guard pathLength > 0 else {
            return nil
        }

        return String(cString: pathBuffer)
    }
}

// MARK: - Cache Implementation

/// Thread-safe cache for ProcessInfo lookups.
private final class ProcessInfoCache {
    private var storage: [pid_t: ProcessInfo] = [:]
    private let queue = DispatchQueue(label: "com.agentsh.processidentifier.cache", attributes: .concurrent)

    func get(pid: pid_t) -> ProcessInfo? {
        return queue.sync {
            storage[pid]
        }
    }

    func set(pid: pid_t, info: ProcessInfo) {
        queue.async(flags: .barrier) {
            self.storage[pid] = info
        }
    }

    func remove(pid: pid_t) {
        queue.async(flags: .barrier) {
            self.storage.removeValue(forKey: pid)
        }
    }

    func clear() {
        queue.async(flags: .barrier) {
            self.storage.removeAll()
        }
    }
}
