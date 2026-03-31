import Foundation

/// Darwin notification name posted by Go server when policy changes.
let policyUpdatedNotification = "ai.canyonroad.agentsh.policy-updated"

// MARK: - Rule Types

struct FileRule {
    let pattern: String
    let operations: Set<String>  // "read", "write", "create", "delete", "rename"
    let action: String           // "allow" or "deny"
}

struct NetworkRule {
    let pattern: String
    let ports: Set<Int>
    let proto: String?
    let action: String
}

struct DNSRule {
    let pattern: String
    let action: String  // "allow", "deny", "nxdomain"
}

struct PolicyDefaults {
    let file: String     // "allow" or "deny"
    let network: String
    let dns: String
}

// MARK: - Per-Session Cache Entry

class SessionCache {
    let sessionID: String
    let rootPID: pid_t
    var version: UInt64
    var sessionPIDs: Set<pid_t>
    var fileRules: [FileRule]
    var networkRules: [NetworkRule]
    var dnsRules: [DNSRule]
    var defaults: PolicyDefaults

    init(sessionID: String, rootPID: pid_t, version: UInt64,
         fileRules: [FileRule], networkRules: [NetworkRule],
         dnsRules: [DNSRule], defaults: PolicyDefaults) {
        self.sessionID = sessionID
        self.rootPID = rootPID
        self.version = version
        self.sessionPIDs = [rootPID]
        self.fileRules = fileRules
        self.networkRules = networkRules
        self.dnsRules = dnsRules
        self.defaults = defaults
    }
}

// MARK: - Policy Cache Manager

class SessionPolicyCache {
    static let shared = SessionPolicyCache()

    private var sessions: [String: SessionCache] = [:]  // sessionID -> cache
    private var pidToSession: [pid_t: String] = [:]      // fast PID -> sessionID lookup
    private var execDepths: [pid_t: Int] = [:]
    private let queue = DispatchQueue(label: "ai.canyonroad.agentsh.policycache",
                                       attributes: .concurrent)

    private init() {
        startListeningForNotifications()
    }

    // MARK: - Session Lifecycle

    func registerSession(sessionID: String, rootPID: pid_t, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            self.sessions[sessionID] = snapshot
            self.pidToSession[rootPID] = sessionID
        }
    }

    func unregisterSession(sessionID: String) {
        queue.async(flags: .barrier) {
            guard let cache = self.sessions[sessionID] else { return }
            for pid in cache.sessionPIDs {
                self.pidToSession.removeValue(forKey: pid)
                self.execDepths.removeValue(forKey: pid)
            }
            self.sessions.removeValue(forKey: sessionID)
        }
    }

    var hasActiveSessions: Bool {
        queue.sync { !sessions.isEmpty }
    }

    // MARK: - PID Tracking (called from NOTIFY_FORK/EXIT)

    func addPID(_ childPID: pid_t, parentPID: pid_t) {
        queue.async(flags: .barrier) {
            guard let sessionID = self.pidToSession[parentPID],
                  let cache = self.sessions[sessionID] else { return }
            cache.sessionPIDs.insert(childPID)
            self.pidToSession[childPID] = sessionID
        }
    }

    func removePID(_ pid: pid_t) {
        queue.async(flags: .barrier) {
            if let sessionID = self.pidToSession.removeValue(forKey: pid) {
                self.sessions[sessionID]?.sessionPIDs.remove(pid)
            }
            self.execDepths.removeValue(forKey: pid)
        }
    }

    // MARK: - Session Membership

    /// Returns the sessionID for a PID, or nil if not in any session.
    func sessionForPID(_ pid: pid_t) -> String? {
        queue.sync { pidToSession[pid] }
    }

    /// Returns the SessionCache for a PID, or nil if not in any session.
    func cacheForPID(_ pid: pid_t) -> SessionCache? {
        queue.sync {
            guard let sid = pidToSession[pid] else { return nil }
            return sessions[sid]
        }
    }

    // MARK: - Exec Depth

    func recordExecDepth(pid: pid_t, parentPID: pid_t) -> Int {
        return queue.sync(flags: .barrier) {
            let parentDepth = execDepths[parentPID] ?? 0
            let depth = parentDepth + 1
            execDepths[pid] = depth
            return depth
        }
    }

    // MARK: - File Policy Evaluation

    enum CacheDecision {
        case allow
        case deny
        case fallthrough_  // No match, use default or XPC
    }

    func evaluateFile(path: String, operation: String, pid: pid_t) -> (CacheDecision, String?) {
        return queue.sync {
            guard let sid = pidToSession[pid],
                  let cache = sessions[sid] else {
                return (.allow, nil)  // Not in session
            }

            // Check deny rules first
            for rule in cache.fileRules where rule.action == "deny" {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    return (.deny, sid)
                }
            }

            // Rules requiring server-side logic -> XPC fallthrough
            for rule in cache.fileRules {
                if rule.operations.contains(operation) && globMatch(pattern: rule.pattern, path: path) {
                    if rule.action == "approve" || rule.action == "redirect" || rule.action == "soft_delete" {
                        return (.fallthrough_, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            // Apply default
            if cache.defaults.file == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    // MARK: - Network Policy Evaluation

    func evaluateNetwork(host: String, port: Int, pid: pid_t) -> (CacheDecision, String?) {
        return queue.sync {
            guard let sid = pidToSession[pid],
                  let cache = sessions[sid] else {
                return (.allow, nil)
            }

            for rule in cache.networkRules where rule.action == "deny" {
                if globMatch(pattern: rule.pattern, path: host) &&
                   (rule.ports.isEmpty || rule.ports.contains(port)) {
                    return (.deny, sid)
                }
            }

            for rule in cache.networkRules {
                if globMatch(pattern: rule.pattern, path: host) &&
                   (rule.ports.isEmpty || rule.ports.contains(port)) {
                    if rule.action == "approve" {
                        return (.fallthrough_, sid)
                    }
                    if rule.action == "allow" {
                        return (.allow, sid)
                    }
                }
            }

            if cache.defaults.network == "deny" {
                return (.deny, sid)
            }
            return (.allow, sid)
        }
    }

    // MARK: - DNS Policy Evaluation (union of all sessions)

    func evaluateDNS(domain: String) -> String? {
        return queue.sync {
            if sessions.isEmpty { return nil }  // No sessions = passthrough

            for (_, cache) in sessions {
                for rule in cache.dnsRules where rule.action == "deny" || rule.action == "nxdomain" {
                    if globMatch(pattern: rule.pattern, path: domain) {
                        return rule.action
                    }
                }
            }

            // Strictest default wins
            for (_, cache) in sessions {
                if cache.defaults.dns == "deny" {
                    return "deny"
                }
            }

            return nil  // All defaults allow = passthrough
        }
    }

    // MARK: - Cache Update

    func updateSession(_ sessionID: String, snapshot: SessionCache) {
        queue.async(flags: .barrier) {
            guard let existing = self.sessions[sessionID] else { return }
            if snapshot.version <= existing.version { return }
            // Preserve sessionPIDs — they're maintained by fork/exit, not snapshot
            snapshot.sessionPIDs = existing.sessionPIDs
            self.sessions[sessionID] = snapshot
        }
    }

    func versionForSession(_ sessionID: String) -> UInt64 {
        queue.sync { sessions[sessionID]?.version ?? 0 }
    }

    func allSessionIDs() -> [String] {
        queue.sync { Array(sessions.keys) }
    }

    // MARK: - Darwin Notification Listener

    private func startListeningForNotifications() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let name = CFNotificationName(policyUpdatedNotification as CFString)
        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let cache = Unmanaged<SessionPolicyCache>.fromOpaque(observer).takeUnretainedValue()
                cache.handlePolicyUpdateNotification()
            },
            name.rawValue,
            nil,
            .deliverImmediately
        )
    }

    private func handlePolicyUpdateNotification() {
        let sessionIDs = allSessionIDs()
        for sessionID in sessionIDs {
            NotificationCenter.default.post(
                name: .policyCacheNeedsRefresh,
                object: nil,
                userInfo: ["session_id": sessionID]
            )
        }
    }

    // MARK: - Glob Matching

    /// Simple glob matcher supporting * (single segment) and ** (recursive).
    /// Matches the Go policy engine's glob semantics.
    private func globMatch(pattern: String, path: String) -> Bool {
        // Use fnmatch for simple cases, handling ** manually
        if pattern.contains("**") {
            // Convert ** to regex-style matching
            let regexPattern = "^" + NSRegularExpression.escapedPattern(for: pattern)
                .replacingOccurrences(of: "\\*\\*", with: ".*")
                .replacingOccurrences(of: "\\*", with: "[^/]*")
            + "$"
            return (try? NSRegularExpression(pattern: regexPattern))?.firstMatch(
                in: path, range: NSRange(path.startIndex..., in: path)
            ) != nil
        }
        // Simple glob: use fnmatch
        return fnmatch(pattern, path, FNM_PATHNAME) == 0
    }
}

// MARK: - Snapshot Parsing

extension SessionCache {
    static func from(json: [String: Any], sessionID: String, rootPID: pid_t) -> SessionCache? {
        guard let version = json["version"] as? UInt64 ?? (json["version"] as? Int).map({ UInt64($0) }) else {
            return nil
        }

        var fileRules: [FileRule] = []
        if let rules = json["file_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let ops = r["operations"] as? [String],
                      let action = r["action"] as? String else { continue }
                fileRules.append(FileRule(pattern: pattern, operations: Set(ops), action: action))
            }
        }

        var networkRules: [NetworkRule] = []
        if let rules = json["network_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                let ports = (r["ports"] as? [Int]).map { Set($0) } ?? Set<Int>()
                let proto = r["protocol"] as? String
                networkRules.append(NetworkRule(pattern: pattern, ports: ports, proto: proto, action: action))
            }
        }

        var dnsRules: [DNSRule] = []
        if let rules = json["dns_rules"] as? [[String: Any]] {
            for r in rules {
                guard let pattern = r["pattern"] as? String,
                      let action = r["action"] as? String else { continue }
                dnsRules.append(DNSRule(pattern: pattern, action: action))
            }
        }

        let defs = json["defaults"] as? [String: String] ?? [:]
        let defaults = PolicyDefaults(
            file: defs["file"] ?? "allow",
            network: defs["network"] ?? "allow",
            dns: defs["dns"] ?? "allow"
        )

        return SessionCache(
            sessionID: sessionID, rootPID: rootPID, version: version,
            fileRules: fileRules, networkRules: networkRules,
            dnsRules: dnsRules, defaults: defaults
        )
    }
}

// MARK: - Notification Name

extension Notification.Name {
    static let policyCacheNeedsRefresh = Notification.Name("ai.canyonroad.agentsh.policyCacheNeedsRefresh")
}
