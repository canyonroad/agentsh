// macos/SysExt/FilterDataProvider.swift
import NetworkExtension
import Foundation

class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Blocking Configuration

    /// When true, uses synchronous blocking mode that returns actual verdicts.
    /// When false (default), uses async audit-only mode that always allows flows.
    var blockingEnabled: Bool = false

    /// Maximum time to wait for policy decision in blocking mode.
    /// Default is 100ms to minimize latency impact.
    var decisionTimeout: TimeInterval = 0.1

    /// Behavior when timeout occurs or policy check fails.
    /// true (default) = allow on timeout/error (fail-open)
    /// false = deny on timeout/error (fail-closed)
    var failOpen: Bool = true

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        _ = ProcessHierarchy.shared
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Get remote endpoint - use remoteFlowEndpoint for modern API, fallback to deprecated
        let ip: String
        let port: Int

        if #available(macOS 15.0, *) {
            guard let endpoint = socketFlow.remoteFlowEndpoint else {
                return .allow()
            }
            switch endpoint {
            case .hostPort(let host, let p):
                ip = "\(host)"
                port = Int(p.rawValue)
            default:
                return .allow()
            }
        } else {
            // Fallback to deprecated API for older macOS
            guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
                return .allow()
            }
            ip = remoteEndpoint.hostname
            port = Int(remoteEndpoint.port) ?? 0
        }

        // Extract process info using audit token
        guard let auditTokenData = socketFlow.sourceAppAuditToken else {
            NSLog("FilterDataProvider: No audit token for flow to \(ip):\(port)")
            return .allow()
        }

        // Convert Data to audit_token_t
        var auditToken = audit_token_t()
        guard auditTokenData.count == MemoryLayout<audit_token_t>.size else {
            NSLog("FilterDataProvider: Invalid audit token size for flow to \(ip):\(port)")
            return .allow()
        }
        _ = withUnsafeMutableBytes(of: &auditToken) { dest in
            auditTokenData.copyBytes(to: dest)
        }

        // Get full process identification
        let processInfo = ProcessIdentifier.identify(auditToken: auditToken)
        let pid = processInfo.pid

        // Get parent PID from hierarchy (may use cached fork events or sysctl fallback)
        let parentPID = ProcessHierarchy.shared.getParent(pid: pid) ?? 0

        // Session scoping: auto-allow if PID is not in any active session
        guard let sessionID = SessionPolicyCache.shared.sessionForPID(pid) else {
            return .allow()
        }

        // Proxy enforcement: ensure session PIDs connect through the proxy
        if blockingEnabled,
           let cache = SessionPolicyCache.shared.cacheForSession(sessionID),
           cache.proxyAddr != nil {

            // Allow localhost connections (always pass through)
            if !isLocalhost(ip) {
                // Allow connections to the session's proxy
                if let proxyAddr = cache.proxyAddr, isProxyAddr(ip, port, proxyAddr: proxyAddr) {
                    return .allow()
                }
                // Allow direct-connect allowlist entries
                else if cache.directAllow.contains(where: { matchesDirectAllow(ip: ip, port: port, entry: $0) }) {
                    return .allow()
                }
                // Block direct external connections (proxy bypass)
                else {
                    NSLog("PROXY_BYPASS_BLOCKED: \(ip):\(port) from pid \(pid) (session \(sessionID))")
                    PolicySocketClient.shared.send([
                        "type": "proxy_bypass_blocked",
                        "session_id": sessionID,
                        "pid": Int(pid),
                        "destination_ip": ip,
                        "destination_port": port,
                        "destination_host": socketFlow.remoteHostname ?? "",
                        "process_name": processInfo.processName ?? "",
                        "bundle_id": processInfo.bundleID ?? ""
                    ])
                    return .drop()
                }
            }
        }

        // Extract domain from flow if available (SNI/hostname)
        let hostname = socketFlow.remoteHostname

        // Cache fast-path: check network rules
        let (cacheDecision, _) = SessionPolicyCache.shared.evaluateNetwork(
            host: hostname ?? ip, port: port, pid: pid)

        switch cacheDecision {
        case .allow:
            return .allow()
        case .deny:
            return .drop()
        case .fallthrough_:
            break  // Continue to PolicySocketClient check
        }

        // Determine protocol (TCP vs UDP)
        let protocolType: String
        switch socketFlow.socketType {
        case SOCK_STREAM:
            protocolType = "tcp"
        case SOCK_DGRAM:
            protocolType = "udp"
        default:
            protocolType = "tcp"  // Default to TCP for unknown types
        }

        // Route to appropriate handler based on blocking mode
        if blockingEnabled {
            return handleNewFlowBlocking(
                ip: ip,
                port: port,
                protocolType: protocolType,
                domain: hostname,
                pid: pid,
                parentPID: parentPID,
                sessionID: sessionID,
                processInfo: processInfo
            )
        } else {
            return handleNewFlowAuditOnly(
                ip: ip,
                port: port,
                protocolType: protocolType,
                domain: hostname,
                pid: pid,
                parentPID: parentPID,
                sessionID: sessionID,
                processInfo: processInfo
            )
        }
    }

    // MARK: - Proxy Enforcement Helpers

    /// Check if an IP address is localhost.
    private func isLocalhost(_ ip: String) -> Bool {
        return ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "localhost"
    }

    /// Check if destination matches a DirectAllowEntry.
    private func matchesDirectAllow(ip: String, port: Int, entry: DirectAllowEntry) -> Bool {
        let hostMatch = entry.host == "*" || entry.host == ip
        let portMatch = entry.port == 0 || entry.port == port
        return hostMatch && portMatch
    }

    /// Check if destination is the session's proxy address.
    private func isProxyAddr(_ ip: String, _ port: Int, proxyAddr: String) -> Bool {
        let parts = proxyAddr.split(separator: ":")
        guard parts.count == 2,
              let proxyPort = Int(parts[1]) else { return false }
        return ip == String(parts[0]) && port == proxyPort
    }

    // MARK: - Audit-Only Mode (Async)

    private func handleNewFlowAuditOnly(
        ip: String, port: Int, protocolType: String, domain: String?,
        pid: pid_t, parentPID: pid_t, sessionID: String, processInfo: ProcessInfo
    ) -> NEFilterNewFlowVerdict {
        PolicySocketClient.shared.send([
            "type": "pnacl_check",
            "ip": ip,
            "port": port,
            "protocol": protocolType,
            "domain": domain ?? "",
            "pid": Int(pid),
            "bundle_id": processInfo.bundleID ?? "",
            "executable_path": processInfo.executablePath ?? "",
            "process_name": processInfo.processName ?? "",
            "parent_pid": Int(parentPID),
            "session_id": sessionID
        ])
        return .allow()
    }

    // MARK: - Blocking Mode (Synchronous)

    private func handleNewFlowBlocking(
        ip: String, port: Int, protocolType: String, domain: String?,
        pid: pid_t, parentPID: pid_t, sessionID: String, processInfo: ProcessInfo
    ) -> NEFilterNewFlowVerdict {
        let semaphore = DispatchSemaphore(value: 0)
        var policyDecision: String?
        var policyRuleID: String?

        PolicySocketClient.shared.request([
            "type": "pnacl_check",
            "ip": ip,
            "port": port,
            "protocol": protocolType,
            "domain": domain ?? "",
            "pid": Int(pid),
            "bundle_id": processInfo.bundleID ?? "",
            "executable_path": processInfo.executablePath ?? "",
            "process_name": processInfo.processName ?? "",
            "parent_pid": Int(parentPID),
            "session_id": sessionID
        ]) { response in
            policyDecision = response?["decision"] as? String
            policyRuleID = response?["rule_id"] as? String
            semaphore.signal()
        }

        let result = semaphore.wait(timeout: .now() + decisionTimeout)

        let verdict: NEFilterNewFlowVerdict
        let wasBlocked: Bool

        switch result {
        case .success:
            if let decision = policyDecision {
                switch decision {
                case "allow", "allow_once", "allow_permanent":
                    verdict = .allow(); wasBlocked = false
                case "deny", "deny_once", "deny_forever":
                    verdict = .drop(); wasBlocked = true
                case "audit":
                    verdict = .allow(); wasBlocked = false
                case "approve", "allow_once_then_approve":
                    if failOpen || decision == "allow_once_then_approve" {
                        verdict = .allow(); wasBlocked = false
                    } else {
                        verdict = .drop(); wasBlocked = true
                    }
                default:
                    verdict = failOpen ? .allow() : .drop()
                    wasBlocked = !failOpen
                }
            } else {
                verdict = failOpen ? .allow() : .drop()
                wasBlocked = !failOpen
            }
        case .timedOut:
            verdict = failOpen ? .allow() : .drop()
            wasBlocked = !failOpen
        }

        logPNACLDecision(
            decision: policyDecision ?? (failOpen ? "allow_fallback" : "deny_fallback"),
            ruleID: policyRuleID, ip: ip, port: port, pid: pid,
            bundleID: processInfo.bundleID, blocked: wasBlocked)

        // Report event to server asynchronously (fire-and-forget)
        PolicySocketClient.shared.send([
            "type": "pnacl_event",
            "event_type": "connection_\(policyDecision ?? "unknown")",
            "ip": ip,
            "port": port,
            "protocol": protocolType,
            "domain": domain ?? "",
            "pid": Int(pid),
            "bundle_id": processInfo.bundleID ?? "",
            "decision": wasBlocked ? "blocked" : "allowed",
            "rule_id": policyRuleID ?? ""
        ])

        return verdict
    }

    // MARK: - Logging

    /// Log PNACL decision for debugging.
    private func logPNACLDecision(
        decision: String,
        ruleID: String?,
        ip: String,
        port: Int,
        pid: pid_t,
        bundleID: String?,
        blocked: Bool = false
    ) {
        let bundleStr = bundleID ?? "unknown"
        let ruleStr = ruleID ?? "none"
        let modeStr = blockingEnabled ? "BLOCKING" : "AUDIT"
        let actionStr = blocked ? "BLOCKED" : "ALLOWED"

        switch decision {
        case "allow":
            // Don't log allowed connections to reduce noise (unless blocked which shouldn't happen)
            if blocked {
                NSLog("PNACL [\(modeStr)] \(actionStr): \(ip):\(port) from \(bundleStr) (pid \(pid), decision: allow)")
            }
        case "deny":
            NSLog("PNACL [\(modeStr)] \(actionStr): \(ip):\(port) from \(bundleStr) (pid \(pid), rule: \(ruleStr))")
        case "approve":
            NSLog("PNACL [\(modeStr)] APPROVE_NEEDED \(actionStr): \(ip):\(port) from \(bundleStr) (pid \(pid))")
        default:
            if decision.contains("timeout") || decision.contains("nil") {
                NSLog("PNACL [\(modeStr)] ERROR \(actionStr): \(ip):\(port) from \(bundleStr) (pid \(pid), reason: \(decision))")
            } else {
                NSLog("PNACL [\(modeStr)] \(decision.uppercased()) \(actionStr): \(ip):\(port) from \(bundleStr) (pid \(pid))")
            }
        }
    }

    // MARK: - Data Handlers

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        return .allow()
    }
}
