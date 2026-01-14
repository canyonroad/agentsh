// macos/SysExt/FilterDataProvider.swift
import NetworkExtension
import Foundation

// Note: AgentshXPCProtocol and xpcServiceIdentifier are defined in Shared/XPCProtocol.swift
// Ensure that file is included in the SysExt target in Xcode.

class FilterDataProvider: NEFilterDataProvider {
    private var xpc: NSXPCConnection?
    private var xpcProxy: AgentshXPCProtocol?
    private let queue = DispatchQueue(label: "com.agentsh.filterprovider")

    // MARK: - Blocking Configuration

    /// When true, uses synchronous blocking mode that returns actual verdicts.
    /// When false (default), uses async audit-only mode that always allows flows.
    var blockingEnabled: Bool = false

    /// Maximum time to wait for policy decision in blocking mode.
    /// Default is 100ms to minimize latency impact.
    var decisionTimeout: TimeInterval = 0.1

    /// Behavior when timeout occurs or XPC call fails.
    /// true (default) = allow on timeout/error (fail-open)
    /// false = deny on timeout/error (fail-closed)
    var failOpen: Bool = true

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        queue.sync {
            // Connect to XPC Service
            xpc = NSXPCConnection(serviceName: xpcServiceIdentifier)
            xpc?.remoteObjectInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
            xpc?.resume()

            xpcProxy = xpc?.remoteObjectProxyWithErrorHandler { error in
                NSLog("XPC error: \(error)")
            } as? AgentshXPCProtocol
        }

        // ProcessHierarchy is a singleton that receives fork/exit events from ESFClient.
        // We just ensure it's initialized here; actual tracking happens via ESF events.
        _ = ProcessHierarchy.shared

        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        queue.sync {
            xpc?.invalidate()
            xpc = nil
            xpcProxy = nil
        }

        completionHandler()
    }

    private func getProxy() -> AgentshXPCProtocol? {
        return queue.sync { xpcProxy }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Get remote endpoint - use remoteFlowEndpoint for modern API, fallback to deprecated
        let ip: String
        let port: Int

        if #available(macOS 14.0, *) {
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
        guard let auditToken = socketFlow.sourceAppAuditToken else {
            NSLog("FilterDataProvider: No audit token for flow to \(ip):\(port)")
            return .allow()
        }

        // Get full process identification
        let processInfo = ProcessIdentifier.identify(auditToken: auditToken)
        let pid = processInfo.pid

        // Get parent PID from hierarchy (may use cached fork events or sysctl fallback)
        let parentPID = ProcessHierarchy.shared.getParent(pid: pid) ?? 0

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

        // Extract domain from flow if available (SNI/hostname)
        let domain = socketFlow.remoteHostname

        // Route to appropriate handler based on blocking mode
        if blockingEnabled {
            return handleNewFlowBlocking(
                ip: ip,
                port: port,
                protocolType: protocolType,
                domain: domain,
                pid: pid,
                parentPID: parentPID,
                processInfo: processInfo
            )
        } else {
            return handleNewFlowAuditOnly(
                ip: ip,
                port: port,
                protocolType: protocolType,
                domain: domain,
                pid: pid,
                parentPID: parentPID,
                processInfo: processInfo
            )
        }
    }

    // MARK: - Audit-Only Mode (Async)

    /// Original async audit-only behavior - always allows flows but logs decisions.
    private func handleNewFlowAuditOnly(
        ip: String,
        port: Int,
        protocolType: String,
        domain: String?,
        pid: pid_t,
        parentPID: pid_t,
        processInfo: ProcessIdentifier.ProcessInfo
    ) -> NEFilterNewFlowVerdict {
        // Make async PNACL check - allow the flow and log decisions
        getProxy()?.checkNetworkPNACL(
            ip: ip,
            port: port,
            protocol: protocolType,
            domain: domain,
            pid: pid,
            bundleID: processInfo.bundleID,
            executablePath: processInfo.executablePath,
            processName: processInfo.processName,
            parentPID: parentPID
        ) { [weak self] (decision: String, ruleID: String?) in
            // Log the decision for audit purposes
            self?.logPNACLDecision(
                decision: decision,
                ruleID: ruleID,
                ip: ip,
                port: port,
                pid: pid,
                bundleID: processInfo.bundleID,
                blocked: false  // Audit mode never blocks
            )

            // Report event to server
            self?.getProxy()?.reportPNACLEvent(
                eventType: "connection_\(decision)",
                ip: ip,
                port: port,
                protocol: protocolType,
                domain: domain,
                pid: pid,
                bundleID: processInfo.bundleID,
                decision: decision,
                ruleID: ruleID
            ) { _ in }
        }

        return .allow()
    }

    // MARK: - Blocking Mode (Synchronous)

    /// Synchronous blocking mode - waits for policy decision and returns actual verdict.
    private func handleNewFlowBlocking(
        ip: String,
        port: Int,
        protocolType: String,
        domain: String?,
        pid: pid_t,
        parentPID: pid_t,
        processInfo: ProcessIdentifier.ProcessInfo
    ) -> NEFilterNewFlowVerdict {
        let semaphore = DispatchSemaphore(value: 0)

        // Variables to capture the result from callback
        var policyDecision: String?
        var policyRuleID: String?
        var xpcError: Bool = false

        // Get proxy once to avoid race conditions
        guard let proxy = getProxy() else {
            NSLog("PNACL: XPC proxy unavailable for \(ip):\(port) pid=\(pid)")
            return failOpen ? .allow() : .drop()
        }

        // Make synchronous XPC call with semaphore
        proxy.checkNetworkPNACL(
            ip: ip,
            port: port,
            protocol: protocolType,
            domain: domain,
            pid: pid,
            bundleID: processInfo.bundleID,
            executablePath: processInfo.executablePath,
            processName: processInfo.processName,
            parentPID: parentPID
        ) { (decision: String, ruleID: String?) in
            policyDecision = decision
            policyRuleID = ruleID
            semaphore.signal()
        }

        // Wait for response with timeout
        let timeoutNanos = Int64(decisionTimeout * Double(NSEC_PER_SEC))
        let result = semaphore.wait(timeout: .now() + .nanoseconds(Int(timeoutNanos)))

        // Determine verdict based on result
        let verdict: NEFilterNewFlowVerdict
        let finalDecision: String
        let wasBlocked: Bool

        switch result {
        case .success:
            // Got response in time - use policy decision
            if let decision = policyDecision {
                finalDecision = decision
                switch decision {
                case "allow":
                    verdict = .allow()
                    wasBlocked = false
                case "deny":
                    verdict = .drop()
                    wasBlocked = true
                case "approve":
                    // Pending approval - use fail behavior
                    if failOpen {
                        verdict = .allow()
                        wasBlocked = false
                    } else {
                        verdict = .drop()
                        wasBlocked = true
                    }
                default:
                    // Unknown decision - use fail behavior
                    NSLog("PNACL: Unknown decision '\(decision)' for \(ip):\(port) pid=\(pid)")
                    verdict = failOpen ? .allow() : .drop()
                    wasBlocked = !failOpen
                }
            } else {
                // Nil decision (shouldn't happen) - use fail behavior
                NSLog("PNACL: Nil decision for \(ip):\(port) pid=\(pid)")
                finalDecision = failOpen ? "allow_nil" : "deny_nil"
                verdict = failOpen ? .allow() : .drop()
                wasBlocked = !failOpen
                xpcError = true
            }

        case .timedOut:
            // Timeout - use fail behavior
            let timeoutMs = Int(decisionTimeout * 1000)
            NSLog("PNACL: Timeout (\(timeoutMs)ms) for \(ip):\(port) pid=\(pid), failOpen=\(failOpen)")
            finalDecision = failOpen ? "allow_timeout" : "deny_timeout"
            verdict = failOpen ? .allow() : .drop()
            wasBlocked = !failOpen
            xpcError = true
        }

        // Log the decision
        logPNACLDecision(
            decision: policyDecision ?? finalDecision,
            ruleID: policyRuleID,
            ip: ip,
            port: port,
            pid: pid,
            bundleID: processInfo.bundleID,
            blocked: wasBlocked
        )

        // Report event to server asynchronously (don't block on this)
        let eventType: String
        if xpcError {
            eventType = "connection_\(finalDecision)"
        } else {
            eventType = "connection_\(policyDecision ?? "unknown")"
        }

        proxy.reportPNACLEvent(
            eventType: eventType,
            ip: ip,
            port: port,
            protocol: protocolType,
            domain: domain,
            pid: pid,
            bundleID: processInfo.bundleID,
            decision: wasBlocked ? "blocked" : "allowed",
            ruleID: policyRuleID
        ) { _ in }

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
