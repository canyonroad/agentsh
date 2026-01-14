// macos/SysExt/FilterDataProvider.swift
import NetworkExtension
import Foundation

// Note: AgentshXPCProtocol and xpcServiceIdentifier are defined in Shared/XPCProtocol.swift
// Ensure that file is included in the SysExt target in Xcode.

class FilterDataProvider: NEFilterDataProvider {
    private var xpc: NSXPCConnection?
    private var xpcProxy: AgentshXPCProtocol?
    private let queue = DispatchQueue(label: "com.agentsh.filterprovider")

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

        // Make async PNACL check - for now, allow the flow and log decisions
        // In production with proper entitlements, use pause/resume flow mechanism
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
                bundleID: processInfo.bundleID
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

        // For blocking mode, we need NEFilterControlProvider or app-specific configuration.
        // Without that, we allow and audit. The Go service can log policy violations.
        // To enable blocking:
        // 1. Configure NEFilterProviderConfiguration with filterPackets/filterSockets
        // 2. Use pauseFlow/resumeFlow API for async decisions
        // 3. Or implement NEFilterControlProvider for rule-based filtering
        return .allow()
    }

    /// Log PNACL decision for debugging.
    private func logPNACLDecision(
        decision: String,
        ruleID: String?,
        ip: String,
        port: Int,
        pid: pid_t,
        bundleID: String?
    ) {
        let bundleStr = bundleID ?? "unknown"
        let ruleStr = ruleID ?? "none"

        switch decision {
        case "allow":
            // Don't log allowed connections to reduce noise
            break
        case "deny":
            NSLog("PNACL DENY: \(ip):\(port) from \(bundleStr) (pid \(pid), rule: \(ruleStr))")
        case "approve":
            NSLog("PNACL APPROVE_NEEDED: \(ip):\(port) from \(bundleStr) (pid \(pid))")
        default:
            NSLog("PNACL \(decision.uppercased()): \(ip):\(port) from \(bundleStr) (pid \(pid))")
        }
    }

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
