// macos/Shared/XPCProtocol.swift
import Foundation

/// Protocol for communication between System Extension and XPC Service.
@objc protocol AgentshXPCProtocol {
    /// Check if a file operation is allowed.
    func checkFile(
        path: String,
        operation: String,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Check if a network connection is allowed.
    func checkNetwork(
        ip: String,
        port: Int,
        domain: String?,
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Check if a command execution is allowed.
    func checkCommand(
        executable: String,
        args: [String],
        pid: pid_t,
        sessionID: String?,
        reply: @escaping (Bool, String?) -> Void
    )

    /// Resolve session ID for a process.
    func resolveSession(
        pid: pid_t,
        reply: @escaping (String?) -> Void
    )

    /// Emit an event to the agentsh server.
    func emitEvent(
        event: Data,
        reply: @escaping (Bool) -> Void
    )

    // MARK: - PNACL (Process Network ACL)

    /// Check network connection with full process identification for PNACL.
    /// Returns decision: "allow", "deny", "approve", "needRules"
    func checkNetworkPNACL(
        ip: String,
        port: Int,
        protocol: String,  // "tcp" or "udp"
        domain: String?,   // SNI hostname if available
        pid: pid_t,
        bundleID: String?,
        executablePath: String?,
        processName: String?,
        parentPID: pid_t,
        reply: @escaping (String, String?) -> Void  // (decision, ruleID)
    )

    /// Report a PNACL connection event (for audit/logging).
    func reportPNACLEvent(
        eventType: String,  // "connection_allowed", "connection_denied", "connection_pending"
        ip: String,
        port: Int,
        protocol: String,
        domain: String?,
        pid: pid_t,
        bundleID: String?,
        decision: String,
        ruleID: String?,
        reply: @escaping (Bool) -> Void
    )

    // MARK: - PNACL Approval Flow (Phase 3)

    /// Get list of pending approval requests.
    /// Returns an array of ApprovalRequest objects for connections awaiting user decision.
    func getPendingApprovals(
        reply: @escaping ([ApprovalRequest]) -> Void
    )

    /// Submit an approval decision for a pending request.
    /// - Parameters:
    ///   - requestID: The unique ID of the approval request
    ///   - decision: "allow" or "deny"
    ///   - permanent: If true, creates a persistent rule for this app/destination
    ///   - reply: Called with success status
    func submitApprovalDecision(
        requestID: String,
        decision: String,
        permanent: Bool,
        reply: @escaping (Bool) -> Void
    )

    // MARK: - PNACL Configuration (Phase 4)

    /// Configure PNACL blocking behavior for the filter provider.
    /// This allows runtime configuration without recompiling.
    /// - Parameters:
    ///   - blockingEnabled: When true, actually blocks connections. When false, audit-only mode.
    ///   - decisionTimeout: Max seconds to wait for policy decision (default 0.1 = 100ms)
    ///   - failOpen: When true, allows on timeout/error. When false, denies on timeout/error.
    ///   - reply: Called with success status
    func configurePNACLBlocking(
        blockingEnabled: Bool,
        decisionTimeout: Double,
        failOpen: Bool,
        reply: @escaping (Bool) -> Void
    )

    /// Get current PNACL blocking configuration.
    /// - Parameters:
    ///   - reply: Returns (blockingEnabled, decisionTimeout, failOpen)
    func getPNACLBlockingConfig(
        reply: @escaping (Bool, Double, Bool) -> Void
    )
}

/// XPC Service identifier.
let xpcServiceIdentifier = "com.agentsh.xpc"
