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
}

/// XPC Service identifier.
let xpcServiceIdentifier = "com.agentsh.xpc"
