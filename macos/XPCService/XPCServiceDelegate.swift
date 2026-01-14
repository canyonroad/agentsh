// macos/XPCService/XPCServiceDelegate.swift
import Foundation

class XPCServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let bridge = PolicyBridge()
    private var approvalManagerStarted = false

    override init() {
        super.init()
        // Start the approval manager for PNACL Phase 3
        startApprovalManager()
    }

    /// Initialize and start the ApprovalManager for handling network approval requests.
    private func startApprovalManager() {
        guard !approvalManagerStarted else { return }
        approvalManagerStarted = true

        ApprovalManager.shared.start(with: bridge)
        NSLog("XPCServiceDelegate: ApprovalManager initialized")
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Configure the XPC interface to include ApprovalRequest class
        let interface = NSXPCInterface(with: AgentshXPCProtocol.self)

        // Register ApprovalRequest for secure coding in the getPendingApprovals reply
        let approvalClasses = NSSet(array: [
            NSArray.self,
            ApprovalRequest.self
        ])

        // Safe cast with fallback
        guard let classes = approvalClasses as? Set<AnyHashable> else {
            NSLog("XPCServiceDelegate: Failed to create approval classes set")
            return false
        }

        interface.setClasses(
            classes,
            for: #selector(AgentshXPCProtocol.getPendingApprovals(reply:)),
            argumentIndex: 0,
            ofReply: true
        )

        newConnection.exportedInterface = interface
        newConnection.exportedObject = bridge
        newConnection.resume()
        return true
    }
}
