// macos/XPCService/XPCServiceDelegate.swift
import Foundation

class XPCServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let bridge = PolicyBridge()

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: AgentshXPCProtocol.self)
        newConnection.exportedObject = bridge
        newConnection.resume()
        return true
    }
}
