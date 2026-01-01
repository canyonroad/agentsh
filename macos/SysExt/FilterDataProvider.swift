// macos/SysExt/FilterDataProvider.swift
import NetworkExtension

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
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }

        let ip = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0
        let pid = socketFlow.sourceAppAuditToken.map { audit_token_to_pid($0) } ?? 0

        // For now, allow and check async
        // In production, use .needRules() and respond later
        getProxy()?.checkNetwork(ip: ip, port: port, domain: nil, pid: pid, sessionID: nil) { allow, _ in
            if !allow {
                NSLog("Would block: \(ip):\(port) from pid \(pid)")
            }
        }

        return .allow()
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
