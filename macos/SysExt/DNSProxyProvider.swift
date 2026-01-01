// macos/SysExt/DNSProxyProvider.swift
import NetworkExtension

class DNSProxyProvider: NEDNSProxyProvider {
    private var xpc: NSXPCConnection?
    private var xpcProxy: AgentshXPCProtocol?
    private let queue = DispatchQueue(label: "com.agentsh.dnsproxyprovider")

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
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

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.sync {
            xpc?.invalidate()
            xpc = nil
            xpcProxy = nil
        }
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // DNS flows come through here
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleDNSFlow(udpFlow)
            return true
        }
        return false
    }

    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                NSLog("DNS flow open error: \(error)")
                return
            }
            self?.readAndProcessDNS(flow)
        }
    }

    private func readAndProcessDNS(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            guard let datagrams = datagrams, let endpoints = endpoints, error == nil else {
                if let error = error {
                    NSLog("DNS read error: \(error)")
                }
                return
            }

            for (datagram, endpoint) in zip(datagrams, endpoints) {
                // Parse DNS query, extract domain
                // Check policy
                // Forward or block
                self.forwardDNS(datagram, to: endpoint, via: flow)
            }

            // Continue reading
            self.readAndProcessDNS(flow)
        }
    }

    private func forwardDNS(_ datagram: Data, to endpoint: NWEndpoint, via flow: NEAppProxyUDPFlow) {
        // In production: parse query, check policy, forward to upstream or return NXDOMAIN
        flow.writeDatagrams([datagram], sentBy: [endpoint]) { error in
            if let error = error {
                NSLog("DNS write error: \(error)")
            }
        }
    }
}
