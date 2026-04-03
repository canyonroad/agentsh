// macos/SysExt/DNSProxyProvider.swift
import NetworkExtension
import Network

class DNSProxyProvider: NEDNSProxyProvider {
    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
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
        if #available(macOS 15.0, *) {
            flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
                if let error = error {
                    NSLog("DNS flow open error: \(error)")
                    return
                }
                self?.readAndProcessDNS(flow)
            }
        } else {
            flow.open(withLocalEndpoint: nil) { [weak self] error in
                if let error = error {
                    NSLog("DNS flow open error: \(error)")
                    return
                }
                self?.readAndProcessDNS(flow)
            }
        }
    }

    private func readAndProcessDNS(_ flow: NEAppProxyUDPFlow) {
        if #available(macOS 15.0, *) {
            readAndProcessDNSModern(flow)
        } else {
            readAndProcessDNSLegacy(flow)
        }
    }

    @available(macOS 15.0, *)
    private func readAndProcessDNSModern(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] tuples, error in
            guard let self = self else { return }

            guard let tuples = tuples, error == nil else {
                if let error = error { NSLog("DNS read error: \(error)") }
                return
            }

            for (datagram, endpoint) in tuples {
                if let response = self.processQuery(datagram) {
                    flow.writeDatagrams([(response, endpoint)]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                } else if self.shouldForward(datagram) {
                    flow.writeDatagrams([(datagram, endpoint)]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                }
            }

            self.readAndProcessDNSModern(flow)
        }
    }

    private func readAndProcessDNSLegacy(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams(completionHandler: { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            guard let datagrams = datagrams, let endpoints = endpoints, error == nil else {
                if let error = error { NSLog("DNS read error: \(error)") }
                return
            }

            for (datagram, endpoint) in zip(datagrams, endpoints) {
                if let response = self.processQuery(datagram) {
                    flow.writeDatagrams([response], sentBy: [endpoint]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                } else if self.shouldForward(datagram) {
                    flow.writeDatagrams([datagram], sentBy: [endpoint]) { error in
                        if let error = error { NSLog("DNS write error: \(error)") }
                    }
                }
            }

            self.readAndProcessDNSLegacy(flow)
        })
    }

    /// Returns an NXDOMAIN response if the query should be blocked, nil otherwise.
    private func processQuery(_ datagram: Data) -> Data? {
        guard let domain = parseDNSQueryDomain(datagram),
              let action = SessionPolicyCache.shared.evaluateDNS(domain: domain) else {
            return nil
        }
        if action == "nxdomain" {
            return synthesizeNXDOMAIN(datagram)
        }
        return nil
    }

    /// Returns true if the datagram should be forwarded (not blocked by policy).
    private func shouldForward(_ datagram: Data) -> Bool {
        guard let domain = parseDNSQueryDomain(datagram),
              let _ = SessionPolicyCache.shared.evaluateDNS(domain: domain) else {
            return true  // No policy match — forward
        }
        return false  // Policy matched (deny/nxdomain) — don't forward
    }

    // MARK: - DNS Wire Format Helpers

    /// Parse domain name from DNS query wire format.
    /// DNS header is 12 bytes, then QNAME as length-prefixed labels.
    private func parseDNSQueryDomain(_ datagram: Data) -> String? {
        guard datagram.count > 12 else { return nil }

        var offset = 12  // Skip DNS header
        var labels: [String] = []

        while offset < datagram.count {
            let length = Int(datagram[offset])
            if length == 0 { break }  // Root label = end
            if length & 0xC0 == 0xC0 { return nil }  // Pointer compression — bail
            guard length <= 63 else { return nil }  // RFC 1035: max label length
            offset += 1
            guard offset + length <= datagram.count else { return nil }
            let label = datagram[offset..<offset+length]
            guard let str = String(bytes: label, encoding: .ascii) else { return nil }
            labels.append(str)
            offset += length
        }

        return labels.isEmpty ? nil : labels.joined(separator: ".")
    }

    /// Synthesize a DNS NXDOMAIN response from a query datagram.
    private func synthesizeNXDOMAIN(_ query: Data) -> Data? {
        guard query.count >= 12 else { return nil }
        var response = query
        // Set QR bit (response) and RCODE=3 (NXDOMAIN)
        // Byte 2: QR=1 (0x80) | Opcode (keep) | AA=0 | TC=0 | RD (keep)
        response[2] = (query[2] & 0x79) | 0x80  // Set QR, preserve Opcode and RD
        // Byte 3: RA=1 (0x80) | Z=0 | RCODE=3 (0x03)
        response[3] = 0x83
        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        response[6] = 0; response[7] = 0
        response[8] = 0; response[9] = 0
        response[10] = 0; response[11] = 0
        // Truncate to header + question only
        var offset = 12
        while offset < response.count {
            let length = Int(response[offset])
            if length == 0 { offset += 1; break }
            offset += 1 + length
        }
        guard offset + 4 <= response.count else { return nil }
        offset += 4  // QTYPE (2) + QCLASS (2)
        return response.prefix(offset)
    }
}
