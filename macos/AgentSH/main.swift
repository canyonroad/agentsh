// macos/SysExt/main.swift
import Foundation
import NetworkExtension
import SystemExtensions

class ExtensionMain: NSObject, OSSystemExtensionRequestDelegate {
    private var filterProvider: FilterDataProvider?
    private var dnsProvider: DNSProxyProvider?

    override init() {
        super.init()
        // Network Extension providers are started by the system
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        NSLog("Extension request finished: \(result.rawValue)")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        NSLog("Extension request failed: \(error)")
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("Extension needs user approval")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

// Entry point
let main = ExtensionMain()
dispatchMain()
