// macos/SysExt/main.swift
import Foundation
import SystemExtensions

// 1. Initialize policy cache BEFORE ES client (avoid lazy init on ES thread)
_ = SessionPolicyCache.shared

// 2. Create ES client (calls es_new_client but does NOT subscribe yet)
var esfClient: ESFClient?
for attempt in 1...3 {
    if let client = ESFClient.create() {
        NSLog("AgentSH SysExt: ES client created on attempt \(attempt)")
        esfClient = client
        break
    }
    if attempt < 3 {
        NSLog("AgentSH SysExt: ES client creation attempt \(attempt) failed, retrying in 2s")
        Thread.sleep(forTimeInterval: 2)
    }
}

guard let esfClient = esfClient else {
    NSLog("AgentSH SysExt: ES client failed to start -- exiting (grant Full Disk Access to enable)")
    exit(1)
}

// 3. Store strong reference BEFORE subscribing
ESFClient.shared = esfClient

// 4. Subscribe to events -- ESFClient.shared is now set, safe for NOTIFY handlers
guard esfClient.subscribe() else {
    NSLog("AgentSH SysExt: Failed to subscribe to ES events -- exiting")
    exit(1)
}

// 5. Start async socket connection (lazy, non-blocking)
PolicySocketClient.shared.connectWhenReady()

dispatchMain()
