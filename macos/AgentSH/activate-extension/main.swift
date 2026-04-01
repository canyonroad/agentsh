// macos/AgentSH/activate-extension/main.swift
// Standalone helper that activates the AgentSH system extension.
// Placed in Contents/MacOS/ and signed with the host app's entitlements
// so it's covered by the host app's provisioning profile.
// Compiled with swiftc (no Xcode target needed).

import AppKit
import Combine
import SwiftUI
import SystemExtensions

// MARK: - Activator

class ExtensionActivator: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    enum Status: Equatable {
        case activating
        case needsUserApproval
        case activated
        case failed(String)
    }

    @Published var status: Status = .activating

    private let extensionBundleID = "ai.canyonroad.agentsh.SysExt"

    func activate() {
        NSLog("activate-extension: requesting activation of \(extensionBundleID)")
        status = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        NSLog("activate-extension: finished with result \(result.rawValue)")
        DispatchQueue.main.async {
            switch result {
            case .completed, .willCompleteAfterReboot:
                self.status = .activated
            @unknown default:
                self.status = .failed("Unknown result: \(result.rawValue)")
            }
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("activate-extension: failed: \(error)")
        DispatchQueue.main.async {
            self.status = .failed(error.localizedDescription)
        }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("activate-extension: needs user approval in System Settings")
        DispatchQueue.main.async {
            self.status = .needsUserApproval
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        NSLog("activate-extension: replacing \(existing.bundleVersion) -> \(ext.bundleVersion)")
        return .replace
    }
}

// MARK: - View

struct ActivationView: View {
    @ObservedObject var activator: ExtensionActivator

    var body: some View {
        VStack(spacing: 20) {
            switch activator.status {
            case .activating:
                ProgressView()
                    .scaleEffect(1.5)
                Text("Activating system extension...")
                    .foregroundColor(.secondary)

            case .needsUserApproval:
                Image(systemName: "gear.badge")
                    .font(.system(size: 48))
                    .foregroundColor(.blue)
                Text("Approval Required")
                    .font(.title.bold())
                Text("Open System Settings \u{2192} General \u{2192} Login Items & Extensions\nand allow the AgentSH extension.")
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)
                Button("Open System Settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?General") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.borderedProminent)

            case .activated:
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.green)
                Text("Extension Activated")
                    .font(.title.bold())
                Text("The AgentSH system extension is now active.")
                    .foregroundColor(.secondary)
                Button("Done") {
                    NSApp.terminate(nil)
                }
                .keyboardShortcut(.defaultAction)

            case .failed(let message):
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.red)
                Text("Activation Failed")
                    .font(.title.bold())
                Text(message)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                HStack(spacing: 12) {
                    Button("Retry") {
                        activator.activate()
                    }
                    .buttonStyle(.bordered)
                    Button("Quit") {
                        NSApp.terminate(nil)
                    }
                }
            }
        }
        .frame(width: 400, height: 300)
        .padding()
    }
}

// MARK: - Entry point

let app = NSApplication.shared
app.setActivationPolicy(.regular)

let activator = ExtensionActivator()

let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 450, height: 350),
    styleMask: [.titled, .closable],
    backing: .buffered,
    defer: false
)
window.title = "AgentSH Setup"
window.contentView = NSHostingView(rootView: ActivationView(activator: activator))
window.center()
window.makeKeyAndOrderFront(nil)

app.activate(ignoringOtherApps: true)
activator.activate()
app.run()
