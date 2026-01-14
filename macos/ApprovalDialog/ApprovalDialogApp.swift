// macos/ApprovalDialog/ApprovalDialogApp.swift
import SwiftUI

/// Main entry point for the ApprovalDialog app.
/// Launched via URL scheme: agentsh-approval://approve?id=<requestID>
@main
struct ApprovalDialogApp: App {
    @State private var request: ApprovalRequestData?
    @State private var errorMessage: String?
    @State private var isLoading = true
    @State private var hasProcessedLaunchURL = false

    private let serverClient = ServerClient()

    var body: some Scene {
        WindowGroup {
            contentView
                .onAppear {
                    // Activate app to front when window appears
                    activateApp()

                    // Handle launch URL on first appearance (for command-line launch)
                    if !hasProcessedLaunchURL {
                        hasProcessedLaunchURL = true
                        if let url = getLaunchURL() {
                            handleURL(url)
                        }
                    }
                }
                .onOpenURL { url in
                    handleURL(url)
                }
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            // Remove standard menu items that don't make sense for this dialog
            CommandGroup(replacing: .newItem) {}
        }
        .handlesExternalEvents(matching: ["approve"])
    }

    @ViewBuilder
    private var contentView: some View {
        if let request = request {
            ApprovalView(request: request, onDecision: handleDecision)
        } else if let error = errorMessage {
            errorView(message: error)
        } else if isLoading {
            loadingView
        }
    }

    // MARK: - Loading View

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
            Text("Loading request...")
                .foregroundColor(.secondary)
        }
        .frame(width: 300, height: 200)
    }

    // MARK: - Error View

    private func errorView(message: String) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(.red)

            Text("Error")
                .font(.title.bold())

            Text(message)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Quit") {
                quitApp()
            }
            .keyboardShortcut(.defaultAction)
        }
        .frame(width: 350, height: 250)
        .padding()
    }

    // MARK: - URL Handling

    private func handleURL(_ url: URL) {
        NSLog("ApprovalDialogApp: Handling URL: \(url)")

        // Reset state for new URL - prevents showing stale data if a second approval arrives
        request = nil
        errorMessage = nil
        isLoading = true

        // Parse request ID from URL
        // Expected format: agentsh-approval://approve?id=<requestID>
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems,
              let requestID = queryItems.first(where: { $0.name == "id" })?.value,
              !requestID.isEmpty else {
            NSLog("ApprovalDialogApp: Invalid URL format or missing request ID")
            errorMessage = "Invalid URL format.\nExpected: agentsh-approval://approve?id=<requestID>"
            isLoading = false
            return
        }

        NSLog("ApprovalDialogApp: Fetching approval for request ID: \(requestID)")

        // Activate app to front
        activateApp()

        // Fetch request details asynchronously
        Task {
            await fetchRequest(requestID: requestID)
        }
    }

    private func fetchRequest(requestID: String) async {
        do {
            if let fetchedRequest = try await serverClient.fetchApproval(requestID: requestID) {
                await MainActor.run {
                    self.request = fetchedRequest
                    self.isLoading = false
                }
                NSLog("ApprovalDialogApp: Successfully loaded request: \(requestID)")
            } else {
                await MainActor.run {
                    self.errorMessage = "Request not found.\nThe approval request may have expired or already been handled."
                    self.isLoading = false
                }
                NSLog("ApprovalDialogApp: Request not found: \(requestID)")
            }
        } catch {
            await MainActor.run {
                self.errorMessage = "Failed to connect to server.\n\(error.localizedDescription)"
                self.isLoading = false
            }
            NSLog("ApprovalDialogApp: Error fetching request: \(error)")
        }
    }

    // MARK: - Decision Handling

    private func handleDecision(_ decision: String, _ permanent: Bool) {
        guard let requestID = request?.requestID else {
            NSLog("ApprovalDialogApp: No request to submit decision for")
            quitApp()
            return
        }

        NSLog("ApprovalDialogApp: Submitting decision '\(decision)' (permanent: \(permanent)) for request: \(requestID)")

        Task {
            do {
                let success = try await serverClient.submitDecision(
                    requestID: requestID,
                    decision: decision,
                    permanent: permanent
                )

                if success {
                    NSLog("ApprovalDialogApp: Decision submitted successfully")
                } else {
                    NSLog("ApprovalDialogApp: Decision submission returned false")
                }
            } catch {
                NSLog("ApprovalDialogApp: Error submitting decision: \(error)")
            }

            // Quit app after submission attempt (even on error, to avoid blocking)
            await MainActor.run {
                quitApp()
            }
        }
    }

    // MARK: - App Lifecycle

    private func activateApp() {
        NSApp.activate(ignoringOtherApps: true)
        // Also bring window to front
        NSApp.windows.first?.makeKeyAndOrderFront(nil)
    }

    private func quitApp() {
        NSLog("ApprovalDialogApp: Quitting")
        NSApp.terminate(nil)
    }

    /// Get the URL that was used to launch the app (if any).
    private func getLaunchURL() -> URL? {
        // Check command line arguments for URL
        let args = ProcessInfo.processInfo.arguments
        for arg in args where arg.hasPrefix("agentsh-approval://") {
            return URL(string: arg)
        }

        // Check for URL in Apple Events (set by launch services)
        // This is handled automatically by onOpenURL, so return nil here
        return nil
    }
}
