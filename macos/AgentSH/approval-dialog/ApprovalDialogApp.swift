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
    @State private var currentRequestID: String?  // Tracks which request we're expecting
    @State private var isSubmitting = false  // Tracks submission in progress
    @State private var pendingDecision: (requestID: String, decision: String, permanent: Bool)?  // For retry

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
        if isSubmitting {
            submittingView
        } else if let request = request {
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

    // MARK: - Submitting View

    private var submittingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
            Text("Submitting decision...")
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

            HStack(spacing: 12) {
                // Show retry button if we have a request to retry
                if let requestID = currentRequestID {
                    Button("Retry") {
                        retryRequest(requestID: requestID)
                    }
                    .buttonStyle(.bordered)
                }

                Button("Quit") {
                    quitApp()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 350, height: 280)
        .padding()
    }

    // MARK: - Retry Logic

    private func retryRequest(requestID: String) {
        // If we have a pending decision, retry the submission
        if let decision = pendingDecision {
            retrySubmission(requestID: decision.requestID, decision: decision.decision, permanent: decision.permanent)
        } else {
            // Otherwise retry fetching the request
            errorMessage = nil
            isLoading = true
            Task {
                await fetchRequest(requestID: requestID)
            }
        }
    }

    private func retrySubmission(requestID: String, decision: String, permanent: Bool) {
        errorMessage = nil
        isSubmitting = true
        Task {
            await submitDecision(requestID: requestID, decision: decision, permanent: permanent)
        }
    }

    // MARK: - URL Handling

    private func handleURL(_ url: URL) {
        NSLog("ApprovalDialogApp: Handling URL: \(url)")

        // Parse request ID from URL
        // Expected format: agentsh-approval://approve?id=<requestID>
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems,
              let requestID = queryItems.first(where: { $0.name == "id" })?.value,
              !requestID.isEmpty else {
            NSLog("ApprovalDialogApp: Invalid URL format or missing request ID")
            request = nil  // Clear any existing request so error view shows
            errorMessage = "Invalid URL format.\nExpected: agentsh-approval://approve?id=<requestID>"
            isLoading = false
            currentRequestID = nil
            return
        }

        // Reset state for new URL - prevents showing stale data if a second approval arrives
        request = nil
        errorMessage = nil
        isLoading = true
        isSubmitting = false
        pendingDecision = nil  // Clear any pending decision from previous request
        currentRequestID = requestID  // Track which request we're loading

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
                    // Only update UI if this is still the request we're waiting for
                    // (prevents older slow requests from overwriting newer ones)
                    guard currentRequestID == requestID else {
                        NSLog("ApprovalDialogApp: Ignoring stale response for \(requestID), now waiting for \(currentRequestID ?? "none")")
                        return
                    }
                    self.request = fetchedRequest
                    self.isLoading = false
                }
                NSLog("ApprovalDialogApp: Successfully loaded request: \(requestID)")
            } else {
                await MainActor.run {
                    guard currentRequestID == requestID else { return }
                    self.errorMessage = "Request not found.\nThe approval request may have expired or already been handled."
                    self.isLoading = false
                }
                NSLog("ApprovalDialogApp: Request not found: \(requestID)")
            }
        } catch {
            await MainActor.run {
                guard currentRequestID == requestID else { return }
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

        // Store decision for potential retry (including requestID since request will be cleared on error)
        pendingDecision = (requestID, decision, permanent)
        isSubmitting = true

        Task {
            await submitDecision(requestID: requestID, decision: decision, permanent: permanent)
        }
    }

    private func submitDecision(requestID: String, decision: String, permanent: Bool) async {
        do {
            let success = try await serverClient.submitDecision(
                requestID: requestID,
                decision: decision,
                permanent: permanent
            )

            await MainActor.run {
                // Guard against stale submissions - if a new request arrived, ignore this completion
                guard pendingDecision?.requestID == requestID else {
                    NSLog("ApprovalDialogApp: Ignoring stale submission result for \(requestID)")
                    return
                }

                if success {
                    NSLog("ApprovalDialogApp: Decision submitted successfully")
                    pendingDecision = nil
                    quitApp()
                } else {
                    NSLog("ApprovalDialogApp: Decision submission returned false")
                    isSubmitting = false
                    request = nil  // Clear request so error view shows
                    errorMessage = "Failed to submit decision.\nThe server rejected the request."
                }
            }
        } catch {
            NSLog("ApprovalDialogApp: Error submitting decision: \(error)")
            await MainActor.run {
                // Guard against stale submissions
                guard pendingDecision?.requestID == requestID else {
                    NSLog("ApprovalDialogApp: Ignoring stale submission error for \(requestID)")
                    return
                }

                isSubmitting = false
                request = nil  // Clear request so error view shows
                errorMessage = "Failed to submit decision.\n\(error.localizedDescription)"
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
