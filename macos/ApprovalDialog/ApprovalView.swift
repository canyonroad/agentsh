// macos/ApprovalDialog/ApprovalView.swift
import SwiftUI

/// SwiftUI view for displaying a network access approval dialog.
/// Shows process and connection information with action buttons for the user to decide.
struct ApprovalView: View {
    let request: ApprovalRequestData
    let onDecision: (String, Bool) -> Void  // (decision, permanent)

    @State private var timeRemaining: TimeInterval
    @State private var timer: Timer?
    @State private var decisionMade: Bool = false  // Prevents timer from firing after user action

    init(request: ApprovalRequestData, onDecision: @escaping (String, Bool) -> Void) {
        self.request = request
        self.onDecision = onDecision
        // Calculate initial time remaining based on timestamp and timeout
        let elapsed = Date().timeIntervalSince(request.timestamp)
        let remaining = max(0, request.timeout - elapsed)
        self._timeRemaining = State(initialValue: remaining)
    }

    var body: some View {
        VStack(spacing: 20) {
            // Header with warning icon
            headerSection

            // Process info GroupBox
            processInfoSection

            // Connection info GroupBox
            connectionInfoSection

            // Timeout progress indicator
            timeoutSection

            // Action buttons (2x2 grid)
            actionButtons
        }
        .padding(24)
        .frame(width: 420)
        .onAppear(perform: startTimer)
        .onDisappear(perform: stopTimer)
    }

    // MARK: - Header Section

    private var headerSection: some View {
        VStack(spacing: 12) {
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 48))
                .foregroundColor(.orange)

            Text("Network Access Request")
                .font(.title.bold())
        }
    }

    // MARK: - Process Info Section

    private var processInfoSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                infoRow(label: "Process", value: request.processName, icon: "app.fill")

                if let bundleID = request.bundleID, !bundleID.isEmpty {
                    infoRow(label: "Bundle ID", value: bundleID, icon: "shippingbox.fill")
                }

                if let executablePath = request.executablePath, !executablePath.isEmpty {
                    infoRow(label: "Path", value: executablePath, icon: "folder.fill")
                }

                infoRow(label: "PID", value: "\(request.pid)", icon: "number")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Process Information", systemImage: "gearshape.fill")
                .font(.headline)
        }
    }

    // MARK: - Connection Info Section

    private var connectionInfoSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                infoRow(label: "Host", value: request.targetHost, icon: "server.rack")
                infoRow(label: "Port", value: "\(request.targetPort)", icon: "number.circle.fill")
                infoRow(label: "Protocol", value: request.targetProtocol.uppercased(), icon: "arrow.left.arrow.right")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Connection Details", systemImage: "network")
                .font(.headline)
        }
    }

    // MARK: - Timeout Section

    private var timeoutSection: some View {
        VStack(spacing: 8) {
            ProgressView(value: timeRemaining, total: request.timeout)
                .progressViewStyle(.linear)
                .tint(timeoutColor)

            HStack {
                Image(systemName: "clock.fill")
                    .foregroundColor(timeoutColor)
                Text(timeoutText)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }

    private var timeoutColor: Color {
        if timeRemaining <= 5 {
            return .red
        } else if timeRemaining <= 15 {
            return .orange
        }
        return .blue
    }

    private var timeoutText: String {
        let seconds = Int(timeRemaining)
        if seconds <= 0 {
            return "Auto-denying..."
        }
        return "Auto-deny in \(seconds) second\(seconds == 1 ? "" : "s")"
    }

    // MARK: - Action Buttons

    private var actionButtons: some View {
        VStack(spacing: 12) {
            // Allow buttons row
            HStack(spacing: 12) {
                Button(action: { submitDecision("allow_once", false) }) {
                    Label("Allow Once", systemImage: "checkmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.green)
                .controlSize(.large)

                Button(action: { submitDecision("allow_permanent", true) }) {
                    Label("Allow Always", systemImage: "checkmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .controlSize(.large)
            }

            // Deny buttons row
            HStack(spacing: 12) {
                Button(action: { submitDecision("deny_once", false) }) {
                    Label("Deny Once", systemImage: "xmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .controlSize(.large)

                Button(action: { submitDecision("deny_forever", true) }) {
                    Label("Deny Always", systemImage: "xmark.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .controlSize(.large)
            }
        }
    }

    // MARK: - Decision Handling

    /// Submit a decision, stopping the timer first to prevent race conditions.
    private func submitDecision(_ decision: String, _ permanent: Bool) {
        // Stop timer immediately to prevent it from firing during submission
        stopTimer()
        decisionMade = true
        onDecision(decision, permanent)
    }

    // MARK: - Helper Views

    private func infoRow(label: String, value: String, icon: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(.secondary)
                .frame(width: 16)

            Text(label + ":")
                .foregroundColor(.secondary)
                .frame(width: 70, alignment: .leading)

            Text(value)
                .fontWeight(.medium)
                .lineLimit(2)
                .truncationMode(.middle)
        }
        .font(.system(.body, design: .default))
    }

    // MARK: - Timer Management

    private func startTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            if timeRemaining > 0 {
                timeRemaining -= 1
            } else {
                stopTimer()
                // Auto-deny when timeout reaches zero, but only if user hasn't already acted
                if !decisionMade {
                    decisionMade = true
                    onDecision("deny_once", false)
                }
            }
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
    }
}

// MARK: - Preview

#if DEBUG
struct ApprovalView_Previews: PreviewProvider {
    static var previews: some View {
        ApprovalView(
            request: ApprovalRequestData(
                requestID: "preview-123",
                processName: "curl",
                bundleID: nil,
                pid: 12345,
                targetHost: "api.example.com",
                targetPort: 443,
                targetProtocol: "tcp",
                timestamp: Date(),
                timeout: 30,
                executablePath: "/usr/bin/curl"
            ),
            onDecision: { decision, permanent in
                print("Decision: \(decision), Permanent: \(permanent)")
            }
        )
        .previewDisplayName("CLI Tool Request")

        ApprovalView(
            request: ApprovalRequestData(
                requestID: "preview-456",
                processName: "Safari",
                bundleID: "com.apple.Safari",
                pid: 54321,
                targetHost: "www.apple.com",
                targetPort: 443,
                targetProtocol: "tcp",
                timestamp: Date(),
                timeout: 30,
                executablePath: "/Applications/Safari.app/Contents/MacOS/Safari"
            ),
            onDecision: { decision, permanent in
                print("Decision: \(decision), Permanent: \(permanent)")
            }
        )
        .previewDisplayName("App Request")
    }
}
#endif
