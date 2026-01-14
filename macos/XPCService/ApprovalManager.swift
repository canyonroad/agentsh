// macos/XPCService/ApprovalManager.swift
import AppKit
import Foundation
import UserNotifications

/// Manages the approval flow for PNACL Phase 3.
/// Polls the Go server for pending approvals and shows macOS notifications.
class ApprovalManager: NSObject {
    /// Shared instance for the XPC service.
    static let shared = ApprovalManager()

    /// Base polling interval in seconds.
    private let basePollInterval: TimeInterval = 1.0

    /// Current polling interval (for exponential backoff).
    private var currentPollInterval: TimeInterval = 1.0

    /// Maximum backoff interval.
    private let maxBackoffInterval: TimeInterval = 60.0

    /// Number of consecutive failures.
    private var consecutiveFailures: Int = 0

    /// Reference to the policy bridge for server communication.
    weak var bridge: PolicyBridge?

    /// Timer for periodic polling.
    private var pollTimer: DispatchSourceTimer?

    /// Queue for polling operations.
    private let pollQueue = DispatchQueue(label: "com.agentsh.approval.poll", qos: .utility)

    /// Currently tracked pending requests (by requestID).
    private var pendingRequests: [String: ApprovalRequest] = [:]
    private let pendingLock = NSLock()

    /// Timestamps when we attempted to show notifications (for escalation tracking).
    /// We track attempt time, not success time, so escalation works even if notifications fail.
    private var notificationAttemptedAt: [String: Date] = [:]

    /// Whether notification permissions have been denied.
    private var notificationsDenied: Bool = false

    /// Requests that have been escalated to the dialog app.
    private var escalatedRequests: Set<String> = []

    /// Delay before escalating from notification to dialog (seconds).
    private let escalationDelay: TimeInterval = 15.0

    /// Notification center for user notifications.
    private let notificationCenter = UNUserNotificationCenter.current()

    /// Notification category identifier.
    private let notificationCategory = "PNACL_APPROVAL"

    /// Notification action identifiers.
    private enum NotificationAction: String {
        case allowOnce = "ALLOW_ONCE"
        case allowAlways = "ALLOW_ALWAYS"
        case denyOnce = "DENY_ONCE"
        case denyAlways = "DENY_ALWAYS"
    }

    private override init() {
        super.init()
    }

    // MARK: - Lifecycle

    /// Start the approval manager with a bridge reference.
    func start(with bridge: PolicyBridge) {
        self.bridge = bridge
        setupNotificationCategories()
        requestNotificationPermissions()
        startPolling()
        NSLog("ApprovalManager: Started")
    }

    /// Stop the approval manager.
    func stop() {
        stopPolling()
        NSLog("ApprovalManager: Stopped")
    }

    // MARK: - Notification Setup

    private func setupNotificationCategories() {
        // Define actions for the notification
        let allowOnce = UNNotificationAction(
            identifier: NotificationAction.allowOnce.rawValue,
            title: "Allow Once",
            options: []
        )
        let allowAlways = UNNotificationAction(
            identifier: NotificationAction.allowAlways.rawValue,
            title: "Allow Always",
            options: []
        )
        let denyOnce = UNNotificationAction(
            identifier: NotificationAction.denyOnce.rawValue,
            title: "Deny Once",
            options: [.destructive]
        )
        let denyAlways = UNNotificationAction(
            identifier: NotificationAction.denyAlways.rawValue,
            title: "Deny Always",
            options: [.destructive]
        )

        // Create category with actions
        let category = UNNotificationCategory(
            identifier: notificationCategory,
            actions: [allowOnce, allowAlways, denyOnce, denyAlways],
            intentIdentifiers: [],
            options: [.customDismissAction]
        )

        notificationCenter.setNotificationCategories([category])
        notificationCenter.delegate = self
    }

    private func requestNotificationPermissions() {
        notificationCenter.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, error in
            guard let self = self else { return }

            self.pendingLock.lock()
            defer { self.pendingLock.unlock() }

            if let error = error {
                NSLog("ApprovalManager: Notification permission error: \(error)")
                self.notificationsDenied = true
            } else if granted {
                NSLog("ApprovalManager: Notification permissions granted")
                self.notificationsDenied = false
            } else {
                NSLog("ApprovalManager: Notification permissions denied - will escalate to dialog immediately")
                self.notificationsDenied = true
            }
        }
    }

    // MARK: - Polling with Exponential Backoff

    private func startPolling() {
        stopPolling()
        scheduleNextPoll()
    }

    private func scheduleNextPoll() {
        let timer = DispatchSource.makeTimerSource(queue: pollQueue)
        timer.schedule(deadline: .now() + currentPollInterval)
        timer.setEventHandler { [weak self] in
            self?.pollForApprovals()
        }
        timer.resume()
        pollTimer = timer
    }

    private func stopPolling() {
        pollTimer?.cancel()
        pollTimer = nil
    }

    private func pollForApprovals() {
        guard let bridge = bridge else { return }

        bridge.fetchPendingApprovals { [weak self] (approvals: [ApprovalRequest], success: Bool) in
            guard let self = self else { return }

            if success {
                // Reset backoff on success
                self.consecutiveFailures = 0
                self.currentPollInterval = self.basePollInterval
                self.handleApprovals(approvals)
            } else {
                // Apply exponential backoff on failure
                self.consecutiveFailures += 1
                self.currentPollInterval = min(
                    self.basePollInterval * pow(2.0, Double(self.consecutiveFailures)),
                    self.maxBackoffInterval
                )
                NSLog("ApprovalManager: Poll failed, backing off to \(self.currentPollInterval)s")
            }

            // Schedule next poll
            self.scheduleNextPoll()
        }
    }

    private func handleApprovals(_ approvals: [ApprovalRequest]) {
        // Collect actions to perform while holding the lock
        var approvalsToNotify: [ApprovalRequest] = []
        var approvalsToEscalateImmediately: [String] = []
        var requestsToEscalate: [String] = []
        var removedIDs: Set<String> = []

        pendingLock.lock()

        // Check for timed-out requests that server hasn't cleaned up
        let now = Date()
        for approval in approvals {
            let timeoutDate = approval.timestamp.addingTimeInterval(approval.timeout)
            if timeoutDate < now {
                // Request has timed out - auto-deny
                NSLog("ApprovalManager: Request \(approval.requestID) timed out, auto-denying")
                submitDecisionAsync(requestID: approval.requestID, decision: "deny_once")
            }
        }

        // Filter out timed-out requests
        let validApprovals = approvals.filter { approval in
            approval.timestamp.addingTimeInterval(approval.timeout) > now
        }

        // Find new approvals that we haven't notified about yet
        let existingIDs = Set(pendingRequests.keys)
        let newApprovals = validApprovals.filter { !existingIDs.contains($0.requestID) }

        // Update our tracking
        var currentIDs = Set<String>()
        for approval in validApprovals {
            currentIDs.insert(approval.requestID)
            pendingRequests[approval.requestID] = approval
        }

        // Remove expired/resolved approvals from tracking
        removedIDs = existingIDs.subtracting(currentIDs)
        for id in removedIDs {
            pendingRequests.removeValue(forKey: id)
            notificationAttemptedAt.removeValue(forKey: id)
            escalatedRequests.remove(id)
        }

        // Determine which approvals need notifications vs immediate escalation
        for approval in newApprovals {
            if notificationsDenied {
                // Notifications not available - escalate to dialog immediately
                NSLog("ApprovalManager: Notifications denied, escalating \(approval.requestID) to dialog immediately")
                escalatedRequests.insert(approval.requestID)
                approvalsToEscalateImmediately.append(approval.requestID)
            } else {
                approvalsToNotify.append(approval)
            }
        }

        // Check for escalation (notification attempted > 15 seconds ago without response)
        for (requestID, attemptedAt) in notificationAttemptedAt {
            // Skip if already escalated
            if escalatedRequests.contains(requestID) {
                continue
            }
            // Check if escalation delay has passed
            if now.timeIntervalSince(attemptedAt) >= escalationDelay {
                NSLog("ApprovalManager: Escalating request \(requestID) to dialog after \(escalationDelay)s")
                escalatedRequests.insert(requestID)
                requestsToEscalate.append(requestID)
            }
        }

        pendingLock.unlock()

        // Now perform actions WITHOUT holding the lock (avoids deadlock)

        // Remove notifications for resolved requests
        if !removedIDs.isEmpty {
            let ids = Array(removedIDs)
            notificationCenter.removeDeliveredNotifications(withIdentifiers: ids)
            notificationCenter.removePendingNotificationRequests(withIdentifiers: ids)
        }

        // Show notifications for new approvals
        for approval in approvalsToNotify {
            showNotification(for: approval)
        }

        // Launch dialog for immediate escalations
        for requestID in approvalsToEscalateImmediately {
            launchDialog(for: requestID)
        }

        // Launch dialog for delayed escalations
        for requestID in requestsToEscalate {
            launchDialog(for: requestID)
        }
    }

    // MARK: - Dialog Escalation

    /// Launch the ApprovalDialog app for a request that hasn't received a timely response.
    private func launchDialog(for requestID: String) {
        guard let encodedID = requestID.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "agentsh-approval://approve?id=\(encodedID)") else {
            NSLog("ApprovalManager: Failed to create URL for dialog launch")
            // Remove from escalated so it can be retried on next poll
            pendingLock.lock()
            escalatedRequests.remove(requestID)
            pendingLock.unlock()
            return
        }

        NSWorkspace.shared.open(url) { [weak self] success, error in
            guard let self = self else { return }

            if success {
                NSLog("ApprovalManager: Launched dialog for request \(requestID)")
            } else {
                // Dialog failed to launch - remove from escalated so it can be retried
                self.pendingLock.lock()
                self.escalatedRequests.remove(requestID)
                self.pendingLock.unlock()

                if let error = error {
                    NSLog("ApprovalManager: Failed to launch dialog: \(error)")
                } else {
                    NSLog("ApprovalManager: Failed to launch dialog for request \(requestID)")
                }
            }
        }
    }

    // MARK: - Notifications

    private func showNotification(for request: ApprovalRequest) {
        let content = UNMutableNotificationContent()
        content.title = "Network Access Request"

        let appName = request.bundleID ?? request.processName
        content.subtitle = "\(appName) (PID: \(request.pid))"

        let destination = "\(request.targetHost):\(request.targetPort)/\(request.targetProtocol)"
        content.body = "Wants to connect to: \(destination)"

        content.categoryIdentifier = notificationCategory
        content.sound = .default

        // Store request ID in userInfo for handling actions
        content.userInfo = [
            "requestID": request.requestID,
            "processName": request.processName,
            "bundleID": request.bundleID ?? "",
            "targetHost": request.targetHost,
            "targetPort": request.targetPort,
            "targetProtocol": request.targetProtocol
        ]

        let notificationRequest = UNNotificationRequest(
            identifier: request.requestID,
            content: content,
            trigger: nil  // Show immediately
        )

        // Record attempt time BEFORE the async call so escalation works even if notification fails
        pendingLock.lock()
        notificationAttemptedAt[request.requestID] = Date()
        pendingLock.unlock()

        notificationCenter.add(notificationRequest) { error in
            if let error = error {
                NSLog("ApprovalManager: Failed to show notification: \(error)")
                // Attempt time already recorded - escalation will still work
            } else {
                NSLog("ApprovalManager: Showed notification for request \(request.requestID)")
            }
        }
    }

    // MARK: - Decision Handling

    /// Submit decision asynchronously (used for auto-timeout).
    private func submitDecisionAsync(requestID: String, decision: String) {
        guard let bridge = bridge else { return }
        bridge.submitApprovalDecision(requestID: requestID, decision: decision, permanent: false) { _ in }
    }

    /// Handle user decision from notification action.
    /// Uses Go-compatible decision vocabulary: allow_once, allow_permanent, deny_once, deny_forever
    private func handleDecision(requestID: String, decision: String) {
        guard let bridge = bridge else {
            NSLog("ApprovalManager: No bridge available for decision")
            return
        }

        // Determine if permanent based on decision type
        let permanent = decision == "allow_permanent" || decision == "deny_forever"

        bridge.submitApprovalDecision(requestID: requestID, decision: decision, permanent: permanent) { [weak self] success in
            guard let self = self else { return }

            if success {
                NSLog("ApprovalManager: Successfully submitted decision '\(decision)' for \(requestID)")
                // Only remove from tracking after successful submission
                self.pendingLock.lock()
                self.pendingRequests.removeValue(forKey: requestID)
                self.notificationAttemptedAt.removeValue(forKey: requestID)
                self.escalatedRequests.remove(requestID)
                self.pendingLock.unlock()
                // Remove notification
                self.notificationCenter.removeDeliveredNotifications(withIdentifiers: [requestID])
            } else {
                NSLog("ApprovalManager: Failed to submit decision for \(requestID), will retry on next poll")
                // Don't remove from tracking - will retry on next poll cycle
            }
        }
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension ApprovalManager: UNUserNotificationCenterDelegate {
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        guard let requestID = userInfo["requestID"] as? String else {
            NSLog("ApprovalManager: No requestID in notification response")
            completionHandler()
            return
        }

        let actionIdentifier = response.actionIdentifier

        // Use Go-compatible decision vocabulary
        switch actionIdentifier {
        case NotificationAction.allowOnce.rawValue:
            handleDecision(requestID: requestID, decision: "allow_once")

        case NotificationAction.allowAlways.rawValue:
            handleDecision(requestID: requestID, decision: "allow_permanent")

        case NotificationAction.denyOnce.rawValue:
            handleDecision(requestID: requestID, decision: "deny_once")

        case NotificationAction.denyAlways.rawValue:
            handleDecision(requestID: requestID, decision: "deny_forever")

        case UNNotificationDismissActionIdentifier:
            // User dismissed without action - treat as deny once
            NSLog("ApprovalManager: Notification dismissed for \(requestID)")
            handleDecision(requestID: requestID, decision: "deny_once")

        case UNNotificationDefaultActionIdentifier:
            // User tapped notification body - could open UI, for now treat as no action
            NSLog("ApprovalManager: Notification tapped for \(requestID)")

        default:
            NSLog("ApprovalManager: Unknown action \(actionIdentifier) for \(requestID)")
        }

        completionHandler()
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Show notifications even when app is in foreground
        completionHandler([.banner, .sound, .badge])
    }
}
