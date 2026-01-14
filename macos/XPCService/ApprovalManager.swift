// macos/XPCService/ApprovalManager.swift
import Foundation
import UserNotifications

/// Manages the approval flow for PNACL Phase 3.
/// Polls the Go server for pending approvals and shows macOS notifications.
class ApprovalManager: NSObject {
    /// Shared instance for the XPC service.
    static let shared = ApprovalManager()

    /// Polling interval in seconds.
    private let pollInterval: TimeInterval = 1.0

    /// Reference to the policy bridge for server communication.
    weak var bridge: PolicyBridge?

    /// Timer for periodic polling.
    private var pollTimer: DispatchSourceTimer?

    /// Queue for polling operations.
    private let pollQueue = DispatchQueue(label: "com.agentsh.approval.poll", qos: .utility)

    /// Currently tracked pending requests (by requestID).
    private var pendingRequests: [String: ApprovalRequest] = [:]
    private let pendingLock = NSLock()

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
        notificationCenter.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                NSLog("ApprovalManager: Notification permission error: \(error)")
            } else if granted {
                NSLog("ApprovalManager: Notification permissions granted")
            } else {
                NSLog("ApprovalManager: Notification permissions denied")
            }
        }
    }

    // MARK: - Polling

    private func startPolling() {
        stopPolling()

        let timer = DispatchSource.makeTimerSource(queue: pollQueue)
        timer.schedule(deadline: .now(), repeating: pollInterval)
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

        bridge.fetchPendingApprovals { [weak self] (approvals: [ApprovalRequest]) in
            self?.handleApprovals(approvals)
        }
    }

    private func handleApprovals(_ approvals: [ApprovalRequest]) {
        pendingLock.lock()
        defer { pendingLock.unlock() }

        // Find new approvals that we haven't notified about yet
        let existingIDs = Set(pendingRequests.keys)
        let newApprovals = approvals.filter { !existingIDs.contains($0.requestID) }

        // Update our tracking
        var currentIDs = Set<String>()
        for approval in approvals {
            currentIDs.insert(approval.requestID)
            pendingRequests[approval.requestID] = approval
        }

        // Remove expired/resolved approvals from tracking
        let removedIDs = existingIDs.subtracting(currentIDs)
        for id in removedIDs {
            pendingRequests.removeValue(forKey: id)
            // Remove any pending notification for this request
            notificationCenter.removeDeliveredNotifications(withIdentifiers: [id])
            notificationCenter.removePendingNotificationRequests(withIdentifiers: [id])
        }

        // Show notifications for new approvals
        for approval in newApprovals {
            showNotification(for: approval)
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

        // Calculate time until timeout for the notification trigger
        let timeoutDate = request.timestamp.addingTimeInterval(request.timeout)
        let remainingTime = timeoutDate.timeIntervalSinceNow

        // Use immediate trigger if timeout is imminent, otherwise set a reminder
        let trigger: UNNotificationTrigger?
        if remainingTime > 5 {
            trigger = UNTimeIntervalNotificationTrigger(timeInterval: 0.1, repeats: false)
        } else {
            trigger = nil
        }

        let notificationRequest = UNNotificationRequest(
            identifier: request.requestID,
            content: content,
            trigger: trigger
        )

        notificationCenter.add(notificationRequest) { error in
            if let error = error {
                NSLog("ApprovalManager: Failed to show notification: \(error)")
            } else {
                NSLog("ApprovalManager: Showed notification for request \(request.requestID)")
            }
        }
    }

    // MARK: - Decision Handling

    private func handleDecision(requestID: String, decision: String, permanent: Bool) {
        guard let bridge = bridge else {
            NSLog("ApprovalManager: No bridge available for decision")
            return
        }

        bridge.submitApprovalDecision(requestID: requestID, decision: decision, permanent: permanent) { success in
            if success {
                NSLog("ApprovalManager: Successfully submitted decision '\(decision)' for \(requestID)")
            } else {
                NSLog("ApprovalManager: Failed to submit decision for \(requestID)")
            }
        }

        // Remove from our tracking
        pendingLock.lock()
        pendingRequests.removeValue(forKey: requestID)
        pendingLock.unlock()

        // Remove notification
        notificationCenter.removeDeliveredNotifications(withIdentifiers: [requestID])
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

        switch actionIdentifier {
        case NotificationAction.allowOnce.rawValue:
            handleDecision(requestID: requestID, decision: "allow", permanent: false)

        case NotificationAction.allowAlways.rawValue:
            handleDecision(requestID: requestID, decision: "allow", permanent: true)

        case NotificationAction.denyOnce.rawValue:
            handleDecision(requestID: requestID, decision: "deny", permanent: false)

        case NotificationAction.denyAlways.rawValue:
            handleDecision(requestID: requestID, decision: "deny", permanent: true)

        case UNNotificationDismissActionIdentifier:
            // User dismissed without action - treat as deny once
            NSLog("ApprovalManager: Notification dismissed for \(requestID)")
            handleDecision(requestID: requestID, decision: "deny", permanent: false)

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
