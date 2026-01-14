# macOS Approval Dialog App Design

## Overview

Standalone SwiftUI app that shows modal approval dialogs when PNACL network access approval is needed and the user ignores the initial notification.

## Behavior Flow

1. Network request triggers approval → XPC Service shows notification
2. If user ignores notification for **15 seconds** → Launch ApprovalDialog.app
3. Dialog shows request details with 4 action buttons
4. User clicks button → Decision sent to Go server → App quits
5. If dialog also ignored → Follow server's `failOpen` setting

## Architecture

```
Notification (15s timeout)
    ↓ ignored
ApprovalManager: NSWorkspace.shared.open("agentsh-approval://approve?id=xxx")
    ↓
ApprovalDialog.app launches
    ↓
Fetches request details from Go server (Unix socket)
    ↓
Shows SwiftUI dialog (activates to front)
    ↓
User clicks button
    ↓
Submits decision to Go server
    ↓
App quits
```

## File Structure

```
macos/ApprovalDialog/
├── ApprovalDialogApp.swift    # @main entry, URL handling
├── ApprovalView.swift         # SwiftUI dialog UI
├── ServerClient.swift         # Go server communication
├── Info.plist                 # URL scheme: agentsh-approval://
└── ApprovalDialog.entitlements
```

## URL Scheme

**Scheme:** `agentsh-approval://approve?id=<requestID>`

Registered in Info.plist:
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>agentsh-approval</string></array>
    <key>CFBundleURLName</key>
    <string>com.agentsh.approval</string>
  </dict>
</array>
```

## Dialog UI

SwiftUI view with:
- Warning icon (SF Symbol: `network.badge.shield.half.filled`)
- "Network Access Request" title
- Application info: name, bundle ID, path, PID
- Connection info: host, port, protocol
- Timeout progress indicator
- 4 buttons:
  - Deny Once (`deny_once`)
  - Deny Always (`deny_forever`)
  - Allow Once (`allow_once`) - primary
  - Allow Always (`allow_permanent`)

Window behavior:
- Fixed size (~420px wide)
- Centered on screen
- Always on top
- App activates to front on launch
- Dock icon bounces if not focused

## Server Communication

Uses Unix socket at `/var/run/agentsh/policy.sock`:

1. **Fetch approval:** `GET get_pending_approvals` → find by requestID
2. **Submit decision:** `POST submit_approval` with requestID, decision, permanent flag

Timeout: 5 seconds per request.

## ApprovalManager Changes

Add escalation tracking:
```swift
private var notificationShownAt: [String: Date] = [:]
private let escalationDelay: TimeInterval = 15.0

// Track when notification shown
// In polling loop, check if 15s passed → launch dialog
// Remove tracking after escalation or decision
```

## Build Integration

- Add ApprovalDialog scheme to Xcode project
- Build via xcodebuild in Makefile
- Copy ApprovalDialog.app to AgentSH.app/Contents/Resources/
- Code sign with appropriate entitlements

## Files to Modify

1. `macos/XPCService/ApprovalManager.swift` - Add escalation logic
2. `macos/Shared/` - May extract SocketClient for reuse
3. `Makefile` - Add build-approval-dialog target

## Files to Create

1. `macos/ApprovalDialog/ApprovalDialogApp.swift`
2. `macos/ApprovalDialog/ApprovalView.swift`
3. `macos/ApprovalDialog/ServerClient.swift`
4. `macos/ApprovalDialog/Info.plist`
5. `macos/ApprovalDialog/ApprovalDialog.entitlements`
