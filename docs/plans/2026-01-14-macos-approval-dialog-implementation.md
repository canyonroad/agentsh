# macOS Approval Dialog Implementation Plan

## Overview

Implement standalone SwiftUI macOS app that shows modal approval dialogs when PNACL notifications are ignored.

## Tasks

### Task 1: Create ApprovalDialog App Structure
**Files to create:**
- `macos/ApprovalDialog/Info.plist` - App metadata with URL scheme registration
- `macos/ApprovalDialog/ApprovalDialog.entitlements` - App entitlements

**Details:**
- Bundle ID: `com.agentsh.approval-dialog`
- URL scheme: `agentsh-approval://`
- Minimum macOS: 13.0

### Task 2: Implement ServerClient
**File to create:**
- `macos/ApprovalDialog/ServerClient.swift`

**Details:**
- Unix socket client for `/var/run/agentsh/policy.sock`
- `fetchApproval(requestID:)` - Get pending approval by ID
- `submitDecision(requestID:decision:permanent:)` - Submit user decision
- JSON serialization matching Go server protocol
- 5 second timeout

### Task 3: Implement ApprovalView (SwiftUI)
**File to create:**
- `macos/ApprovalDialog/ApprovalView.swift`

**Details:**
- Display process info: name, bundle ID, path, PID
- Display connection info: host, port, protocol
- Timeout progress indicator
- 4 action buttons: Allow Once, Allow Always, Deny Once, Deny Always
- ~420px fixed width

### Task 4: Implement ApprovalDialogApp (Main Entry)
**File to create:**
- `macos/ApprovalDialog/ApprovalDialogApp.swift`

**Details:**
- SwiftUI @main entry point
- Handle `onOpenURL` for `agentsh-approval://approve?id=xxx`
- Fetch request details via ServerClient
- Show ApprovalView
- Activate app to front
- Quit after decision submitted

### Task 5: Update ApprovalManager with Escalation Logic
**File to modify:**
- `macos/XPCService/ApprovalManager.swift`

**Details:**
- Track notification shown timestamps
- Check for 15-second escalation timeout in polling loop
- Launch dialog via `NSWorkspace.shared.open(url)`
- Remove escalation tracking after dialog launched or decision received

### Task 6: Update Build System
**Files to modify:**
- `Makefile` - Add build-approval-dialog target
- Possibly Xcode project files

**Details:**
- Build ApprovalDialog.app via xcodebuild
- Copy to AgentSH.app/Contents/Resources/
- Code signing

## Verification

1. Build all Swift targets successfully
2. Run existing XPC and PNACL tests (should still pass)
3. Manual test: `open "agentsh-approval://approve?id=test"` launches app
4. Manual test: Dialog shows with mock data, buttons work
