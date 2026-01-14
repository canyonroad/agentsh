# Approval Dialog Implementation Plan

## Overview

Implement the cross-platform native dialog system for approval requests as designed in `2026-01-14-approval-dialog-design.md`.

## Implementation Tasks

### Task 1: Create dialog package with detection logic

**Files to create:**
- `internal/approval/dialog/detect.go`

**Implementation:**
```go
package dialog

// IsCI returns true if running in a CI environment
func IsCI() bool

// HasDisplay returns true if a display is available
func HasDisplay() bool

// IsWSL returns true if running in Windows Subsystem for Linux
func IsWSL() bool

// IsEnabled returns true if dialog should be shown based on mode
func IsEnabled(mode string) bool
```

**Detection logic:**
- CI: Check env vars (CI, GITHUB_ACTIONS, GITLAB_CI, CIRCLECI, TRAVIS, JENKINS_URL, BUILDKITE)
- Display: Linux checks DISPLAY/WAYLAND_DISPLAY, others return true
- WSL: Check /proc/version for "microsoft" or "wsl"
- IsEnabled: disabled→false, enabled→true, auto→!IsCI() && (HasDisplay() || IsWSL())

**Tests:** `internal/approval/dialog/detect_test.go`

---

### Task 2: Create dialog interface and types

**Files to create:**
- `internal/approval/dialog/dialog.go`

**Implementation:**
```go
package dialog

type DialogRequest struct {
    Title   string
    Message string
    Allow   string        // Button label, default "Allow"
    Deny    string        // Button label, default "Deny"
    Timeout time.Duration
}

type DialogResponse struct {
    Allowed  bool
    TimedOut bool
}

// Show displays a native dialog and returns the user's choice
// Falls back gracefully if no dialog backend is available
func Show(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

**Tests:** `internal/approval/dialog/dialog_test.go`

---

### Task 3: Linux implementation (zenity/kdialog)

**Files to create:**
- `internal/approval/dialog/dialog_linux.go`

**Implementation:**
```go
//go:build linux

package dialog

func showNative(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

**Logic:**
1. Check if zenity exists in PATH → use zenity
2. Else check if kdialog exists → use kdialog
3. Else if IsWSL() → call showWindows via powershell.exe
4. Else return error (no backend)

**zenity command:**
```bash
zenity --question --title="<title>" --text="<message>" --ok-label="<allow>" --cancel-label="<deny>"
```
Exit 0 = Allow, Exit 1 = Deny

**kdialog command:**
```bash
kdialog --title "<title>" --yesno "<message>" --yes-label "<allow>" --no-label "<deny>"
```

**Tests:** `internal/approval/dialog/dialog_linux_test.go`

---

### Task 4: macOS implementation (osascript)

**Files to create:**
- `internal/approval/dialog/dialog_darwin.go`

**Implementation:**
```go
//go:build darwin

package dialog

func showNative(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

**Logic:**
```bash
osascript -e 'display dialog "<message>" with title "<title>" buttons {"<deny>", "<allow>"} default button "<deny>"'
```
Parse stdout for button name.

**Tests:** `internal/approval/dialog/dialog_darwin_test.go`

---

### Task 5: Windows implementation (PowerShell)

**Files to create:**
- `internal/approval/dialog/dialog_windows.go`

**Implementation:**
```go
//go:build windows

package dialog

func showNative(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

**Logic:**
```powershell
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("<message>", "<title>", "YesNo")
```
Returns "Yes" = Allow, "No" = Deny

**Also export for WSL:**
```go
func showWindows(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

**Tests:** `internal/approval/dialog/dialog_windows_test.go`

---

### Task 6: Update PNACL config structs

**Files to modify:**
- `internal/netmonitor/pnacl/config.go`

**Changes:**
1. Add `ApprovalUI *ApprovalUIConfig` field to Config struct
2. Add ApprovalUIConfig struct with Mode and Timeout fields
3. Add GetMode() method
4. Update Validate() to validate approval_ui settings

**Tests:** Update `internal/netmonitor/pnacl/config_test.go`

---

### Task 7: Create DialogPromptProvider for PNACL

**Files to create:**
- `internal/netmonitor/pnacl/dialog_prompt.go`

**Implementation:**
```go
package pnacl

type DialogPromptProvider struct {
    fallbackDecision UserDecision
}

func (p *DialogPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error)
```

**Logic:**
1. Build DialogRequest from ApprovalRequest
2. Call dialog.Show()
3. Convert DialogResponse to ApprovalResponse
4. Handle timeout/error with fallbackDecision

**Tests:** `internal/netmonitor/pnacl/dialog_prompt_test.go`

---

### Task 8: Wire up dialog in monitor initialization

**Files to modify:**
- `internal/netmonitor/pnacl/approval.go` or monitor setup code

**Changes:**
1. Check dialog.IsEnabled(config.ApprovalUI.GetMode())
2. If enabled, create DialogPromptProvider and set on ApprovalProvider
3. If disabled, use existing TTYPromptProvider or no-op

---

## Task Dependencies

```
Task 1 (detect) ─────────────────────┐
                                     ├─→ Task 2 (interface) ─→ Task 7 (PNACL adapter) ─→ Task 8 (wiring)
Task 3 (linux)  ─────────────────────┤
Task 4 (darwin) ─────────────────────┤
Task 5 (windows) ────────────────────┘
Task 6 (config) ─────────────────────────────────────────────→ Task 8 (wiring)
```

**Parallelizable:**
- Tasks 1, 3, 4, 5, 6 can run in parallel
- Task 2 depends on Task 1
- Task 7 depends on Tasks 2 and 6
- Task 8 depends on Tasks 7

## Testing Strategy

- Unit tests for each platform implementation (mock exec.Command)
- Unit tests for detection logic (mock env vars and file reads)
- Integration test for PNACL config parsing
- Manual testing on each platform

## Files Summary

**New files:**
- `internal/approval/dialog/detect.go`
- `internal/approval/dialog/detect_test.go`
- `internal/approval/dialog/dialog.go`
- `internal/approval/dialog/dialog_test.go`
- `internal/approval/dialog/dialog_linux.go`
- `internal/approval/dialog/dialog_linux_test.go`
- `internal/approval/dialog/dialog_darwin.go`
- `internal/approval/dialog/dialog_darwin_test.go`
- `internal/approval/dialog/dialog_windows.go`
- `internal/approval/dialog/dialog_windows_test.go`
- `internal/netmonitor/pnacl/dialog_prompt.go`
- `internal/netmonitor/pnacl/dialog_prompt_test.go`

**Modified files:**
- `internal/netmonitor/pnacl/config.go`
- `internal/netmonitor/pnacl/config_test.go`
- `internal/netmonitor/pnacl/approval.go` (or monitor setup)
