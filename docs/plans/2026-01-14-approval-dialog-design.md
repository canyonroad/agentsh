# Interactive Approval Dialog Design

## Overview

A cross-platform native dialog system for interactive approval requests. Primarily used for PNACL (Process Network ACL) approval prompts on developer machines, but designed as a reusable component for any approval workflow in the system.

## Requirements

- Show native modal dialogs on Linux, macOS, and Windows
- Auto-detect environment (developer machine vs CI/CD)
- Configurable via `network-acl.yml`
- Fall back gracefully when no display available
- Reusable for non-network approvals

## Configuration

Add to `network-acl.yml`:

```yaml
network_acl:
  default: deny

  # Interactive approval UI (optional)
  approval_ui:
    # "auto" (default) | "enabled" | "disabled"
    # auto: detect display availability, disable in CI
    mode: auto

    # Timeout for user response (uses existing approval timeout if not set)
    timeout: 30s

  processes:
    # ... existing process rules
```

### Auto-detection Logic

| Condition | Result |
|-----------|--------|
| `mode: disabled` | Disabled |
| `mode: enabled` | Enabled (force) |
| `mode: auto` + CI environment detected | Disabled |
| `mode: auto` + display available | Enabled |
| `mode: auto` + WSL without display | Enabled (use PowerShell) |
| `mode: auto` + no display | Disabled |

**CI detection:** Check for `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TRAVIS`, `JENKINS_URL`, `BUILDKITE` environment variables.

**Display detection:**
- Linux: `DISPLAY` or `WAYLAND_DISPLAY` environment variables
- macOS/Windows: Always available in desktop session

## Platform Implementations

### Linux

Primary: `zenity` (GTK, widely available)
Fallback: `kdialog` (KDE)

```bash
zenity --question \
  --title="Network Access Request" \
  --text="Process: node (pid: 12345)\nTarget: api.anthropic.com:443 (tcp)" \
  --ok-label="Allow" \
  --cancel-label="Deny"
# Exit code: 0 = Allow, 1 = Deny/Cancel
```

### macOS

Use `osascript` with AppleScript (no external dependencies):

```bash
osascript -e 'display dialog "Process: node (pid: 12345)\nTarget: api.anthropic.com:443 (tcp)" with title "Network Access Request" buttons {"Deny", "Allow"} default button "Deny"'
# Returns button name in stdout
```

### Windows

PowerShell with Windows Forms MessageBox:

```powershell
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show(
  "Process: node (pid: 12345)`nTarget: api.anthropic.com:443 (tcp)",
  "Network Access Request",
  "YesNo"
)
# Returns "Yes" (Allow) or "No" (Deny)
```

### WSL (Windows Subsystem for Linux)

Hybrid approach:
1. If `DISPLAY`/`WAYLAND_DISPLAY` set (WSLg or X server) → use zenity/kdialog
2. If no display → call `powershell.exe` directly

WSL detection: Check `/proc/version` for "Microsoft" or "WSL".

## Dialog UI

Simple 2-button dialog:

```
┌─────────────────────────────────────────────┐
│  Network Access Request                     │
├─────────────────────────────────────────────┤
│  Process: node (pid: 12345)                 │
│  Target:  api.anthropic.com:443 (tcp)       │
│                                             │
│          [Allow]          [Deny]            │
└─────────────────────────────────────────────┘
```

| Action | Result |
|--------|--------|
| Click "Allow" | Allow connection |
| Click "Deny" | Deny connection |
| Close/Dismiss dialog | Deny connection |
| Timeout | Use fallback decision from config |

## Code Architecture

### Package Structure

```
internal/approval/
├── dialog/
│   ├── dialog.go         # DialogProvider, auto-detection logic
│   ├── dialog_linux.go   # Linux: zenity/kdialog
│   ├── dialog_darwin.go  # macOS: osascript
│   ├── dialog_windows.go # Windows: PowerShell
│   └── detect.go         # Environment detection (CI, display, WSL)
```

### Generic Interface

```go
// DialogRequest is a generic approval dialog request
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
func Show(ctx context.Context, req DialogRequest) (DialogResponse, error)
```

### Detection Functions

```go
func IsCI() bool {
    envs := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
                     "TRAVIS", "JENKINS_URL", "BUILDKITE"}
    for _, e := range envs {
        if os.Getenv(e) != "" {
            return true
        }
    }
    return false
}

func HasDisplay() bool {
    if runtime.GOOS == "linux" {
        return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
    }
    return true // macOS and Windows always have display in desktop session
}

func IsWSL() bool {
    data, err := os.ReadFile("/proc/version")
    if err != nil {
        return false
    }
    lower := strings.ToLower(string(data))
    return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

func IsEnabled(mode string) bool {
    switch mode {
    case "disabled":
        return false
    case "enabled":
        return true
    default: // "auto"
        if IsCI() {
            return false
        }
        return HasDisplay() || IsWSL()
    }
}
```

### PNACL Integration

Adapter to connect generic dialog to PNACL's `PromptProvider` interface:

```go
// In internal/netmonitor/pnacl/dialog_prompt.go

type DialogPromptProvider struct {
    fallbackDecision UserDecision
}

func (p *DialogPromptProvider) Prompt(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error) {
    resp, err := dialog.Show(ctx, dialog.DialogRequest{
        Title:   "Network Access Request",
        Message: fmt.Sprintf("Process: %s (pid: %d)\nTarget: %s:%d (%s)",
            req.ProcessName, req.PID, req.Target, req.Port, req.Protocol),
        Timeout: time.Until(req.ExpiresAt),
    })

    if err != nil || resp.TimedOut {
        return ApprovalResponse{
            RequestID: req.ID,
            Decision:  p.fallbackDecision,
        }, err
    }

    decision := UserDecisionDenyOnce
    if resp.Allowed {
        decision = UserDecisionAllowOnce
    }

    return ApprovalResponse{
        RequestID: req.ID,
        Decision:  decision,
        At:        time.Now().UTC(),
    }, nil
}
```

Wiring in monitor setup:

```go
if dialog.IsEnabled(config.ApprovalUI.GetMode()) {
    approvalProvider.SetPromptProvider(&DialogPromptProvider{
        fallbackDecision: UserDecisionDenyOnce,
    })
}
```

### Config Structs

```go
type Config struct {
    Default    string            `yaml:"default,omitempty"`
    ApprovalUI *ApprovalUIConfig `yaml:"approval_ui,omitempty"`
    Processes  []ProcessConfig   `yaml:"processes,omitempty"`
}

type ApprovalUIConfig struct {
    Mode    string `yaml:"mode,omitempty"`    // "auto", "enabled", "disabled"
    Timeout string `yaml:"timeout,omitempty"` // e.g., "30s"
}

func (c *ApprovalUIConfig) GetMode() string {
    if c == nil || c.Mode == "" {
        return "auto"
    }
    return c.Mode
}
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `zenity` not installed (Linux) | Try `kdialog`, then fall back to timeout/default |
| Dialog process killed | Treat as Deny |
| Dialog times out | Return `TimedOut: true`, use fallback decision |
| Multiple dialogs at once | Queue them (OS handles stacking) |
| Display disconnected mid-dialog | Dialog fails, treat as Deny |
| WSL without PowerShell | Fall back to timeout/default |

## Future Enhancements

- **"Allow Always" button**: Requires defining semantics (session scope vs config persistence)
- **Rule suggestions**: Analyze recorded decisions and suggest permanent rules
- **Notification mode**: Optional non-modal notifications for audit-only scenarios
- **Batch approval UI**: Review multiple pending requests at once

## Event Recording

All decisions are recorded via the existing `EventEmitter` interface for later analysis:

```go
type NetworkACLEvent struct {
    Timestamp   time.Time
    ProcessName string
    ProcessPath string
    PID         int
    ParentPID   int
    Target      string
    Port        int
    Protocol    string
    Decision    string
    RuleSource  string
    UserAction  string
}
```

This enables future features like auto-generating rule suggestions from approval history.
