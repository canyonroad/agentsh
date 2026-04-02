# macOS FUSE-T Removal & ESF Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace FUSE-T with ESF as the sole file monitoring mechanism on macOS, rename the XPC package to policysock, add secure socket authentication, and add NE proxy enforcement for eBPF parity.

**Architecture:** The ESF system extension handles file/process monitoring via AUTH/NOTIFY events. The Go server communicates with the sysext via a secure Unix socket (policy socket) at `/var/run/agentsh/policy.sock`. The NetworkExtension content filter enforces that session PIDs connect through the HTTP proxy, blocking direct external connections. FUSE-T is removed entirely from macOS (Linux/Windows FUSE unaffected).

**Tech Stack:** Go (server), Swift (sysext), Unix domain sockets, macOS code signing APIs, Endpoint Security Framework, NetworkExtension

**Spec:** `docs/superpowers/specs/2026-04-02-macos-fuse-removal-esf-integration-design.md`

---

## File Structure

### Files to Modify (Go)
| File | Responsibility |
|------|---------------|
| `internal/platform/fuse/detect_darwin.go` | FUSE availability detection (→ always false) |
| `internal/platform/fuse/detect_darwin_test.go` | Tests for above |
| `internal/platform/darwin/permissions.go` | macOS permission/tier detection |
| `internal/platform/darwin/permissions_test.go` | Tests for above |
| `internal/platform/darwin/platform.go` | Platform capability mapping |
| `internal/platform/darwin/platform_test.go` | Tests for above |
| `internal/platform/darwin/sysext.go` | Sysext bundle ID constant |
| `internal/platform/darwin/sysext_test.go` | Tests for above |
| `internal/capabilities/detect_darwin.go` | Capability detection and mode selection |
| `internal/capabilities/detect_darwin_test.go` | Tests for above |
| `internal/capabilities/tips.go` | Tip definitions for missing capabilities |
| `internal/platform/darwin/es_exec.go` | Import path update (xpc→policysock) |
| `internal/platform/darwin/es_exec_test.go` | Import path update |
| `internal/platform/darwin/es_exec_integration_test.go` | Import path update |

### Files to Move (Go — 14 files)
| From | To |
|------|-----|
| `internal/platform/darwin/xpc/*` | `internal/platform/darwin/policysock/*` |

All 14 files: `server.go`, `server_test.go`, `protocol.go`, `protocol_test.go`, `handler.go`, `handler_test.go`, `sessions.go`, `sessions_test.go`, `snapshot.go`, `snapshot_test.go`, `version.go`, `version_test.go`, `event_handler_test.go`, `integration_test.go`

### Files to Create (Go)
| File | Responsibility |
|------|---------------|
| `internal/platform/darwin/policysock/auth.go` | Peer UID/PID/code-signing validation |
| `internal/platform/darwin/policysock/auth_test.go` | Tests for above |

### Files to Modify (Swift)
| File | Responsibility |
|------|---------------|
| `macos/AgentSH/PolicySocketClient.swift` | Add server validation after connect |
| `macos/AgentSH/SessionPolicyCache.swift` | Add proxyAddr, directAllow to SessionCache |
| `macos/AgentSH/FilterDataProvider.swift` | Add proxy enforcement in handleNewFlow() |

---

### Task 1: Fix Sysext Bundle ID Inconsistency

**Files:**
- Modify: `internal/platform/darwin/sysext.go:38`
- Modify: `internal/platform/darwin/sysext_test.go:14,29,38,53,162,163,168,190,205`

**Context:** The canonical sysext bundle ID is `ai.canyonroad.agentsh.SysExt` (matches the Xcode project's `PRODUCT_BUNDLE_IDENTIFIER` which overrides Info.plist at build time, and matches `systemextensionsctl` output). The Go code uses lowercase `ai.canyonroad.agentsh.sysext`. This must be fixed before other tasks reference the bundle ID. Note: `Info.plist` has lowercase `CFBundleIdentifier` but Xcode's build setting overrides it — no Info.plist change needed.

- [ ] **Step 1: Update the bundle ID constant in sysext.go**

In `internal/platform/darwin/sysext.go`, change line 38:
```go
// Before:
bundleID:   "ai.canyonroad.agentsh.sysext",

// After:
bundleID:   "ai.canyonroad.agentsh.SysExt",
```

- [ ] **Step 2: Update all bundle ID references in sysext_test.go**

In `internal/platform/darwin/sysext_test.go`, replace all occurrences of `"ai.canyonroad.agentsh.sysext"` with `"ai.canyonroad.agentsh.SysExt"`. There are references at lines 14, 15, 29, 30, 38, 53, 162, 163, 168, 190, 205.

- [ ] **Step 3: Run tests**

Run: `go test ./internal/platform/darwin/ -run TestSysExt -v`
Expected: PASS (tests use mock data, not real systemextensionsctl)

- [ ] **Step 4: Commit**

```bash
git add internal/platform/darwin/sysext.go internal/platform/darwin/sysext_test.go
git commit -m "fix(darwin): use canonical SysExt bundle ID casing"
```

---

### Task 2: Remove FUSE-T Detection on macOS

**Files:**
- Modify: `internal/platform/fuse/detect_darwin.go` (entire file)
- Modify: `internal/platform/fuse/detect_darwin_test.go` (entire file)

**Context:** macOS now uses ESF for file monitoring. FUSE detection should always return false/none on darwin. Linux and Windows FUSE detection is in separate files and unaffected.

- [ ] **Step 1: Replace detect_darwin.go**

Replace the entire contents of `internal/platform/fuse/detect_darwin.go`:

```go
// internal/platform/fuse/detect_darwin.go
//go:build darwin

package fuse

// macOS uses the Endpoint Security Framework (via system extension) for file
// monitoring instead of FUSE. FUSE mounting is not used on macOS.

func checkAvailable() bool {
	return false
}

func detectImplementation() string {
	return "none"
}
```

- [ ] **Step 2: Replace detect_darwin_test.go**

Replace the entire contents of `internal/platform/fuse/detect_darwin_test.go`:

```go
//go:build darwin

package fuse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAvailable_AlwaysFalse(t *testing.T) {
	assert.False(t, checkAvailable(), "FUSE is not used on macOS")
}

func TestDetectImplementation_AlwaysNone(t *testing.T) {
	assert.Equal(t, "none", detectImplementation(), "FUSE implementation should be none on macOS")
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/platform/fuse/ -v`
Expected: PASS

- [ ] **Step 4: Verify cross-compilation still works**

Run: `GOOS=linux go build ./internal/platform/fuse/`
Expected: Builds without error (Linux FUSE detection is in separate files)

- [ ] **Step 5: Commit**

```bash
git add internal/platform/fuse/detect_darwin.go internal/platform/fuse/detect_darwin_test.go
git commit -m "feat(darwin): remove FUSE-T detection, macOS uses ESF for file monitoring"
```

---

### Task 3: Collapse macOS Tier System to 3 Tiers

**Files:**
- Modify: `internal/platform/darwin/permissions.go:14-27,65-89,101-126,138-172,197-261,263-308,328-385`
- Modify: `internal/platform/darwin/permissions_test.go`

**Context:** The current 5-tier system (Enterprise/Full/NetworkOnly/MonitorOnly/Minimal) collapses to 3 tiers (Enterprise/Standard/Minimal) since FUSE-T removal makes Full and NetworkOnly identical. `HasSystemExtension` replaces `HasFuseT` for tier computation.

- [ ] **Step 1: Update the PermissionTier enum**

In `internal/platform/darwin/permissions.go`, replace the tier constants (lines 14–27):

```go
const (
	// TierEnterprise has the system extension installed (ESF + Network Extension).
	TierEnterprise PermissionTier = iota
	// TierStandard has root + pf but no system extension.
	TierStandard
	// TierMinimal provides only command execution logging.
	TierMinimal
)
```

Update `String()` (lines 30–45):
```go
func (t PermissionTier) String() string {
	switch t {
	case TierEnterprise:
		return "enterprise"
	case TierStandard:
		return "standard"
	case TierMinimal:
		return "minimal"
	default:
		return "unknown"
	}
}
```

Update `SecurityScore()` (lines 47–63):
```go
func (t PermissionTier) SecurityScore() int {
	switch t {
	case TierEnterprise:
		return 95
	case TierStandard:
		return 50
	case TierMinimal:
		return 10
	default:
		return 0
	}
}
```

- [ ] **Step 2: Update the Permissions struct**

Replace the FUSE fields in the `Permissions` struct (lines 65–89):

```go
type Permissions struct {
	// System Extension (provides ESF + NE)
	HasSystemExtension bool // System extension installed and activated

	// Basic Permissions
	HasRootAccess     bool
	HasFullDiskAccess bool

	// Fallbacks
	CanUsePF    bool
	HasFSEvents bool // Always true on macOS
	HasLibpcap  bool

	// Computed
	Tier               PermissionTier
	MissingPermissions []MissingPermission
	DetectedAt         time.Time
}
```

Note: `HasEndpointSecurity` and `HasNetworkExtension` are removed — they checked the running binary's entitlements, which the CLI never has. The sysext provides both ESF and NE, so `HasSystemExtension` is sufficient for tier computation.

- [ ] **Step 3: Update DetectPermissions()**

Replace `DetectPermissions()` (lines 101–126):

```go
func DetectPermissions() *Permissions {
	p := &Permissions{
		HasFSEvents: true,
		DetectedAt:  time.Now(),
	}

	// Check if system extension is installed and activated
	p.HasSystemExtension = checkSysExtInstalled()

	// Check basic permissions
	p.HasRootAccess = os.Geteuid() == 0
	p.HasFullDiskAccess = checkFullDiskAccess()
	p.CanUsePF = p.HasRootAccess && checkPFAvailable()
	p.HasLibpcap = checkLibpcapAvailable()

	// Compute tier and missing permissions
	p.computeTier()
	p.computeMissingPermissions()

	return p
}
```

Also remove the `checkEntitlement()` function (lines 128–136) — it is no longer used.

- [ ] **Step 4: Add checkSysExtInstalled() and remove FUSE-T functions**

Delete `checkFuseT()` (lines 138–158) and `checkMacFUSE()` (lines 160–172). Add:

```go
// checkSysExtInstalled checks if the agentsh system extension is installed and activated.
func checkSysExtInstalled() bool {
	cmd := exec.Command("systemextensionsctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	// Check for activated extension with canonical bundle ID
	return strings.Contains(string(output), "ai.canyonroad.agentsh.SysExt") &&
		strings.Contains(string(output), "activated enabled")
}
```

- [ ] **Step 5: Update computeTier()**

Replace `computeTier()` (lines 197–211):

```go
func (p *Permissions) computeTier() {
	switch {
	case p.HasSystemExtension:
		p.Tier = TierEnterprise
	case p.HasRootAccess && p.CanUsePF:
		p.Tier = TierStandard
	default:
		p.Tier = TierMinimal
	}
}
```

- [ ] **Step 6: Update computeMissingPermissions()**

Replace `computeMissingPermissions()` (lines 213–261):

```go
func (p *Permissions) computeMissingPermissions() {
	p.MissingPermissions = []MissingPermission{}

	if !p.HasSystemExtension {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "System Extension",
			Description: "ESF-based file/process monitoring and Network Extension filtering",
			Impact:      "Cannot intercept or block file operations. File monitoring unavailable.",
			HowToEnable: "Install the agentsh macOS app bundle which includes the system extension.\n" +
				"After installation, approve it in System Settings > Privacy & Security.",
			Required: false,
		})
	}

	if !p.HasRootAccess {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "Root Access",
			Description: "Administrator privileges for pf network interception",
			Impact:      "Cannot use pf for network interception. Network policy enforcement disabled.",
			HowToEnable: "Run agentsh with sudo:\n  sudo agentsh server",
			Required:    false,
		})
	}

	if !p.HasFullDiskAccess {
		p.MissingPermissions = append(p.MissingPermissions, MissingPermission{
			Name:        "Full Disk Access",
			Description: "Access to protected directories (Mail, Messages, Safari, etc.)",
			Impact:      "Cannot monitor file operations in protected system directories.",
			HowToEnable: "1. Open System Settings > Privacy & Security > Full Disk Access\n" +
				"2. Click '+' and add Terminal.app or the agentsh binary\n" +
				"3. Restart agentsh",
			Required: false,
		})
	}
}
```

- [ ] **Step 7: Update AvailableFeatures() and DisabledFeatures()**

Replace `AvailableFeatures()` (lines 263–308):

```go
func (p *Permissions) AvailableFeatures() []string {
	switch p.Tier {
	case TierEnterprise:
		return []string{
			"file_read_interception (ESF - can block)",
			"file_write_interception (ESF - can block)",
			"process_exec_blocking (ESF)",
			"network_interception (NE - can block)",
			"per_app_network_filtering (NE)",
			"dns_interception",
			"tls_inspection",
			"kernel_event_monitoring",
			"command_logging",
		}
	case TierStandard:
		return []string{
			"file_monitoring (FSEvents - observe only)",
			"network_interception (pf - can block)",
			"dns_interception",
			"tls_inspection",
			"command_logging",
		}
	case TierMinimal:
		return []string{
			"command_logging",
		}
	default:
		return []string{}
	}
}
```

Replace `DisabledFeatures()` (lines 310–327):

```go
func (p *Permissions) DisabledFeatures() []string {
	switch p.Tier {
	case TierEnterprise:
		return []string{}
	case TierStandard:
		return []string{"file_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
	case TierMinimal:
		return []string{"file_monitoring", "file_blocking", "network_monitoring", "network_blocking", "process_blocking", "per_app_filtering", "kernel_events"}
	default:
		return []string{}
	}
}
```

- [ ] **Step 8: Update LogStatus()**

Replace the "Filesystem Interception" section in `LogStatus()` (around lines 345–351):

```go
	// System Extension
	sb.WriteString("System Extension:\n")
	sb.WriteString(formatPermission("SysExt Installed", p.HasSystemExtension, "ESF + Network Extension via system extension"))
	sb.WriteString("\n")
```

Remove the `if p.HasMacFUSE` block (lines 348–350).

Also update line 375 which references the now-removed `TierFull`:
```go
// Before:
if mp.Required || p.Tier > TierFull {

// After:
if mp.Required || p.Tier > TierEnterprise {
```

- [ ] **Step 9: Update permissions_test.go**

Update test cases in `internal/platform/darwin/permissions_test.go` to use the 3-tier model:
- `TestPermissionTier_String`: test `enterprise`, `standard`, `minimal`
- `TestPermissionTier_SecurityScore`: test 95, 50, 10
- `TestPermissions_computeTier`: test sysext→Enterprise, root+pf→Standard, nothing→Minimal
- `TestPermissions_AvailableFeatures`: test Enterprise has ESF features, Standard has FSEvents/pf
- `TestPermissions_DisabledFeatures`: update for 3 tiers
- `TestPermissions_computeMissingPermissions`: test sysext install tip instead of FUSE-T

- [ ] **Step 10: Run tests**

Run: `go test ./internal/platform/darwin/ -v`
Expected: PASS (run all darwin tests to catch any references to removed tiers/fields)

- [ ] **Step 11: Commit**

```bash
git add internal/platform/darwin/permissions.go internal/platform/darwin/permissions_test.go
git commit -m "feat(darwin): collapse tier system to 3 tiers, replace FUSE-T with sysext detection"
```

---

### Task 4: Update Platform Capability Mapping

**Files:**
- Modify: `internal/platform/darwin/platform.go:4,87-123`
- Modify: `internal/platform/darwin/platform_test.go`

**Context:** The `detectCapabilities()` switch statement maps tiers to platform capabilities. With only 3 tiers, the switch simplifies. The doc comment references FUSE-T and must be updated.

- [ ] **Step 1: Update the doc comment**

In `internal/platform/darwin/platform.go`, line 4:

```go
// Before:
// It uses FUSE-T for filesystem interception and pf for network redirection.

// After:
// It uses the Endpoint Security Framework (via system extension) for file/process
// monitoring and pf or Network Extension for network interception.
```

- [ ] **Step 2: Update the detectCapabilities() initial caps and switch**

In `detectCapabilities()`, update the initial capabilities struct (lines 81–84) to derive `HasEndpointSecurity` and `HasNetworkExtension` from `HasSystemExtension`:
```go
		// macOS-specific frameworks (provided by system extension)
		HasEndpointSecurity: p.permissions.HasSystemExtension,
		HasNetworkExtension: p.permissions.HasSystemExtension,
```

Then replace the switch statement (lines 87–123):

```go
	switch tier {
	case TierEnterprise:
		caps.HasFUSE = true
		caps.FUSEImplementation = "endpoint-security"
		caps.HasNetworkIntercept = true
		caps.NetworkImplementation = "network-extension"
		caps.CanRedirectTraffic = true
		caps.CanInspectTLS = true

	case TierStandard:
		caps.HasFUSE = false
		caps.FUSEImplementation = "fsevents-observe"
		caps.HasNetworkIntercept = true
		caps.NetworkImplementation = "pf"
		caps.CanRedirectTraffic = true
		caps.CanInspectTLS = true

	case TierMinimal:
		caps.HasFUSE = false
		caps.HasNetworkIntercept = false
	}
```

- [ ] **Step 3: Update platform_test.go**

Update `TestPlatform_detectCapabilities_ByTier` to test 3 tiers instead of 5. Verify:
- Enterprise: `HasFUSE=true, FUSEImplementation="endpoint-security"`
- Standard: `HasFUSE=false, HasNetworkIntercept=true`
- Minimal: `HasFUSE=false, HasNetworkIntercept=false`

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/ -run TestPlatform -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/platform.go internal/platform/darwin/platform_test.go
git commit -m "feat(darwin): update capability mapping for 3-tier model with ESF"
```

---

### Task 5: Update Capability Detection and Mode Selection

**Files:**
- Modify: `internal/capabilities/detect_darwin.go:10-78,80-116,118-133,152-173`
- Modify: `internal/capabilities/detect_darwin_test.go`

**Context:** Remove `fuse_t` from capability detection, replace `checkESF()` with `checkSysExtInstalled()`, and simplify mode selection to remove FUSE-T modes.

- [ ] **Step 1: Replace checkFuseT() with checkSysExtInstalled()**

In `internal/capabilities/detect_darwin.go`, delete `checkFuseT()` (lines 118–127) and replace `checkESF()` (lines 129–133).

Reuse the `checkSysExtInstalled()` function from `internal/platform/darwin/permissions.go` (added in Task 3). Import it via the `darwin` package:

```go
import "github.com/agentsh/agentsh/internal/platform/darwin"
```

If the `darwin` package's `checkSysExtInstalled()` is unexported (lowercase), either export it as `CheckSysExtInstalled()` or duplicate it here. The preferred approach is to export it from `permissions.go` and call `darwin.CheckSysExtInstalled()` here. Update the function name in Task 3 accordingly (capitalize the `C`).

- [ ] **Step 2: Update Detect() caps map**

In `Detect()` (line 82–88), replace:

```go
	caps := map[string]any{
		"sandbox_exec":      true,
		"esf":               checkSysExtInstalled(),
		"network_extension": checkNetworkExtension(),
		"lima_available":    checkLima(),
	}
```

Remove the `"fuse_t"` entry entirely.

- [ ] **Step 3: Update buildDarwinDomains()**

In `buildDarwinDomains()` (lines 10–78):

Remove line 11 (`fuseT, _ := caps["fuse_t"].(bool)`) and lines 16–19 (fuseDetail variable).

Update the File Protection domain (lines 26–31) to remove the `fuse-t` backend:

```go
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "esf", Available: esf, Detail: "", Description: "Endpoint Security Framework", CheckMethod: "sysext"},
			},
		},
```

- [ ] **Step 4: Update selectDarwinMode()**

Replace `selectDarwinMode()` (lines 152–173):

```go
func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}

	hasMacwrap := checkMacwrap()
	if hasMacwrap {
		return "dynamic-seatbelt", 65
	}
	return "sandbox-exec", 60
}
```

- [ ] **Step 5: Update detect_darwin_test.go**

In `internal/capabilities/detect_darwin_test.go`:

Update `TestSelectDarwinMode` test cases — remove `"fuse_t"` from all caps maps and remove test cases for `"dynamic-seatbelt-fuse"` and `"fuse-t"` modes:

```go
func TestSelectDarwinMode(t *testing.T) {
	hasMacwrap := checkMacwrap()

	tests := []struct {
		name         string
		caps         map[string]any
		wantMode     string
		wantScore    int
		needsMacwrap bool
	}{
		{"esf wins", map[string]any{"esf": true, "lima_available": true}, "esf", 90, false},
		{"lima second", map[string]any{"esf": false, "lima_available": true}, "lima", 85, false},
		{"dynamic seatbelt", map[string]any{"esf": false, "lima_available": false}, "dynamic-seatbelt", 65, true},
		{"sandbox-exec fallback", map[string]any{"esf": false, "lima_available": false}, "sandbox-exec", 60, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.needsMacwrap && !hasMacwrap {
				t.Skip("agentsh-macwrap not in PATH")
			}
			if !tt.needsMacwrap && hasMacwrap {
				if tt.wantMode == "sandbox-exec" {
					t.Skip("macwrap is in PATH, this tests the no-macwrap path")
				}
			}
			mode, score := selectDarwinMode(tt.caps)
			if mode != tt.wantMode {
				t.Errorf("selectDarwinMode() mode = %q, want %q", mode, tt.wantMode)
			}
			if score != tt.wantScore {
				t.Errorf("selectDarwinMode() score = %d, want %d", score, tt.wantScore)
			}
		})
	}
}
```

Update `TestDetect_Darwin` — replace `"fuse_t"` with `"esf"` in the expected keys:

```go
	expectedKeys := []string{"sandbox_exec", "esf", "network_extension"}
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/capabilities/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/capabilities/detect_darwin.go internal/capabilities/detect_darwin_test.go
git commit -m "feat(darwin): remove fuse_t from capability detection, add sysext check"
```

---

### Task 6: Remove FUSE-T from Tips

**Files:**
- Modify: `internal/capabilities/tips.go:54-60,153`

**Context:** Remove the FUSE-T tip from the darwin tips array and the tipsByBackend map. Linux/Windows tips are unaffected.

- [ ] **Step 1: Remove fuse_t from darwinTips**

In `internal/capabilities/tips.go`, remove the first entry from `darwinTips` (lines 55–60):

```go
// Remove this entry:
{
    Feature:  "fuse_t",
    CheckKey: "fuse_t",
    Impact:   "File policy enforcement limited to observation-only",
    Action:   "Install FUSE-T: brew install fuse-t",
},
```

Update the `esf` tip's action text to reference sysext installation instead:

```go
{
    Feature:  "esf",
    CheckKey: "esf",
    Impact:   "Using sandbox-exec instead of Endpoint Security",
    Action:   "Install the agentsh macOS app bundle which includes the system extension.",
},
```

- [ ] **Step 2: Remove fuse-t from tipsByBackend**

Remove line 153:
```go
// Remove:
"fuse-t": {Feature: "fuse-t", Impact: "Filesystem interception unavailable", Action: "Install FUSE-T: brew install fuse-t"},
```

Update the `"esf"` entry to reference sysext:
```go
"esf": {Feature: "esf", Impact: "Endpoint Security Framework unavailable", Action: "Install the agentsh macOS app bundle with system extension"},
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/capabilities/ -v`
Expected: PASS

- [ ] **Step 4: Verify full build**

Run: `go build ./...`
Expected: Builds without error

Run: `GOOS=windows go build ./...`
Expected: Builds without error (Windows tips unaffected)

- [ ] **Step 5: Commit**

```bash
git add internal/capabilities/tips.go
git commit -m "feat(darwin): remove FUSE-T from tips, update ESF tip to reference sysext"
```

---

### Task 7: Rename XPC Package to policysock

**Files:**
- Move: all 14 files from `internal/platform/darwin/xpc/` → `internal/platform/darwin/policysock/`
- Modify: `internal/platform/darwin/es_exec.go:14` (import path)
- Modify: `internal/platform/darwin/es_exec_test.go:10` (import path)
- Modify: `internal/platform/darwin/es_exec_integration_test.go:14` (import path)

**Context:** The "xpc" package is a misnomer — Go can't speak Apple's XPC. It's already a Unix socket server with JSON protocol. Renaming to "policysock" reflects its actual purpose. Do NOT rename references to Apple's XPC services in `internal/api/xpc_darwin.go` — those are unrelated.

- [ ] **Step 1: Move files using git mv to preserve history**

```bash
git mv internal/platform/darwin/xpc internal/platform/darwin/policysock
```

- [ ] **Step 2: Update package declaration in all moved files**

In every `.go` file in `internal/platform/darwin/policysock/`, change:

```go
// Before:
package xpc

// After:
package policysock
```

Files to update: `server.go`, `server_test.go`, `protocol.go`, `protocol_test.go`, `handler.go`, `handler_test.go`, `sessions.go`, `sessions_test.go`, `snapshot.go`, `snapshot_test.go`, `version.go`, `version_test.go`, `event_handler_test.go`, `integration_test.go`

- [ ] **Step 3: Update internal import paths within the package**

In `sessions.go` and `sessions_test.go`, if they import the xpc package path, update to:
```go
"github.com/agentsh/agentsh/internal/platform/darwin/policysock"
```

- [ ] **Step 4: Update XPC-specific strings**

In `server.go`:
- Line 13 comment: `"XPC bridge"` → `"policy socket bridge"`
- Line 118 panic: `"xpc: handler must not be nil"` → `"policysock: handler must not be nil"`

In `handler.go`:
- Any slog prefix `"xpc:"` → `"policysock:"`

- [ ] **Step 5: Update external import paths**

In `internal/platform/darwin/es_exec.go`, update the import (line 14):
```go
// Before:
"github.com/agentsh/agentsh/internal/platform/darwin/xpc"

// After:
"github.com/agentsh/agentsh/internal/platform/darwin/policysock"
```

Update all references from `xpc.` to `policysock.` in the file body.

Repeat for `es_exec_test.go` and `es_exec_integration_test.go`.

- [ ] **Step 6: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -v`
Expected: PASS

Run: `go test ./internal/platform/darwin/ -v`
Expected: PASS (es_exec tests use the new import)

- [ ] **Step 7: Verify full build**

Run: `go build ./...`
Expected: Builds without error. No remaining references to the old import path.

- [ ] **Step 8: Commit**

```bash
git add -A internal/platform/darwin/policysock/ internal/platform/darwin/es_exec.go internal/platform/darwin/es_exec_test.go internal/platform/darwin/es_exec_integration_test.go
git commit -m "refactor(darwin): rename xpc package to policysock"
```

---

### Task 8: Add Policy Socket Peer Authentication

**Files:**
- Create: `internal/platform/darwin/policysock/auth.go`
- Create: `internal/platform/darwin/policysock/auth_test.go`
- Modify: `internal/platform/darwin/policysock/server.go` (Accept loop, ~line 229)

**Context:** Three-layer authentication: file permissions (root:wheel 0600), peer UID check via `getpeereid()`, and code signing validation via `LOCAL_PEERPID` + `codesign`. Applied on every accepted connection.

- [ ] **Step 1: Write the auth_test.go tests**

Create `internal/platform/darwin/policysock/auth_test.go`:

```go
//go:build darwin

package policysock

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCodeSignature_InvalidPath(t *testing.T) {
	err := validateCodeSignature("/nonexistent/binary", "WCKWMMKJ35")
	assert.Error(t, err, "should fail for nonexistent binary")
}

func TestValidateCodeSignature_UnsignedBinary(t *testing.T) {
	// /usr/bin/true is Apple-signed, not our team ID
	err := validateCodeSignature("/usr/bin/true", "WCKWMMKJ35")
	assert.Error(t, err, "should fail for binary signed by different team")
}

func TestResolvePIDPath_Self(t *testing.T) {
	// Our own process should resolve
	path, err := resolvePIDPath(int32(os.Getpid()))
	assert.NoError(t, err)
	assert.NotEmpty(t, path)
}

func TestResolvePIDPath_InvalidPID(t *testing.T) {
	_, err := resolvePIDPath(-1)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/policysock/ -run TestValidateCodeSignature -v`
Expected: FAIL (functions not defined)

- [ ] **Step 3: Implement auth.go**

Create `internal/platform/darwin/policysock/auth.go`:

```go
//go:build darwin

package policysock

import (
	"fmt"
	"net"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

// ValidatePeer checks that a connected Unix socket peer is:
// 1. Running as root (UID 0)
// 2. Signed by the expected team ID
func ValidatePeer(conn *net.UnixConn, teamID string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var peerUID uint32
	var peerPID int32
	var sockErr error

	err = raw.Control(func(fd uintptr) {
		// Layer 2: Peer UID check
		uid, err := getpeereid(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("getpeereid: %w", err)
			return
		}
		peerUID = uid

		// Layer 3: Get peer PID
		pid, err := getPeerPID(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("LOCAL_PEERPID: %w", err)
			return
		}
		peerPID = pid
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if sockErr != nil {
		return sockErr
	}

	// Layer 2: Reject non-root
	if peerUID != 0 {
		return fmt.Errorf("peer UID %d is not root", peerUID)
	}

	// Layer 3: Resolve binary path and validate code signing
	path, err := resolvePIDPath(peerPID)
	if err != nil {
		return fmt.Errorf("resolve pid %d path: %w", peerPID, err)
	}

	if err := validateCodeSignature(path, teamID); err != nil {
		return fmt.Errorf("code signing validation failed for %s (pid %d): %w", path, peerPID, err)
	}

	return nil
}

// LOCAL_PEERPID is the socket option to get the peer's PID on macOS.
const LOCAL_PEERPID = 0x002

// getpeereid returns the effective UID of the peer.
func getpeereid(fd int) (uid uint32, err error) {
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return xucred.Uid, nil
}

// getPeerPID returns the PID of the peer process.
func getPeerPID(fd int) (int32, error) {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return 0, err
	}
	return int32(pid), nil
}

// resolvePIDPath returns the executable path for a given PID.
func resolvePIDPath(pid int32) (string, error) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidpath failed for pid %d", pid)
	}
	return C.GoString(&buf[0]), nil
}

// validateCodeSignature verifies a binary is signed by the expected team ID.
func validateCodeSignature(path string, teamID string) error {
	requirement := fmt.Sprintf(
		`anchor apple generic and certificate leaf[subject.OU] = "%s"`,
		teamID,
	)
	cmd := exec.Command("codesign", "--verify", "-R="+requirement, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign verification failed: %s: %w", string(output), err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -run TestValidateCodeSignature -v`
Expected: PASS

Run: `go test ./internal/platform/darwin/policysock/ -run TestResolvePIDPath -v`
Expected: PASS

- [ ] **Step 5: Wire ValidatePeer into the server Accept loop**

In `internal/platform/darwin/policysock/server.go`, in the accept loop (around line 229). The current code uses `ln.Accept()` which returns `net.Conn`. Change it to `ln.AcceptUnix()` to get `*net.UnixConn` (the listener is already `*net.UnixListener`). Then add validation after the accept:

```go
		// Validate peer identity (UID + code signing)
		if s.teamID != "" {
			if err := ValidatePeer(conn, s.teamID); err != nil {
				s.log.Warn("rejected policy socket connection", "error", err)
				conn.Close()
				continue
			}
		}
```

Add a `teamID` field to the `Server` struct and accept it in `NewServer()`.

- [ ] **Step 6: Update socket permissions**

In `server.go`, change the `os.Chmod(s.sockPath, 0666)` (line 204) to `os.Chmod(s.sockPath, 0600)`:

```go
// Before:
if err := os.Chmod(s.sockPath, 0666); err != nil {

// After:
if err := os.Chmod(s.sockPath, 0600); err != nil {
```

Update the TODO comment above it:
```go
// Policy socket: root-only access (0600). Approval operations have been
// separated to the main HTTP API socket (data/agentsh.sock) which remains
// user-accessible. The ApprovalDialog.app should use the HTTP API instead.
```

**Note:** This permission change means the ApprovalDialog.app can no longer connect to this socket. Approval operations (get pending approvals, submit decisions) should go through the existing HTTP API at `data/agentsh.sock` or `127.0.0.1:18080` instead. The approval dialog already has HTTP capability since it connects to the server. No new approval socket is needed — the HTTP API is the approval channel.

- [ ] **Step 7: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/platform/darwin/policysock/auth.go internal/platform/darwin/policysock/auth_test.go internal/platform/darwin/policysock/server.go
git commit -m "feat(darwin): add policy socket peer authentication (UID + code signing)"
```

---

### Task 9: Add Server-Side Validation to PolicySocketClient.swift

**Files:**
- Modify: `macos/AgentSH/PolicySocketClient.swift`

**Context:** The sysext must validate that the process at the other end of the policy socket is signed by the expected team ID. This prevents a rogue process from squatting on the socket path. Uses native `Security.framework` APIs (no shell-out needed in Swift).

- [ ] **Step 1: Add validateServer() method**

In `macos/AgentSH/PolicySocketClient.swift`, add a method after the `sendSync()` method:

```swift
import Security

/// Validates that the server process at the other end of the socket is signed
/// by the expected team ID.
private func validateServer(fd: Int32) -> Bool {
    // Get peer PID via LOCAL_PEERPID
    var peerPID: pid_t = 0
    var peerPIDLen = socklen_t(MemoryLayout<pid_t>.size)
    let result = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &peerPIDLen)
    guard result == 0, peerPID > 0 else {
        NSLog("PolicySocketClient: Failed to get peer PID")
        return false
    }

    // Create SecCode for the peer process
    let attributes = [kSecGuestAttributePid: peerPID] as CFDictionary
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
    guard status == errSecSuccess, let code = code else {
        NSLog("PolicySocketClient: Failed to get SecCode for pid %d: %d", peerPID, status)
        return false
    }

    // Validate code signing against our team ID
    let requirementStr = "anchor apple generic and certificate leaf[subject.OU] = \"WCKWMMKJ35\""
    var requirement: SecRequirement?
    let reqStatus = SecRequirementCreateWithString(requirementStr as CFString, [], &requirement)
    guard reqStatus == errSecSuccess, let requirement = requirement else {
        NSLog("PolicySocketClient: Failed to create requirement: %d", reqStatus)
        return false
    }

    let checkStatus = SecCodeCheckValidityWithErrors(code, [], requirement, nil)
    if checkStatus != errSecSuccess {
        NSLog("PolicySocketClient: Server code signing validation FAILED for pid %d: %d", peerPID, checkStatus)
        return false
    }

    return true
}
```

- [ ] **Step 2: Call validateServer() after connect**

In the `sendSync()` method, after the `connect()` call succeeds (around line 115), add:

```swift
// Validate the server's code signing
guard validateServer(fd: sockFD) else {
    close(sockFD)
    throw SocketError.connectionFailed
}
```

- [ ] **Step 3: Build the sysext to verify compilation**

Run: `xcodebuild -project macos/AgentSH/agentsh.xcodeproj -scheme SysExt -configuration Release build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO 2>&1 | tail -5`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add macos/AgentSH/PolicySocketClient.swift
git commit -m "feat(sysext): add server-side code signing validation on policy socket"
```

---

### Task 10: Add Proxy Enforcement Wire Format

**Files:**
- Modify: `internal/platform/darwin/policysock/protocol.go`
- Modify: `internal/platform/darwin/policysock/snapshot.go`
- Modify: `internal/platform/darwin/policysock/snapshot_test.go`

**Context:** Add `proxy_addr` and `direct_allow` fields to the session snapshot so the sysext knows which proxy address to enforce for each session.

- [ ] **Step 1: Add DirectAllow type to protocol.go**

In `internal/platform/darwin/policysock/protocol.go`, add after the existing type definitions:

```go
// DirectAllow defines an entry in the proxy bypass allowlist.
// Host can be an IP, hostname, or "*" (any host).
// Port 0 means any port.
type DirectAllow struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}
```

- [ ] **Step 2: Add proxy fields to PolicySnapshotResponse**

In `internal/platform/darwin/policysock/snapshot.go`, add to the `PolicySnapshotResponse` struct:

```go
type PolicySnapshotResponse struct {
	Version      uint64               `json:"version"`
	SessionID    string               `json:"session_id"`
	RootPID      int32                `json:"root_pid"`
	FileRules    []SnapshotFileRule   `json:"file_rules"`
	NetworkRules []SnapshotNetworkRule `json:"network_rules"`
	DNSRules     []SnapshotDNSRule    `json:"dns_rules"`
	ExecRules    []SnapshotExecRule   `json:"exec_rules"`
	Defaults     *SnapshotDefaults    `json:"defaults"`
	ProxyAddr    string               `json:"proxy_addr,omitempty"`
	DirectAllow  []DirectAllow        `json:"direct_allow,omitempty"`
}
```

- [ ] **Step 3: Update snapshot_test.go**

Add a test case that verifies proxy fields serialize/deserialize correctly:

```go
func TestPolicySnapshotResponse_ProxyFields(t *testing.T) {
	snap := PolicySnapshotResponse{
		SessionID: "test-session",
		ProxyAddr: "127.0.0.1:50382",
		DirectAllow: []DirectAllow{
			{Host: "127.0.0.1", Port: 0},
			{Host: "::1", Port: 0},
			{Host: "*", Port: 53},
		},
	}

	data, err := json.Marshal(snap)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"proxy_addr":"127.0.0.1:50382"`)

	var decoded PolicySnapshotResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:50382", decoded.ProxyAddr)
	assert.Len(t, decoded.DirectAllow, 3)
	assert.Equal(t, "*", decoded.DirectAllow[2].Host)
	assert.Equal(t, 53, decoded.DirectAllow[2].Port)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/platform/darwin/policysock/ -run TestPolicySnapshot -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/policysock/protocol.go internal/platform/darwin/policysock/snapshot.go internal/platform/darwin/policysock/snapshot_test.go
git commit -m "feat(policysock): add proxy_addr and direct_allow to session snapshot"
```

---

### Task 11: Add Proxy Enforcement to Sysext

**Files:**
- Modify: `macos/AgentSH/SessionPolicyCache.swift`
- Modify: `macos/AgentSH/FilterDataProvider.swift`

**Context:** Parse `proxy_addr` and `direct_allow` from session snapshots. In the NE content filter, enforce that session PIDs connect through the proxy. Non-session PIDs pass through freely. When `blockingEnabled` is false, audit only (no enforcement).

- [ ] **Step 1: Add proxy fields to SessionPolicyCache**

In `macos/AgentSH/SessionPolicyCache.swift`, add the `DirectAllowEntry` struct and fields to `SessionCache`:

```swift
struct DirectAllowEntry {
    let host: String  // IP, hostname, or "*"
    let port: Int     // 0 = any port
}
```

Add to the `SessionCache` struct (or class):
```swift
var proxyAddr: String?
var directAllow: [DirectAllowEntry] = []
```

- [ ] **Step 2: Parse proxy fields in from(json:)**

In `SessionCache.from(json:sessionID:rootPID:)`, add parsing for the new fields:

```swift
if let proxyAddr = json["proxy_addr"] as? String, !proxyAddr.isEmpty {
    cache.proxyAddr = proxyAddr
}

if let directAllowArr = json["direct_allow"] as? [[String: Any]] {
    cache.directAllow = directAllowArr.compactMap { entry in
        guard let host = entry["host"] as? String else { return nil }
        let port = entry["port"] as? Int ?? 0
        return DirectAllowEntry(host: host, port: port)
    }
}
```

- [ ] **Step 3: Add proxy enforcement helpers to FilterDataProvider**

In `macos/AgentSH/FilterDataProvider.swift`, add helper methods:

```swift
/// Check if an IP address is localhost.
private func isLocalhost(_ ip: String) -> Bool {
    return ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "localhost"
}

/// Check if destination matches a DirectAllowEntry.
private func matchesDirectAllow(ip: String, port: Int, entry: DirectAllowEntry) -> Bool {
    let hostMatch = entry.host == "*" || entry.host == ip
    let portMatch = entry.port == 0 || entry.port == port
    return hostMatch && portMatch
}

/// Check if destination is the session's proxy address.
private func isProxyAddr(_ ip: String, _ port: Int, proxyAddr: String) -> Bool {
    let parts = proxyAddr.split(separator: ":")
    guard parts.count == 2,
          let proxyPort = Int(parts[1]) else { return false }
    return ip == String(parts[0]) && port == proxyPort
}
```

- [ ] **Step 4: Add proxy enforcement logic to handleNewFlow()**

In `FilterDataProvider.handleNewFlow()`, after the session check (around line 89, after `guard let sessionID = ...`) and BEFORE the cache evaluation (line 95), add proxy enforcement:

```swift
// Proxy enforcement: ensure session PIDs connect through the proxy
if blockingEnabled,
   let cache = SessionPolicyCache.shared.cacheForSession(sessionID) {

    // Allow localhost connections
    if isLocalhost(ip) {
        // fall through to normal evaluation
    }
    // Allow connections to the session's proxy
    else if let proxyAddr = cache.proxyAddr, isProxyAddr(ip, port, proxyAddr: proxyAddr) {
        return .allow()
    }
    // Allow direct-connect allowlist entries
    else if cache.directAllow.contains(where: { matchesDirectAllow(ip: ip, port: port, entry: $0) }) {
        return .allow()
    }
    // Block direct external connections (proxy bypass)
    else if cache.proxyAddr != nil {
        NSLog("PROXY_BYPASS_BLOCKED: %@:%d from pid %d (session %@)", ip, port, pid, sessionID)
        PolicySocketClient.shared.send([
            "type": "proxy_bypass_blocked",
            "session_id": sessionID,
            "pid": Int(pid),
            "destination_ip": ip,
            "destination_port": port,
            "destination_host": hostname ?? "",
            "process_name": processInfo.processName ?? "",
            "bundle_id": processInfo.bundleID ?? ""
        ])
        return .drop()
    }
}
```

- [ ] **Step 5: Add cacheForSession() method if not present**

In `SessionPolicyCache.swift`, ensure there's a method to get the cache by session ID:

```swift
func cacheForSession(_ sessionID: String) -> SessionCache? {
    return sessions[sessionID]
}
```

- [ ] **Step 6: Build the sysext**

Run: `xcodebuild -project macos/AgentSH/agentsh.xcodeproj -scheme SysExt -configuration Release build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO 2>&1 | tail -5`
Expected: BUILD SUCCEEDED

- [ ] **Step 7: Commit**

```bash
git add macos/AgentSH/SessionPolicyCache.swift macos/AgentSH/FilterDataProvider.swift
git commit -m "feat(sysext): add NE proxy enforcement for eBPF parity"
```

---

### Task 12: Wire Policy Socket Server into Main Server Startup

**Files:**
- Modify: server startup code (likely `cmd/agentsh/` or `internal/server/`)
- Modify: `internal/config/config.go` (add policy_socket config section)

**Context:** The policysock.Server needs to be started during server init. It should listen on the configured path, push session snapshots when sessions change, and receive events from the sysext. This task requires exploring the server startup code to find the right integration point.

**Note to implementer:** This task requires reading the server startup code to understand how sessions are created and events are stored. The key integration points are:
1. Server init: create and start `policysock.Server`
2. Session lifecycle hooks: push snapshots on create/update/destroy
3. Event ingestion: route incoming sysext events to session event store

- [ ] **Step 1: Add policy_socket config section**

In `internal/config/config.go`, add a new config section:

```go
type PolicySocketConfig struct {
	Path   string `yaml:"path" json:"path"`
	TeamID string `yaml:"team_id" json:"team_id"`
}
```

Add to the main config struct:
```go
PolicySocket PolicySocketConfig `yaml:"policy_socket" json:"policy_socket"`
```

Default values:
```go
PolicySocket: PolicySocketConfig{
    Path:   "/var/run/agentsh/policy.sock",
    TeamID: "WCKWMMKJ35",
},
```

- [ ] **Step 2: Add config to config.yml**

Add to `config.yml`:

```yaml
# =============================================================================
# POLICY SOCKET (macOS System Extension IPC)
# =============================================================================

policy_socket:
  path: "/var/run/agentsh/policy.sock"
  team_id: "WCKWMMKJ35"
```

- [ ] **Step 3: Start policysock.Server in server init**

Find the server startup code and add policysock initialization. The server should:
1. Create `/var/run/agentsh/` directory if it doesn't exist (requires root)
2. Create `policysock.NewServer(cfg.PolicySocket.Path, handler, teamID)`
3. Start listening in a goroutine
4. Shut down on server stop

- [ ] **Step 4: Hook session lifecycle events**

When a session is created/updated/destroyed, push the snapshot to connected sysext clients via `policysock.Server.PushSnapshot()`. Include the session's `proxy_addr` from the proxy listener.

- [ ] **Step 5: Hook event ingestion**

Route incoming events from the sysext (file events, proxy_bypass_blocked, etc.) to the session's event store so they appear in `events query`.

- [ ] **Step 6: Run the server and verify**

```bash
sudo ./agentsh server --config ./config.yml
# In another terminal:
ls -la /var/run/agentsh/policy.sock
# Should show root:wheel 0600
```

- [ ] **Step 7: Run full test suite**

Run: `go test ./... 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go config.yml cmd/agentsh/ internal/server/
git commit -m "feat(server): wire policy socket server into main startup"
```

---

### Task 13: Build, Sign, Install, and Manual E2E Test

**Files:** No code changes. This is a manual verification task.

**Context:** Build the full stack (Go binary + sysext), sign, notarize, install, and run the E2E test sequence from the spec.

- [ ] **Step 1: Build**

```bash
make build-macos-go
# Build sysext
xcodebuild -project macos/AgentSH/agentsh.xcodeproj -scheme SysExt -configuration Release build
```

- [ ] **Step 2: Assemble, sign, notarize**

```bash
make assemble-bundle
make sign-bundle
# Create zip and notarize
ditto -c -k --keepParent build/AgentSH.app build/AgentSH.zip
xcrun notarytool submit build/AgentSH.zip --keychain-profile agentsh --wait
xcrun stapler staple build/AgentSH.app
```

- [ ] **Step 3: Install and enable**

Install the app bundle, approve the system extension in System Settings, enable Full Disk Access.

- [ ] **Step 4: Start server and verify socket**

```bash
sudo ./agentsh server --config ./config.yml
# Check socket exists
ls -la /var/run/agentsh/policy.sock
# Check sysext connects (in server logs)
```

- [ ] **Step 5: Test file I/O via ESF**

```bash
SID=$(./agentsh session create --policy agent-observe --workspace /tmp/test --json | jq -r .id)
./agentsh exec "$SID" -- bash -c 'echo test > /tmp/test/file.txt'
./agentsh exec "$SID" -- cat /tmp/test/file.txt
./agentsh events query "$SID" | python3 -c "
import json, sys
events = json.load(sys.stdin)
file_events = [e for e in events if 'fs_' in e.get('type','')]
print(f'File events: {len(file_events)}')
for e in file_events[:5]:
    print(f'  {e[\"type\"]}: {e.get(\"fields\",{})}')
"
```

Expected: File events (`fs_open`, `fs_close`) appear from ESF.

- [ ] **Step 6: Test file blocking**

Switch to a policy with file deny rules, run a file operation, verify it's blocked.

- [ ] **Step 7: Test network via proxy**

```bash
./agentsh exec "$SID" -- curl -s -o /dev/null -w '%{http_code}' https://example.com
./agentsh events query "$SID" | python3 -c "
import json, sys
events = json.load(sys.stdin)
net_events = [e for e in events if 'net_' in e.get('type','')]
print(f'Network events: {len(net_events)}')
for e in net_events:
    print(f'  {e[\"type\"]}: domain={e.get(\"domain\",\"\")} remote={e.get(\"remote\",\"\")}')
"
```

Expected: `net_connect` and `net_close` events appear.

- [ ] **Step 8: Test proxy bypass blocking**

```bash
./agentsh exec "$SID" -- python3 -c "import urllib.request; urllib.request.urlopen('https://example.com')"
./agentsh events query "$SID" | grep proxy_bypass_blocked
```

Expected: Connection blocked, `proxy_bypass_blocked` event appears.

- [ ] **Step 9: Test exec redirect**

Configure a policy with exec redirect rules, run the command, verify ESF denies original exec.

- [ ] **Step 10: Document results**

Record which tests passed/failed. If any fail, create issues for follow-up.
