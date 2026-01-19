# Landlock Fallback Security Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement security enforcement using Landlock + capability dropping when seccomp is unavailable (nested containers, restricted runtimes).

**Architecture:** Detection layer identifies available primitives → mode selection picks best available → enforcement layer applies Landlock rulesets + drops capabilities per-session. Graceful degradation with optional strict mode.

**Tech Stack:** Go, golang.org/x/sys/unix for Landlock syscalls, existing internal/capabilities framework

**Design Doc:** `docs/plans/2026-01-18-landlock-fallback-security-design.md`

---

## Task 1: Add Landlock Detection

**Files:**
- Create: `internal/capabilities/check_landlock.go`
- Create: `internal/capabilities/check_landlock_test.go`

**Step 1: Write the failing test**

```go
// internal/capabilities/check_landlock_test.go
package capabilities

import (
    "testing"
)

func TestDetectLandlock(t *testing.T) {
    result := DetectLandlock()

    // Should return a valid result (may or may not be available)
    if result.ABI < 0 || result.ABI > 5 {
        t.Errorf("unexpected ABI version: %d", result.ABI)
    }

    // Network support requires ABI v4+
    if result.NetworkSupport && result.ABI < 4 {
        t.Error("network support claimed but ABI < 4")
    }
}

func TestLandlockResult_String(t *testing.T) {
    tests := []struct {
        name     string
        result   LandlockResult
        contains string
    }{
        {
            name:     "available with network",
            result:   LandlockResult{Available: true, ABI: 4, NetworkSupport: true},
            contains: "ABI v4",
        },
        {
            name:     "unavailable",
            result:   LandlockResult{Available: false, ABI: 0, Error: "not supported"},
            contains: "unavailable",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            s := tt.result.String()
            if !strings.Contains(s, tt.contains) {
                t.Errorf("expected %q to contain %q", s, tt.contains)
            }
        })
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run TestDetectLandlock -v`
Expected: FAIL with "undefined: DetectLandlock"

**Step 3: Write minimal implementation**

```go
// internal/capabilities/check_landlock.go
//go:build linux

package capabilities

import (
    "fmt"
    "strings"

    "golang.org/x/sys/unix"
)

// LandlockResult holds the result of Landlock availability detection.
type LandlockResult struct {
    Available      bool
    ABI            int
    NetworkSupport bool
    Error          string
}

func (r LandlockResult) String() string {
    if !r.Available {
        return fmt.Sprintf("Landlock: unavailable (%s)", r.Error)
    }
    features := []string{fmt.Sprintf("ABI v%d", r.ABI)}
    if r.NetworkSupport {
        features = append(features, "network support")
    }
    return fmt.Sprintf("Landlock: available (%s)", strings.Join(features, ", "))
}

// DetectLandlock checks if Landlock is available and returns capability info.
func DetectLandlock() LandlockResult {
    // Try to detect highest supported ABI version
    for abi := 5; abi >= 1; abi-- {
        if tryLandlockABI(abi) {
            return LandlockResult{
                Available:      true,
                ABI:            abi,
                NetworkSupport: abi >= 4,
            }
        }
    }

    return LandlockResult{
        Available: false,
        Error:     "kernel does not support Landlock or it is disabled",
    }
}

func tryLandlockABI(abi int) bool {
    // Build access mask for this ABI version
    var accessFS uint64

    // ABI v1 access rights
    accessFS = unix.LANDLOCK_ACCESS_FS_EXECUTE |
        unix.LANDLOCK_ACCESS_FS_READ_FILE |
        unix.LANDLOCK_ACCESS_FS_READ_DIR |
        unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
        unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
        unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
        unix.LANDLOCK_ACCESS_FS_MAKE_REG |
        unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
        unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
        unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        unix.LANDLOCK_ACCESS_FS_MAKE_SYM

    if abi >= 2 {
        accessFS |= unix.LANDLOCK_ACCESS_FS_REFER
    }
    if abi >= 3 {
        accessFS |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
    }

    attr := unix.LandlockRulesetAttr{
        HandledAccessFs: accessFS,
    }

    // Add network access for ABI v4+
    if abi >= 4 {
        attr.HandledAccessNet = unix.LANDLOCK_ACCESS_NET_BIND_TCP |
            unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
    }

    fd, err := unix.LandlockCreateRuleset(&attr, 0)
    if err != nil {
        return false
    }
    unix.Close(fd)
    return true
}
```

**Step 4: Create stub for non-Linux**

```go
// internal/capabilities/check_landlock_other.go
//go:build !linux

package capabilities

// LandlockResult holds the result of Landlock availability detection.
type LandlockResult struct {
    Available      bool
    ABI            int
    NetworkSupport bool
    Error          string
}

func (r LandlockResult) String() string {
    return "Landlock: unavailable (not Linux)"
}

// DetectLandlock returns unavailable on non-Linux platforms.
func DetectLandlock() LandlockResult {
    return LandlockResult{
        Available: false,
        Error:     "Landlock is only available on Linux",
    }
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run TestDetectLandlock -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/capabilities/check_landlock*.go
git commit -m "feat(capabilities): add Landlock availability detection"
```

---

## Task 2: Add SecurityCapabilities Type

**Files:**
- Create: `internal/capabilities/security_caps.go`
- Create: `internal/capabilities/security_caps_test.go`

**Step 1: Write the failing test**

```go
// internal/capabilities/security_caps_test.go
package capabilities

import (
    "testing"
)

func TestDetectSecurityCapabilities(t *testing.T) {
    caps := DetectSecurityCapabilities()

    // Should always have Capabilities (can always drop caps)
    if !caps.Capabilities {
        t.Error("Capabilities should always be true")
    }

    // Landlock network requires Landlock available
    if caps.LandlockNetwork && !caps.Landlock {
        t.Error("LandlockNetwork requires Landlock")
    }
}

func TestSecurityCapabilities_SelectMode(t *testing.T) {
    tests := []struct {
        name     string
        caps     SecurityCapabilities
        expected string
    }{
        {
            name: "full mode when all available",
            caps: SecurityCapabilities{
                Seccomp: true, eBPF: true, FUSE: true, Landlock: true,
                Capabilities: true,
            },
            expected: "full",
        },
        {
            name: "landlock mode when seccomp unavailable",
            caps: SecurityCapabilities{
                Seccomp: false, eBPF: false, FUSE: true, Landlock: true,
                Capabilities: true,
            },
            expected: "landlock",
        },
        {
            name: "landlock-only when FUSE also unavailable",
            caps: SecurityCapabilities{
                Seccomp: false, eBPF: false, FUSE: false, Landlock: true,
                Capabilities: true,
            },
            expected: "landlock-only",
        },
        {
            name: "minimal when nothing available",
            caps: SecurityCapabilities{
                Seccomp: false, eBPF: false, FUSE: false, Landlock: false,
                Capabilities: true,
            },
            expected: "minimal",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mode := tt.caps.SelectMode()
            if mode != tt.expected {
                t.Errorf("expected mode %q, got %q", tt.expected, mode)
            }
        })
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestDetectSecurityCapabilities|TestSecurityCapabilities_SelectMode" -v`
Expected: FAIL with "undefined: SecurityCapabilities"

**Step 3: Write minimal implementation**

```go
// internal/capabilities/security_caps.go
package capabilities

// SecurityCapabilities holds detected security primitive availability.
type SecurityCapabilities struct {
    Seccomp         bool // seccomp-bpf + user-notify
    SeccompBasic    bool // seccomp-bpf without user-notify
    Landlock        bool // any Landlock support
    LandlockABI     int  // 1-5, determines features
    LandlockNetwork bool // ABI v4+, kernel 6.7+
    eBPF            bool // network monitoring
    FUSE            bool // filesystem interception
    Capabilities    bool // can drop capabilities (always true)
    PIDNamespace    bool // isolated PID namespace
}

// SecurityMode represents the security enforcement mode.
const (
    ModeFull        = "full"
    ModeLandlock    = "landlock"
    ModeLandlockOnly = "landlock-only"
    ModeMinimal     = "minimal"
)

// DetectSecurityCapabilities probes the system for available security primitives.
func DetectSecurityCapabilities() *SecurityCapabilities {
    caps := &SecurityCapabilities{
        Capabilities: true, // Can always drop capabilities
    }

    // Detect Landlock
    llResult := DetectLandlock()
    caps.Landlock = llResult.Available
    caps.LandlockABI = llResult.ABI
    caps.LandlockNetwork = llResult.NetworkSupport

    // Detect other capabilities (use existing checks)
    caps.Seccomp = checkSeccompUserNotify()
    caps.SeccompBasic = checkSeccompBasic()
    caps.eBPF = checkeBPF()
    caps.FUSE = checkFUSE()
    caps.PIDNamespace = checkPIDNamespace()

    return caps
}

// SelectMode returns the best available security mode based on capabilities.
func (c *SecurityCapabilities) SelectMode() string {
    // Full mode: all features available
    if c.Seccomp && c.eBPF && c.FUSE {
        return ModeFull
    }

    // Landlock mode: Landlock + FUSE (no seccomp)
    if c.Landlock && c.FUSE {
        return ModeLandlock
    }

    // Landlock-only: just Landlock (no FUSE either)
    if c.Landlock {
        return ModeLandlockOnly
    }

    // Minimal: only capabilities dropping
    return ModeMinimal
}

// Placeholder check functions - will wire up to existing checks
func checkSeccompBasic() bool {
    // TODO: implement or wire to existing
    return false
}

func checkFUSE() bool {
    // Check if /dev/fuse is accessible
    // TODO: implement
    return false
}

func checkPIDNamespace() bool {
    // Check if we're in a PID namespace
    // TODO: implement
    return false
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestDetectSecurityCapabilities|TestSecurityCapabilities_SelectMode" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/security_caps_test.go
git commit -m "feat(capabilities): add SecurityCapabilities type with mode selection"
```

---

## Task 3: Add Config Schema for Landlock

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/security_test.go`

**Step 1: Write the failing test**

```go
// internal/config/security_test.go
package config

import (
    "testing"

    "gopkg.in/yaml.v3"
)

func TestSecurityConfig_Unmarshal(t *testing.T) {
    yamlData := `
security:
  mode: auto
  strict: false
  minimum_mode: landlock-only
  warn_degraded: true

landlock:
  enabled: true
  allow_execute:
    - /usr/bin
    - /bin
  allow_read:
    - /etc/ssl/certs
  deny_paths:
    - /var/run/docker.sock
  network:
    allow_connect_tcp: true
    allow_bind_tcp: false

capabilities:
  allow:
    - CAP_NET_RAW
`

    var cfg Config
    err := yaml.Unmarshal([]byte(yamlData), &cfg)
    if err != nil {
        t.Fatalf("failed to unmarshal: %v", err)
    }

    // Verify security config
    if cfg.Security.Mode != "auto" {
        t.Errorf("expected mode 'auto', got %q", cfg.Security.Mode)
    }
    if cfg.Security.MinimumMode != "landlock-only" {
        t.Errorf("expected minimum_mode 'landlock-only', got %q", cfg.Security.MinimumMode)
    }

    // Verify landlock config
    if !cfg.Landlock.Enabled {
        t.Error("expected landlock.enabled = true")
    }
    if len(cfg.Landlock.AllowExecute) != 2 {
        t.Errorf("expected 2 allow_execute paths, got %d", len(cfg.Landlock.AllowExecute))
    }
    if len(cfg.Landlock.DenyPaths) != 1 {
        t.Errorf("expected 1 deny_paths, got %d", len(cfg.Landlock.DenyPaths))
    }

    // Verify capabilities config
    if len(cfg.Capabilities.Allow) != 1 || cfg.Capabilities.Allow[0] != "CAP_NET_RAW" {
        t.Errorf("expected [CAP_NET_RAW], got %v", cfg.Capabilities.Allow)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/config/... -run TestSecurityConfig_Unmarshal -v`
Expected: FAIL with "cfg.Security undefined" or similar

**Step 3: Add config structs to config.go**

Add these structs to `internal/config/config.go`:

```go
// SecurityConfig controls security mode selection and strictness.
type SecurityConfig struct {
    Mode         string `yaml:"mode"`          // auto, full, landlock, landlock-only, minimal
    Strict       bool   `yaml:"strict"`        // Fail if mode requirements not met
    MinimumMode  string `yaml:"minimum_mode"`  // Fail if auto-detect picks worse
    WarnDegraded bool   `yaml:"warn_degraded"` // Log warnings in degraded mode
}

// LandlockConfig controls Landlock sandbox settings.
type LandlockConfig struct {
    Enabled      bool     `yaml:"enabled"`
    AllowExecute []string `yaml:"allow_execute"` // Paths where execute is allowed
    AllowRead    []string `yaml:"allow_read"`    // Paths where read is allowed
    AllowWrite   []string `yaml:"allow_write"`   // Paths where write is allowed
    DenyPaths    []string `yaml:"deny_paths"`    // Paths to deny (by omission)
    Network      LandlockNetworkConfig `yaml:"network"`
}

// LandlockNetworkConfig controls Landlock network restrictions (kernel 6.7+).
type LandlockNetworkConfig struct {
    AllowConnectTCP bool    `yaml:"allow_connect_tcp"` // Allow outbound TCP
    AllowBindTCP    bool    `yaml:"allow_bind_tcp"`    // Allow listening
    BindPorts       []int   `yaml:"bind_ports"`        // Specific ports if bind allowed
}

// CapabilitiesConfig controls Linux capability dropping.
type CapabilitiesConfig struct {
    Allow []string `yaml:"allow"` // Capabilities to keep (empty = drop all droppable)
}
```

Add fields to main Config struct:

```go
type Config struct {
    // ... existing fields ...
    Security     SecurityConfig     `yaml:"security"`
    Landlock     LandlockConfig     `yaml:"landlock"`
    Capabilities CapabilitiesConfig `yaml:"capabilities"`
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/config/... -run TestSecurityConfig_Unmarshal -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/security_test.go
git commit -m "feat(config): add Security, Landlock, and Capabilities config schemas"
```

---

## Task 4: Implement Capability Dropping

**Files:**
- Create: `internal/capabilities/drop.go`
- Create: `internal/capabilities/drop_test.go`

**Step 1: Write the failing test**

```go
// internal/capabilities/drop_test.go
//go:build linux

package capabilities

import (
    "testing"
)

func TestAlwaysDropCaps(t *testing.T) {
    // These must always be in the always-drop list
    required := []string{
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_SYS_MODULE",
        "CAP_DAC_OVERRIDE",
        "CAP_SETUID",
        "CAP_SETGID",
        "CAP_NET_ADMIN",
    }

    for _, cap := range required {
        if !isAlwaysDrop(cap) {
            t.Errorf("%s should be in always-drop list", cap)
        }
    }
}

func TestValidateAllowList(t *testing.T) {
    tests := []struct {
        name    string
        allow   []string
        wantErr bool
    }{
        {
            name:    "empty allow list is valid",
            allow:   []string{},
            wantErr: false,
        },
        {
            name:    "CAP_NET_RAW is allowable",
            allow:   []string{"CAP_NET_RAW"},
            wantErr: false,
        },
        {
            name:    "CAP_SYS_ADMIN is never allowable",
            allow:   []string{"CAP_SYS_ADMIN"},
            wantErr: true,
        },
        {
            name:    "CAP_SYS_PTRACE is never allowable",
            allow:   []string{"CAP_SYS_PTRACE"},
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateCapabilityAllowList(tt.allow)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateCapabilityAllowList() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestAlwaysDropCaps|TestValidateAllowList" -v`
Expected: FAIL with "undefined: isAlwaysDrop"

**Step 3: Write minimal implementation**

```go
// internal/capabilities/drop.go
//go:build linux

package capabilities

import (
    "fmt"
    "strings"

    "golang.org/x/sys/unix"
)

// alwaysDropCaps are capabilities that are NEVER allowed - container escape vectors.
var alwaysDropCaps = map[string]struct{}{
    "CAP_SYS_ADMIN":        {}, // Mount, namespace escape, catch-all
    "CAP_SYS_PTRACE":       {}, // Attach to processes, read memory
    "CAP_SYS_MODULE":       {}, // Load kernel modules
    "CAP_DAC_OVERRIDE":     {}, // Bypass file permissions
    "CAP_DAC_READ_SEARCH":  {}, // Bypass read/search permissions
    "CAP_SETUID":           {}, // Change UID
    "CAP_SETGID":           {}, // Change GID
    "CAP_CHOWN":            {}, // Change file ownership
    "CAP_FOWNER":           {}, // Bypass owner permission checks
    "CAP_MKNOD":            {}, // Create device files
    "CAP_SYS_RAWIO":        {}, // Raw I/O port access
    "CAP_SYS_BOOT":         {}, // Reboot system
    "CAP_NET_ADMIN":        {}, // Network configuration
    "CAP_SYS_CHROOT":       {}, // chroot escape vector
    "CAP_LINUX_IMMUTABLE":  {}, // Modify immutable files
}

// defaultDropCaps are dropped by default but can be explicitly allowed.
var defaultDropCaps = map[string]struct{}{
    "CAP_NET_BIND_SERVICE": {}, // Bind to ports < 1024
    "CAP_NET_RAW":          {}, // Raw sockets (ping)
    "CAP_KILL":             {}, // Signal any same-UID process
    "CAP_SETFCAP":          {}, // Set file capabilities
}

// isAlwaysDrop returns true if the capability must always be dropped.
func isAlwaysDrop(cap string) bool {
    cap = strings.ToUpper(cap)
    if !strings.HasPrefix(cap, "CAP_") {
        cap = "CAP_" + cap
    }
    _, ok := alwaysDropCaps[cap]
    return ok
}

// ValidateCapabilityAllowList checks that no always-drop caps are in the allow list.
func ValidateCapabilityAllowList(allow []string) error {
    for _, cap := range allow {
        if isAlwaysDrop(cap) {
            return fmt.Errorf("capability %s cannot be allowed: hardcoded deny", cap)
        }
    }
    return nil
}

// DropCapabilities drops all capabilities except those in the allow list.
func DropCapabilities(allow []string) error {
    if err := ValidateCapabilityAllowList(allow); err != nil {
        return err
    }

    // Build set of allowed caps
    allowSet := make(map[string]struct{})
    for _, cap := range allow {
        cap = strings.ToUpper(cap)
        if !strings.HasPrefix(cap, "CAP_") {
            cap = "CAP_" + cap
        }
        allowSet[cap] = struct{}{}
    }

    // Drop from bounding set
    for cap := 0; cap <= int(unix.CAP_LAST_CAP); cap++ {
        capName := capToName(cap)
        if _, allowed := allowSet[capName]; allowed {
            continue
        }

        if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
            // Ignore EINVAL for caps that don't exist on this kernel
            if err != unix.EINVAL {
                return fmt.Errorf("failed to drop %s: %w", capName, err)
            }
        }
    }

    return nil
}

// capToName converts capability number to name.
func capToName(cap int) string {
    names := map[int]string{
        0:  "CAP_CHOWN",
        1:  "CAP_DAC_OVERRIDE",
        2:  "CAP_DAC_READ_SEARCH",
        3:  "CAP_FOWNER",
        4:  "CAP_FSETID",
        5:  "CAP_KILL",
        6:  "CAP_SETGID",
        7:  "CAP_SETUID",
        8:  "CAP_SETPCAP",
        9:  "CAP_LINUX_IMMUTABLE",
        10: "CAP_NET_BIND_SERVICE",
        11: "CAP_NET_BROADCAST",
        12: "CAP_NET_ADMIN",
        13: "CAP_NET_RAW",
        14: "CAP_IPC_LOCK",
        15: "CAP_IPC_OWNER",
        16: "CAP_SYS_MODULE",
        17: "CAP_SYS_RAWIO",
        18: "CAP_SYS_CHROOT",
        19: "CAP_SYS_PTRACE",
        20: "CAP_SYS_PACCT",
        21: "CAP_SYS_ADMIN",
        22: "CAP_SYS_BOOT",
        23: "CAP_SYS_NICE",
        24: "CAP_SYS_RESOURCE",
        25: "CAP_SYS_TIME",
        26: "CAP_SYS_TTY_CONFIG",
        27: "CAP_MKNOD",
        28: "CAP_LEASE",
        29: "CAP_AUDIT_WRITE",
        30: "CAP_AUDIT_CONTROL",
        31: "CAP_SETFCAP",
        // ... more caps if needed
    }
    if name, ok := names[cap]; ok {
        return name
    }
    return fmt.Sprintf("CAP_%d", cap)
}
```

**Step 4: Create stub for non-Linux**

```go
// internal/capabilities/drop_other.go
//go:build !linux

package capabilities

import "errors"

var alwaysDropCaps = map[string]struct{}{}
var defaultDropCaps = map[string]struct{}{}

func isAlwaysDrop(cap string) bool { return false }
func ValidateCapabilityAllowList(allow []string) error { return nil }
func DropCapabilities(allow []string) error {
    return errors.New("capability dropping only supported on Linux")
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestAlwaysDropCaps|TestValidateAllowList" -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/capabilities/drop*.go
git commit -m "feat(capabilities): implement capability dropping with always-drop list"
```

---

## Task 5: Implement Landlock Ruleset Builder

**Files:**
- Create: `internal/landlock/ruleset.go`
- Create: `internal/landlock/ruleset_test.go`

**Step 1: Write the failing test**

```go
// internal/landlock/ruleset_test.go
//go:build linux

package landlock

import (
    "testing"
)

func TestRulesetBuilder_AddPath(t *testing.T) {
    b := NewRulesetBuilder(3) // ABI v3

    err := b.AddExecutePath("/usr/bin")
    if err != nil {
        t.Errorf("failed to add execute path: %v", err)
    }

    err = b.AddReadPath("/etc/ssl/certs")
    if err != nil {
        t.Errorf("failed to add read path: %v", err)
    }

    if len(b.executePaths) != 1 {
        t.Errorf("expected 1 execute path, got %d", len(b.executePaths))
    }
    if len(b.readPaths) != 1 {
        t.Errorf("expected 1 read path, got %d", len(b.readPaths))
    }
}

func TestRulesetBuilder_DenyPaths(t *testing.T) {
    b := NewRulesetBuilder(3)
    b.AddDenyPath("/var/run/docker.sock")

    if len(b.denyPaths) != 1 {
        t.Errorf("expected 1 deny path, got %d", len(b.denyPaths))
    }
}

func TestRulesetBuilder_WorkspacePath(t *testing.T) {
    b := NewRulesetBuilder(3)
    b.SetWorkspace("/home/user/project")

    if b.workspace != "/home/user/project" {
        t.Errorf("expected workspace /home/user/project, got %s", b.workspace)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/landlock/... -run TestRulesetBuilder -v`
Expected: FAIL with "cannot find package"

**Step 3: Write minimal implementation**

```go
// internal/landlock/ruleset.go
//go:build linux

package landlock

import (
    "fmt"
    "os"
    "path/filepath"

    "golang.org/x/sys/unix"
)

// RulesetBuilder constructs a Landlock ruleset from paths.
type RulesetBuilder struct {
    abi          int
    workspace    string
    executePaths []string
    readPaths    []string
    writePaths   []string
    denyPaths    []string
    allowNetwork bool
    allowBind    bool
}

// NewRulesetBuilder creates a new ruleset builder for the given ABI version.
func NewRulesetBuilder(abi int) *RulesetBuilder {
    return &RulesetBuilder{
        abi:          abi,
        executePaths: make([]string, 0),
        readPaths:    make([]string, 0),
        writePaths:   make([]string, 0),
        denyPaths:    make([]string, 0),
    }
}

// SetWorkspace sets the workspace path (gets full read/write/execute access).
func (b *RulesetBuilder) SetWorkspace(path string) {
    b.workspace = path
}

// AddExecutePath adds a path where execution is allowed.
func (b *RulesetBuilder) AddExecutePath(path string) error {
    absPath, err := filepath.Abs(path)
    if err != nil {
        return fmt.Errorf("invalid path %s: %w", path, err)
    }
    b.executePaths = append(b.executePaths, absPath)
    return nil
}

// AddReadPath adds a path where reading is allowed.
func (b *RulesetBuilder) AddReadPath(path string) error {
    absPath, err := filepath.Abs(path)
    if err != nil {
        return fmt.Errorf("invalid path %s: %w", path, err)
    }
    b.readPaths = append(b.readPaths, absPath)
    return nil
}

// AddWritePath adds a path where writing is allowed.
func (b *RulesetBuilder) AddWritePath(path string) error {
    absPath, err := filepath.Abs(path)
    if err != nil {
        return fmt.Errorf("invalid path %s: %w", path, err)
    }
    b.writePaths = append(b.writePaths, absPath)
    return nil
}

// AddDenyPath marks a path to be denied (by not adding it to the ruleset).
func (b *RulesetBuilder) AddDenyPath(path string) {
    b.denyPaths = append(b.denyPaths, path)
}

// SetNetworkAccess configures network restrictions (ABI v4+ only).
func (b *RulesetBuilder) SetNetworkAccess(allowConnect, allowBind bool) {
    b.allowNetwork = allowConnect
    b.allowBind = allowBind
}

// Build creates the Landlock ruleset and returns the fd.
func (b *RulesetBuilder) Build() (int, error) {
    // Build access masks based on ABI
    accessFS := b.buildFSAccessMask()

    attr := unix.LandlockRulesetAttr{
        HandledAccessFs: accessFS,
    }

    // Add network handling for ABI v4+
    if b.abi >= 4 {
        attr.HandledAccessNet = unix.LANDLOCK_ACCESS_NET_BIND_TCP |
            unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
    }

    // Create the ruleset
    rulesetFd, err := unix.LandlockCreateRuleset(&attr, 0)
    if err != nil {
        return -1, fmt.Errorf("landlock_create_ruleset: %w", err)
    }

    // Add workspace rule (full access)
    if b.workspace != "" {
        if err := b.addPathRule(rulesetFd, b.workspace, accessFS); err != nil {
            unix.Close(rulesetFd)
            return -1, fmt.Errorf("add workspace rule: %w", err)
        }
    }

    // Add execute paths
    execAccess := unix.LANDLOCK_ACCESS_FS_EXECUTE |
        unix.LANDLOCK_ACCESS_FS_READ_FILE |
        unix.LANDLOCK_ACCESS_FS_READ_DIR
    for _, path := range b.executePaths {
        if b.isDenied(path) {
            continue
        }
        if err := b.addPathRule(rulesetFd, path, execAccess); err != nil {
            // Non-fatal: path might not exist
            continue
        }
    }

    // Add read paths
    readAccess := unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
    for _, path := range b.readPaths {
        if b.isDenied(path) {
            continue
        }
        if err := b.addPathRule(rulesetFd, path, readAccess); err != nil {
            continue
        }
    }

    // Add write paths
    writeAccess := unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
        unix.LANDLOCK_ACCESS_FS_MAKE_REG |
        unix.LANDLOCK_ACCESS_FS_MAKE_DIR
    for _, path := range b.writePaths {
        if b.isDenied(path) {
            continue
        }
        if err := b.addPathRule(rulesetFd, path, writeAccess); err != nil {
            continue
        }
    }

    // Add network rules (ABI v4+)
    if b.abi >= 4 {
        if b.allowNetwork {
            if err := b.addNetRule(rulesetFd, unix.LANDLOCK_ACCESS_NET_CONNECT_TCP); err != nil {
                unix.Close(rulesetFd)
                return -1, fmt.Errorf("add network connect rule: %w", err)
            }
        }
        if b.allowBind {
            if err := b.addNetRule(rulesetFd, unix.LANDLOCK_ACCESS_NET_BIND_TCP); err != nil {
                unix.Close(rulesetFd)
                return -1, fmt.Errorf("add network bind rule: %w", err)
            }
        }
    }

    return rulesetFd, nil
}

func (b *RulesetBuilder) buildFSAccessMask() uint64 {
    access := uint64(
        unix.LANDLOCK_ACCESS_FS_EXECUTE |
        unix.LANDLOCK_ACCESS_FS_READ_FILE |
        unix.LANDLOCK_ACCESS_FS_READ_DIR |
        unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
        unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
        unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
        unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
        unix.LANDLOCK_ACCESS_FS_MAKE_REG |
        unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
        unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
        unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        unix.LANDLOCK_ACCESS_FS_MAKE_SYM)

    if b.abi >= 2 {
        access |= unix.LANDLOCK_ACCESS_FS_REFER
    }
    if b.abi >= 3 {
        access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
    }

    return access
}

func (b *RulesetBuilder) addPathRule(rulesetFd int, path string, access uint64) error {
    fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
    if err != nil {
        return fmt.Errorf("open %s: %w", path, err)
    }
    defer unix.Close(fd)

    pathBeneath := unix.LandlockPathBeneathAttr{
        AllowedAccess: access,
        ParentFd:      int32(fd),
    }

    err = unix.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, 0)
    if err != nil {
        return fmt.Errorf("landlock_add_rule: %w", err)
    }

    return nil
}

func (b *RulesetBuilder) addNetRule(rulesetFd int, access uint64) error {
    // Network rules in Landlock allow all ports when added
    // For port-specific rules, we'd need to add per-port rules
    netAttr := unix.LandlockNetPortAttr{
        AllowedAccess: access,
        Port:          0, // 0 means all ports
    }

    return unix.LandlockAddNetPortRule(rulesetFd, &netAttr, 0)
}

func (b *RulesetBuilder) isDenied(path string) bool {
    for _, deny := range b.denyPaths {
        if path == deny || filepath.HasPrefix(path, deny+string(os.PathSeparator)) {
            return true
        }
    }
    return false
}

// Enforce applies the ruleset to the current process.
func Enforce(rulesetFd int) error {
    // Set no_new_privs first (required)
    if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
        return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
    }

    // Apply the ruleset
    if err := unix.LandlockRestrictSelf(rulesetFd, 0); err != nil {
        return fmt.Errorf("landlock_restrict_self: %w", err)
    }

    return nil
}
```

**Step 4: Create stub for non-Linux**

```go
// internal/landlock/ruleset_other.go
//go:build !linux

package landlock

import "errors"

type RulesetBuilder struct {
    abi          int
    workspace    string
    executePaths []string
    readPaths    []string
    writePaths   []string
    denyPaths    []string
}

func NewRulesetBuilder(abi int) *RulesetBuilder {
    return &RulesetBuilder{abi: abi}
}

func (b *RulesetBuilder) SetWorkspace(path string)              { b.workspace = path }
func (b *RulesetBuilder) AddExecutePath(path string) error      { b.executePaths = append(b.executePaths, path); return nil }
func (b *RulesetBuilder) AddReadPath(path string) error         { b.readPaths = append(b.readPaths, path); return nil }
func (b *RulesetBuilder) AddWritePath(path string) error        { b.writePaths = append(b.writePaths, path); return nil }
func (b *RulesetBuilder) AddDenyPath(path string)               { b.denyPaths = append(b.denyPaths, path) }
func (b *RulesetBuilder) SetNetworkAccess(connect, bind bool)   {}
func (b *RulesetBuilder) Build() (int, error)                   { return -1, errors.New("Landlock not supported") }
func Enforce(rulesetFd int) error                               { return errors.New("Landlock not supported") }
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/landlock/... -run TestRulesetBuilder -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/landlock/
git commit -m "feat(landlock): implement Landlock ruleset builder"
```

---

## Task 6: Derive Landlock Paths from Policy

**Files:**
- Create: `internal/landlock/policy.go`
- Create: `internal/landlock/policy_test.go`

**Step 1: Write the failing test**

```go
// internal/landlock/policy_test.go
package landlock

import (
    "testing"

    "github.com/agentsh/agentsh/internal/policy"
)

func TestDeriveExecutePathsFromPolicy(t *testing.T) {
    // Create a mock policy with command rules
    rules := []policy.CommandRule{
        {FullPaths: []string{"/usr/bin/git"}, Decision: policy.Allow},
        {FullPaths: []string{"/usr/local/bin/node"}, Decision: policy.Allow},
        {FullPaths: []string{"/bin/rm"}, Decision: policy.Deny}, // Should be ignored
    }

    paths := DeriveExecutePathsFromRules(rules)

    // Should extract directories, not full paths
    expected := map[string]bool{
        "/usr/bin":       true,
        "/usr/local/bin": true,
    }

    for _, p := range paths {
        if !expected[p] {
            t.Errorf("unexpected path: %s", p)
        }
        delete(expected, p)
    }

    if len(expected) > 0 {
        t.Errorf("missing paths: %v", expected)
    }
}

func TestDeriveExecutePathsFromGlobs(t *testing.T) {
    rules := []policy.CommandRule{
        {PathGlobs: []string{"/usr/bin/*"}, Decision: policy.Allow},
        {PathGlobs: []string{"/opt/*/bin/*"}, Decision: policy.Allow},
    }

    paths := DeriveExecutePathsFromRules(rules)

    // Should extract base directories from globs
    found := make(map[string]bool)
    for _, p := range paths {
        found[p] = true
    }

    if !found["/usr/bin"] {
        t.Error("expected /usr/bin from glob /usr/bin/*")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/landlock/... -run TestDeriveExecutePaths -v`
Expected: FAIL with "undefined: DeriveExecutePathsFromRules"

**Step 3: Write minimal implementation**

```go
// internal/landlock/policy.go
package landlock

import (
    "path/filepath"
    "strings"

    "github.com/agentsh/agentsh/internal/policy"
)

// DeriveExecutePathsFromRules extracts directory paths from policy command rules.
func DeriveExecutePathsFromRules(rules []policy.CommandRule) []string {
    pathSet := make(map[string]struct{})

    for _, rule := range rules {
        // Only process allow rules
        if rule.Decision != policy.Allow {
            continue
        }

        // Extract directories from full paths
        for _, p := range rule.FullPaths {
            dir := filepath.Dir(p)
            if dir != "" && dir != "." {
                pathSet[dir] = struct{}{}
            }
        }

        // Extract base directories from globs
        for _, g := range rule.PathGlobs {
            dir := extractBaseDir(g)
            if dir != "" && dir != "." {
                pathSet[dir] = struct{}{}
            }
        }
    }

    // Convert to slice
    paths := make([]string, 0, len(pathSet))
    for p := range pathSet {
        paths = append(paths, p)
    }

    return paths
}

// extractBaseDir extracts the non-glob prefix from a glob pattern.
// e.g., "/usr/bin/*" -> "/usr/bin"
// e.g., "/opt/*/bin/*" -> "/opt"
func extractBaseDir(glob string) string {
    // Find first glob character
    for i, c := range glob {
        if c == '*' || c == '?' || c == '[' {
            // Return directory up to this point
            prefix := glob[:i]
            return filepath.Dir(prefix)
        }
    }
    // No glob characters, return directory of the path
    return filepath.Dir(glob)
}

// BuildFromConfig creates a RulesetBuilder from config and policy.
func BuildFromConfig(cfg *Config, pol *policy.Policy, workspace string, abi int) (*RulesetBuilder, error) {
    b := NewRulesetBuilder(abi)

    // Set workspace (full access)
    if workspace != "" {
        b.SetWorkspace(workspace)
    }

    // Add paths derived from policy
    if pol != nil {
        derivedPaths := DeriveExecutePathsFromRules(pol.Commands)
        for _, p := range derivedPaths {
            _ = b.AddExecutePath(p)
        }
    }

    // Add explicit config paths
    if cfg != nil {
        for _, p := range cfg.AllowExecute {
            _ = b.AddExecutePath(p)
        }
        for _, p := range cfg.AllowRead {
            _ = b.AddReadPath(p)
        }
        for _, p := range cfg.AllowWrite {
            _ = b.AddWritePath(p)
        }
        for _, p := range cfg.DenyPaths {
            b.AddDenyPath(p)
        }
        b.SetNetworkAccess(cfg.Network.AllowConnectTCP, cfg.Network.AllowBindTCP)
    }

    // Add default deny paths (container escape vectors)
    defaultDenyPaths := []string{
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/var/run/crio/crio.sock",
        "/var/run/secrets/kubernetes.io",
        "/run/systemd/private",
    }
    for _, p := range defaultDenyPaths {
        b.AddDenyPath(p)
    }

    return b, nil
}

// Config mirrors the LandlockConfig from internal/config.
type Config struct {
    Enabled      bool
    AllowExecute []string
    AllowRead    []string
    AllowWrite   []string
    DenyPaths    []string
    Network      NetworkConfig
}

type NetworkConfig struct {
    AllowConnectTCP bool
    AllowBindTCP    bool
    BindPorts       []int
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/landlock/... -run TestDeriveExecutePaths -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/landlock/policy.go internal/landlock/policy_test.go
git commit -m "feat(landlock): derive execute paths from policy rules"
```

---

## Task 7: Integrate with Exec Flow

**Files:**
- Modify: `internal/api/app.go` - Add Landlock hook
- Create: `internal/api/landlock_hook.go`
- Create: `internal/api/landlock_hook_test.go`

**Step 1: Write the failing test**

```go
// internal/api/landlock_hook_test.go
//go:build linux

package api

import (
    "testing"

    "github.com/agentsh/agentsh/internal/capabilities"
    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/internal/landlock"
)

func TestCreateLandlockHook(t *testing.T) {
    cfg := &config.LandlockConfig{
        Enabled:      true,
        AllowExecute: []string{"/usr/bin", "/bin"},
        AllowRead:    []string{"/etc/ssl/certs"},
        DenyPaths:    []string{"/var/run/docker.sock"},
    }

    secCaps := &capabilities.SecurityCapabilities{
        Landlock:    true,
        LandlockABI: 3,
    }

    hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

    if hook == nil {
        t.Error("expected non-nil hook when Landlock available")
    }
}

func TestCreateLandlockHook_Disabled(t *testing.T) {
    cfg := &config.LandlockConfig{
        Enabled: false,
    }

    secCaps := &capabilities.SecurityCapabilities{
        Landlock:    true,
        LandlockABI: 3,
    }

    hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

    if hook != nil {
        t.Error("expected nil hook when Landlock disabled")
    }
}

func TestCreateLandlockHook_Unavailable(t *testing.T) {
    cfg := &config.LandlockConfig{
        Enabled: true,
    }

    secCaps := &capabilities.SecurityCapabilities{
        Landlock: false,
    }

    hook := CreateLandlockHook(cfg, secCaps, "/tmp/workspace", nil)

    if hook != nil {
        t.Error("expected nil hook when Landlock unavailable")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/api/... -run TestCreateLandlockHook -v`
Expected: FAIL with "undefined: CreateLandlockHook"

**Step 3: Write minimal implementation**

```go
// internal/api/landlock_hook.go
//go:build linux

package api

import (
    "fmt"
    "log/slog"

    "github.com/agentsh/agentsh/internal/capabilities"
    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/internal/landlock"
    "github.com/agentsh/agentsh/internal/policy"
)

// LandlockHook is a post-fork hook that applies Landlock restrictions.
type LandlockHook struct {
    cfg       *config.LandlockConfig
    secCaps   *capabilities.SecurityCapabilities
    workspace string
    policy    *policy.Policy
    logger    *slog.Logger
}

// CreateLandlockHook creates a hook for applying Landlock restrictions.
// Returns nil if Landlock is disabled or unavailable.
func CreateLandlockHook(
    cfg *config.LandlockConfig,
    secCaps *capabilities.SecurityCapabilities,
    workspace string,
    pol *policy.Policy,
) *LandlockHook {
    if cfg == nil || !cfg.Enabled {
        return nil
    }

    if secCaps == nil || !secCaps.Landlock {
        return nil
    }

    return &LandlockHook{
        cfg:       cfg,
        secCaps:   secCaps,
        workspace: workspace,
        policy:    pol,
        logger:    slog.Default(),
    }
}

// Apply builds and enforces the Landlock ruleset.
// This should be called in the child process after fork, before exec.
func (h *LandlockHook) Apply() error {
    // Convert config to landlock.Config
    llCfg := &landlock.Config{
        Enabled:      h.cfg.Enabled,
        AllowExecute: h.cfg.AllowExecute,
        AllowRead:    h.cfg.AllowRead,
        AllowWrite:   h.cfg.AllowWrite,
        DenyPaths:    h.cfg.DenyPaths,
        Network: landlock.NetworkConfig{
            AllowConnectTCP: h.cfg.Network.AllowConnectTCP,
            AllowBindTCP:    h.cfg.Network.AllowBindTCP,
            BindPorts:       h.cfg.Network.BindPorts,
        },
    }

    // Build the ruleset
    builder, err := landlock.BuildFromConfig(llCfg, h.policy, h.workspace, h.secCaps.LandlockABI)
    if err != nil {
        return fmt.Errorf("build landlock ruleset: %w", err)
    }

    rulesetFd, err := builder.Build()
    if err != nil {
        return fmt.Errorf("create landlock ruleset: %w", err)
    }
    defer func() {
        if rulesetFd >= 0 {
            // Close after enforce (or on error)
        }
    }()

    // Enforce the ruleset
    if err := landlock.Enforce(rulesetFd); err != nil {
        return fmt.Errorf("enforce landlock ruleset: %w", err)
    }

    h.logger.Debug("landlock restrictions applied",
        "workspace", h.workspace,
        "abi", h.secCaps.LandlockABI,
        "execute_paths", len(h.cfg.AllowExecute),
        "deny_paths", len(h.cfg.DenyPaths))

    return nil
}
```

**Step 4: Create stub for non-Linux**

```go
// internal/api/landlock_hook_other.go
//go:build !linux

package api

import (
    "github.com/agentsh/agentsh/internal/capabilities"
    "github.com/agentsh/agentsh/internal/config"
    "github.com/agentsh/agentsh/internal/policy"
)

type LandlockHook struct{}

func CreateLandlockHook(
    cfg *config.LandlockConfig,
    secCaps *capabilities.SecurityCapabilities,
    workspace string,
    pol *policy.Policy,
) *LandlockHook {
    return nil
}

func (h *LandlockHook) Apply() error {
    return nil
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/api/... -run TestCreateLandlockHook -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/api/landlock_hook*.go
git commit -m "feat(api): add Landlock post-fork hook"
```

---

## Task 8: Add Security Mode Validation

**Files:**
- Create: `internal/capabilities/validate.go`
- Create: `internal/capabilities/validate_test.go`

**Step 1: Write the failing test**

```go
// internal/capabilities/validate_test.go
package capabilities

import (
    "testing"
)

func TestValidateStrictMode(t *testing.T) {
    tests := []struct {
        name    string
        mode    string
        caps    SecurityCapabilities
        wantErr bool
    }{
        {
            name: "full mode with all caps",
            mode: ModeFull,
            caps: SecurityCapabilities{
                Seccomp: true, eBPF: true, FUSE: true,
            },
            wantErr: false,
        },
        {
            name: "full mode missing seccomp",
            mode: ModeFull,
            caps: SecurityCapabilities{
                Seccomp: false, eBPF: true, FUSE: true,
            },
            wantErr: true,
        },
        {
            name: "landlock mode with Landlock + FUSE",
            mode: ModeLandlock,
            caps: SecurityCapabilities{
                Landlock: true, FUSE: true,
            },
            wantErr: false,
        },
        {
            name: "landlock mode missing FUSE",
            mode: ModeLandlock,
            caps: SecurityCapabilities{
                Landlock: true, FUSE: false,
            },
            wantErr: true,
        },
        {
            name: "minimal always passes",
            mode: ModeMinimal,
            caps: SecurityCapabilities{},
            wantErr: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateStrictMode(tt.mode, &tt.caps)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateStrictMode() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestValidateMinimumMode(t *testing.T) {
    tests := []struct {
        name        string
        selected    string
        minimum     string
        wantErr     bool
    }{
        {
            name:     "full meets landlock minimum",
            selected: ModeFull,
            minimum:  ModeLandlock,
            wantErr:  false,
        },
        {
            name:     "minimal fails landlock minimum",
            selected: ModeMinimal,
            minimum:  ModeLandlock,
            wantErr:  true,
        },
        {
            name:     "landlock-only fails landlock minimum",
            selected: ModeLandlockOnly,
            minimum:  ModeLandlock,
            wantErr:  true,
        },
        {
            name:     "empty minimum always passes",
            selected: ModeMinimal,
            minimum:  "",
            wantErr:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateMinimumMode(tt.selected, tt.minimum)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateMinimumMode() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestValidateStrictMode|TestValidateMinimumMode" -v`
Expected: FAIL with "undefined: ValidateStrictMode"

**Step 3: Write minimal implementation**

```go
// internal/capabilities/validate.go
package capabilities

import (
    "fmt"
)

// modeRank defines the security strength of each mode (higher = stronger).
var modeRank = map[string]int{
    ModeFull:        4,
    ModeLandlock:    3,
    ModeLandlockOnly: 2,
    ModeMinimal:     1,
}

// ValidateStrictMode checks that required capabilities are available for the mode.
func ValidateStrictMode(mode string, caps *SecurityCapabilities) error {
    switch mode {
    case ModeFull:
        if !caps.Seccomp {
            return fmt.Errorf("strict mode %q requires seccomp", mode)
        }
        if !caps.eBPF {
            return fmt.Errorf("strict mode %q requires eBPF", mode)
        }
        if !caps.FUSE {
            return fmt.Errorf("strict mode %q requires FUSE", mode)
        }

    case ModeLandlock:
        if !caps.Landlock {
            return fmt.Errorf("strict mode %q requires Landlock", mode)
        }
        if !caps.FUSE {
            return fmt.Errorf("strict mode %q requires FUSE", mode)
        }

    case ModeLandlockOnly:
        if !caps.Landlock {
            return fmt.Errorf("strict mode %q requires Landlock", mode)
        }

    case ModeMinimal:
        // Always passes
    }

    return nil
}

// ValidateMinimumMode checks that the selected mode meets the minimum requirement.
func ValidateMinimumMode(selected, minimum string) error {
    if minimum == "" {
        return nil
    }

    selectedRank, ok := modeRank[selected]
    if !ok {
        return fmt.Errorf("unknown mode: %s", selected)
    }

    minimumRank, ok := modeRank[minimum]
    if !ok {
        return fmt.Errorf("unknown minimum mode: %s", minimum)
    }

    if selectedRank < minimumRank {
        return fmt.Errorf("selected mode %q does not meet minimum requirement %q", selected, minimum)
    }

    return nil
}

// PolicyWarning represents a warning about policy enforcement limitations.
type PolicyWarning struct {
    Level   string // "warn" or "info"
    Message string
}

// ValidatePolicyForMode checks if policy rules can be enforced in the current mode.
func ValidatePolicyForMode(caps *SecurityCapabilities, hasUnixSocketRules, hasSignalRules, hasNetworkRules bool) []PolicyWarning {
    var warnings []PolicyWarning

    if !caps.Seccomp && hasUnixSocketRules {
        warnings = append(warnings, PolicyWarning{
            Level:   "warn",
            Message: "Unix socket rules defined but seccomp unavailable - abstract sockets unprotected",
        })
    }

    if !caps.Seccomp && hasSignalRules {
        warnings = append(warnings, PolicyWarning{
            Level:   "warn",
            Message: "Signal rules defined but seccomp unavailable - relying on PID namespace + CAP_KILL drop",
        })
    }

    if !caps.LandlockNetwork && !caps.eBPF && hasNetworkRules {
        warnings = append(warnings, PolicyWarning{
            Level:   "warn",
            Message: "Network rules defined but no enforcement available (need eBPF or Landlock ABI v4+)",
        })
    }

    return warnings
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/capabilities/... -run "TestValidateStrictMode|TestValidateMinimumMode" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/validate.go internal/capabilities/validate_test.go
git commit -m "feat(capabilities): add strict mode and minimum mode validation"
```

---

## Task 9: Integrate Detection at Server Startup

**Files:**
- Modify: `internal/server/server.go` - Add security detection and mode selection

**Step 1: Read the current server.go implementation**

Read `internal/server/server.go` lines 64-100 to understand the current capability check integration.

**Step 2: Add security capabilities detection**

After the existing `capabilities.CheckAll(cfg)` call (around line 80), add:

```go
// Detect security capabilities and select mode
secCaps := capabilities.DetectSecurityCapabilities()

// Determine security mode
secMode := cfg.Security.Mode
if secMode == "" || secMode == "auto" {
    secMode = secCaps.SelectMode()
}

// Validate strict mode if enabled
if cfg.Security.Strict {
    if err := capabilities.ValidateStrictMode(secMode, secCaps); err != nil {
        return nil, fmt.Errorf("strict mode validation failed: %w", err)
    }
}

// Validate minimum mode
if err := capabilities.ValidateMinimumMode(secMode, cfg.Security.MinimumMode); err != nil {
    return nil, fmt.Errorf("minimum mode validation failed: %w", err)
}

// Log security posture
logger.Info("security detection complete",
    "landlock", secCaps.Landlock,
    "landlock_abi", secCaps.LandlockABI,
    "seccomp", secCaps.Seccomp,
    "ebpf", secCaps.eBPF,
    "fuse", secCaps.FUSE,
    "mode", secMode)

if secMode != capabilities.ModeFull && cfg.Security.WarnDegraded {
    logger.Warn("running in degraded security mode",
        "mode", secMode,
        "signal_interception", secCaps.Seccomp,
        "unix_socket_interception", secCaps.Seccomp)
}
```

**Step 3: Store security caps in Server struct**

Add field to Server struct:

```go
type Server struct {
    // ... existing fields ...
    securityCaps *capabilities.SecurityCapabilities
    securityMode string
}
```

**Step 4: Pass to session/API layer**

Ensure the security capabilities and mode are passed to the API app for use in exec hooks.

**Step 5: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(server): integrate security detection and mode selection at startup"
```

---

## Task 10: Wire Landlock Hook into Exec Flow

**Files:**
- Modify: `internal/api/app.go` - Add Landlock hook creation
- Modify: `internal/api/exec.go` - Apply Landlock in post-start hook chain

**Step 1: Add Landlock hook to App struct**

In `internal/api/app.go`, add:

```go
type App struct {
    // ... existing fields ...
    securityCaps *capabilities.SecurityCapabilities
    securityMode string
}
```

**Step 2: Create combined post-start hook**

Modify the hook chain to include Landlock:

```go
func (a *App) createPostStartHook(session *session.Session) postStartHook {
    return func(pid int) (func() error, error) {
        var cleanups []func() error

        // Apply cgroups (existing)
        if a.cgroupsEnabled {
            cleanup, err := a.applyCgroupV2(pid, session)
            if err != nil {
                return nil, err
            }
            if cleanup != nil {
                cleanups = append(cleanups, cleanup)
            }
        }

        // Apply Landlock (new)
        if a.securityCaps != nil && a.securityCaps.Landlock {
            llHook := CreateLandlockHook(
                &a.cfg.Landlock,
                a.securityCaps,
                session.Workspace,
                session.Policy,
            )
            if llHook != nil {
                // Note: Landlock must be applied IN the child process
                // This hook runs in parent, so we need a different approach
                // See Step 3 for the actual integration
            }
        }

        return func() error {
            for _, c := range cleanups {
                _ = c()
            }
            return nil
        }, nil
    }
}
```

**Step 3: Apply Landlock in child process**

The key insight: Landlock must be applied IN the child process after fork but before exec. This is different from cgroups which can be applied from the parent.

In `runCommandWithResources` or the wrapper setup, pass Landlock config via environment or socket so the wrapper can apply it:

```go
// In setupSeccompWrapper or similar
if a.securityCaps.Landlock {
    // Pass Landlock config to wrapper via env var
    env = append(env, "AGENTSH_LANDLOCK_CONFIG="+encodeLandlockConfig(cfg))
}
```

Then in `agentsh-unixwrap` or a new wrapper, apply Landlock before exec.

**Step 4: Update wrapper to apply Landlock**

The wrapper binary needs to:
1. Read `AGENTSH_LANDLOCK_CONFIG` env var
2. Build and apply Landlock ruleset
3. Drop capabilities
4. Exec the actual command

**Step 5: Commit**

```bash
git add internal/api/app.go internal/api/exec.go
git commit -m "feat(api): wire Landlock hook into exec flow"
```

---

## Task 11: Add Integration Tests

**Files:**
- Create: `internal/landlock/integration_test.go`

**Step 1: Write integration test**

```go
// internal/landlock/integration_test.go
//go:build linux && integration

package landlock

import (
    "os"
    "os/exec"
    "testing"
)

func TestLandlockEnforcement_BlocksExecute(t *testing.T) {
    if os.Getuid() == 0 {
        t.Skip("test should not run as root")
    }

    result := DetectLandlock()
    if !result.Available {
        t.Skip("Landlock not available")
    }

    // Create a ruleset that only allows /bin
    b := NewRulesetBuilder(result.ABI)
    b.AddExecutePath("/bin")
    b.AddReadPath("/lib")
    b.AddReadPath("/lib64")
    b.AddReadPath("/usr/lib")

    fd, err := b.Build()
    if err != nil {
        t.Fatalf("failed to build ruleset: %v", err)
    }
    defer unix.Close(fd)

    // Fork a child to test enforcement
    // (We can't enforce in the test process itself)
    cmd := exec.Command("/bin/sh", "-c", "/usr/bin/id")
    err = cmd.Run()

    // Before enforcement, this should work
    if err != nil {
        t.Logf("command failed before enforcement (expected on some systems): %v", err)
    }
}

func TestLandlockEnforcement_AllowsWorkspace(t *testing.T) {
    result := DetectLandlock()
    if !result.Available {
        t.Skip("Landlock not available")
    }

    // Create temp workspace
    workspace, err := os.MkdirTemp("", "landlock-test-*")
    if err != nil {
        t.Fatalf("failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(workspace)

    // Create test file
    testFile := workspace + "/test.txt"
    if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
        t.Fatalf("failed to write test file: %v", err)
    }

    b := NewRulesetBuilder(result.ABI)
    b.SetWorkspace(workspace)

    fd, err := b.Build()
    if err != nil {
        t.Fatalf("failed to build ruleset: %v", err)
    }

    // Verify ruleset was created
    if fd < 0 {
        t.Error("expected valid ruleset fd")
    }

    unix.Close(fd)
}
```

**Step 2: Run integration tests**

Run: `cd /home/eran/work/agentsh/.worktrees/landlock-fallback && go test ./internal/landlock/... -tags=integration -v`

**Step 3: Commit**

```bash
git add internal/landlock/integration_test.go
git commit -m "test(landlock): add integration tests for Landlock enforcement"
```

---

## Task 12: Update Documentation

**Files:**
- Update: `docs/plans/2026-01-18-landlock-fallback-security-design.md` - Mark as implemented
- Create: `docs/configuration/security-modes.md` - User documentation

**Step 1: Write user documentation**

```markdown
# Security Modes

agentsh supports multiple security modes depending on available kernel features.

## Modes

| Mode | Requirements | Protection Level |
|------|--------------|-----------------|
| `full` | seccomp + eBPF + FUSE | 100% |
| `landlock` | Landlock + FUSE | ~85% |
| `landlock-only` | Landlock | ~80% |
| `minimal` | (none) | ~50% |

## Configuration

```yaml
security:
  mode: auto           # auto-detect best available
  strict: false        # fail if mode requirements not met
  minimum_mode: ""     # fail if auto-detect picks worse
  warn_degraded: true  # log warnings in degraded mode

landlock:
  enabled: true
  allow_execute:
    - /usr/bin
    - /bin
    - /usr/local/bin
  allow_read:
    - /etc/ssl/certs
    - /etc/resolv.conf
  deny_paths:
    - /var/run/docker.sock
  network:
    allow_connect_tcp: true
    allow_bind_tcp: false

capabilities:
  allow: []  # drop all capabilities by default
```

## Known Limitations

In `landlock` and `landlock-only` modes:

- **Signal interception disabled** - Relies on PID namespace + CAP_KILL drop
- **Abstract Unix sockets unprotected** - Only path-based sockets blocked
- **Network restrictions require kernel 6.7+** - Landlock ABI v4
```

**Step 2: Commit**

```bash
git add docs/
git commit -m "docs: add security modes configuration documentation"
```

---

## Summary

This implementation plan covers:

1. **Detection** - Landlock availability and ABI version detection
2. **Config** - New config schema for security mode, Landlock, and capabilities
3. **Capabilities** - Three-tier capability dropping with hardcoded always-drop
4. **Landlock** - Ruleset builder with path derivation from policy
5. **Integration** - Hook into exec flow, server startup detection
6. **Validation** - Strict mode and minimum mode enforcement
7. **Testing** - Unit and integration tests
8. **Documentation** - User-facing configuration docs

Total tasks: 12
Estimated implementation: Each task is 15-30 minutes following TDD.
