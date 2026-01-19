# agentsh detect Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `agentsh detect` and `agentsh detect config` CLI commands for cross-platform security capability detection and config generation.

**Architecture:** DetectResult struct holds unified cross-platform detection results. Platform-specific detection functions populate it. Formatters render output (table/json/yaml). ConfigGenerator produces optimized config snippets.

**Tech Stack:** Go, Cobra CLI, gopkg.in/yaml.v3, encoding/json

---

## Task 1: Create DetectResult Types

**Files:**
- Create: `internal/capabilities/detect_result.go`
- Create: `internal/capabilities/detect_result_test.go`

**Step 1: Write the failing test**

```go
//go:build linux || darwin || windows

package capabilities

import (
	"testing"
)

func TestDetectResult_JSON(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 80,
		Capabilities: map[string]any{
			"landlock":     true,
			"landlock_abi": 4,
		},
		Summary: DetectSummary{
			Available:   []string{"landlock"},
			Unavailable: []string{"seccomp"},
		},
		Tips: []Tip{
			{
				Feature: "seccomp",
				Status:  "unavailable",
				Impact:  "Syscall filtering disabled",
				Action:  "Run on host",
			},
		},
	}

	json, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if len(json) == 0 {
		t.Error("JSON() returned empty")
	}
}

func TestDetectResult_YAML(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "minimal",
		ProtectionScore: 50,
		Capabilities:    map[string]any{},
		Summary:         DetectSummary{},
		Tips:            []Tip{},
	}

	yaml, err := result.YAML()
	if err != nil {
		t.Fatalf("YAML() error: %v", err)
	}
	if len(yaml) == 0 {
		t.Error("YAML() returned empty")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetectResult -v`
Expected: FAIL with "undefined: DetectResult"

**Step 3: Write minimal implementation**

```go
//go:build linux || darwin || windows

package capabilities

import (
	"encoding/json"

	"gopkg.in/yaml.v3"
)

// DetectResult is the unified cross-platform detection result.
type DetectResult struct {
	Platform        string         `json:"platform" yaml:"platform"`
	SecurityMode    string         `json:"security_mode" yaml:"security_mode"`
	ProtectionScore int            `json:"protection_score" yaml:"protection_score"`
	Capabilities    map[string]any `json:"capabilities" yaml:"capabilities"`
	Summary         DetectSummary  `json:"summary" yaml:"summary"`
	Tips            []Tip          `json:"tips" yaml:"tips"`
}

// DetectSummary provides a quick overview of available/unavailable features.
type DetectSummary struct {
	Available   []string `json:"available" yaml:"available"`
	Unavailable []string `json:"unavailable" yaml:"unavailable"`
}

// Tip provides actionable guidance for enabling a capability.
type Tip struct {
	Feature string `json:"feature" yaml:"feature"`
	Status  string `json:"status" yaml:"status"`
	Impact  string `json:"impact" yaml:"impact"`
	Action  string `json:"action" yaml:"action"`
}

// JSON returns the detection result as JSON bytes.
func (r *DetectResult) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// YAML returns the detection result as YAML bytes.
func (r *DetectResult) YAML() ([]byte, error) {
	return yaml.Marshal(r)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestDetectResult -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/detect_result.go internal/capabilities/detect_result_test.go
git commit -m "feat(detect): add DetectResult types with JSON/YAML serialization"
```

---

## Task 2: Create Table Formatter

**Files:**
- Modify: `internal/capabilities/detect_result.go`
- Modify: `internal/capabilities/detect_result_test.go`

**Step 1: Write the failing test**

Add to `detect_result_test.go`:

```go
func TestDetectResult_Table(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 80,
		Capabilities: map[string]any{
			"seccomp":          false,
			"landlock":         true,
			"landlock_abi":     4,
			"landlock_network": true,
			"fuse":             false,
		},
		Summary: DetectSummary{
			Available:   []string{"landlock", "landlock_network"},
			Unavailable: []string{"seccomp", "fuse"},
		},
		Tips: []Tip{
			{
				Feature: "fuse",
				Status:  "unavailable",
				Impact:  "Fine-grained filesystem control disabled",
				Action:  "Install FUSE3: pacman -S fuse3",
			},
		},
	}

	table := result.Table()
	if len(table) == 0 {
		t.Error("Table() returned empty")
	}
	// Check key elements are present
	if !strings.Contains(table, "linux") {
		t.Error("Table() missing platform")
	}
	if !strings.Contains(table, "landlock") {
		t.Error("Table() missing landlock")
	}
	if !strings.Contains(table, "fuse") {
		t.Error("Table() missing tip about fuse")
	}
}
```

Add import `"strings"` to test file.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetectResult_Table -v`
Expected: FAIL with "r.Table undefined"

**Step 3: Write minimal implementation**

Add to `detect_result.go`:

```go
import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Table returns a human-readable table representation.
func (r *DetectResult) Table() string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("Platform: %s\n", r.Platform))
	sb.WriteString(fmt.Sprintf("Security Mode: %s\n", r.SecurityMode))
	sb.WriteString(fmt.Sprintf("Protection Score: %d%%\n", r.ProtectionScore))
	sb.WriteString("\n")

	// Capabilities table
	sb.WriteString("CAPABILITIES\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	// Sort capability keys for consistent output
	keys := make([]string, 0, len(r.Capabilities))
	for k := range r.Capabilities {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := r.Capabilities[k]
		status := formatCapabilityValue(v)
		sb.WriteString(fmt.Sprintf("  %-24s %s\n", k, status))
	}

	// Tips section
	if len(r.Tips) > 0 {
		sb.WriteString("\nTIPS\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, tip := range r.Tips {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", tip.Feature, tip.Impact))
			sb.WriteString(fmt.Sprintf("    -> %s\n", tip.Action))
		}
	}

	sb.WriteString("\nRun 'agentsh detect config' to generate an optimized configuration.\n")

	return sb.String()
}

func formatCapabilityValue(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "✓"
		}
		return "-"
	case int:
		return fmt.Sprintf("✓ (v%d)", val)
	case string:
		return val
	default:
		return fmt.Sprintf("%v", v)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestDetectResult_Table -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/detect_result.go internal/capabilities/detect_result_test.go
git commit -m "feat(detect): add table formatter for human-readable output"
```

---

## Task 3: Create Tips Generator

**Files:**
- Create: `internal/capabilities/tips.go`
- Create: `internal/capabilities/tips_test.go`

**Step 1: Write the failing test**

```go
//go:build linux || darwin || windows

package capabilities

import (
	"runtime"
	"testing"
)

func TestGenerateTips_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	caps := map[string]any{
		"seccomp":          false,
		"landlock":         true,
		"landlock_abi":     3,
		"landlock_network": false,
		"fuse":             false,
		"ebpf":             false,
	}

	tips := GenerateTips("linux", caps)

	// Should have tips for missing features
	hasFuseTip := false
	hasNetworkTip := false
	for _, tip := range tips {
		if tip.Feature == "fuse" {
			hasFuseTip = true
			if tip.Action == "" {
				t.Error("fuse tip missing action")
			}
		}
		if tip.Feature == "landlock_network" {
			hasNetworkTip = true
		}
	}

	if !hasFuseTip {
		t.Error("missing fuse tip")
	}
	if !hasNetworkTip {
		t.Error("missing landlock_network tip")
	}
}

func TestGenerateTips_Darwin(t *testing.T) {
	caps := map[string]any{
		"fuse_t":       false,
		"sandbox_exec": true,
		"esf":          false,
	}

	tips := GenerateTips("darwin", caps)

	hasFuseTTip := false
	for _, tip := range tips {
		if tip.Feature == "fuse_t" {
			hasFuseTTip = true
			if tip.Action == "" {
				t.Error("fuse_t tip missing action")
			}
		}
	}

	if !hasFuseTTip {
		t.Error("missing fuse_t tip")
	}
}

func TestGenerateTips_Windows(t *testing.T) {
	caps := map[string]any{
		"app_container": true,
		"winfsp":        false,
		"minifilter":    false,
	}

	tips := GenerateTips("windows", caps)

	hasWinfspTip := false
	for _, tip := range tips {
		if tip.Feature == "winfsp" {
			hasWinfspTip = true
		}
	}

	if !hasWinfspTip {
		t.Error("missing winfsp tip")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestGenerateTips -v`
Expected: FAIL with "undefined: GenerateTips"

**Step 3: Write minimal implementation**

```go
//go:build linux || darwin || windows

package capabilities

// tipDefinition defines a tip for a missing capability.
type tipDefinition struct {
	Feature  string
	Impact   string
	Action   string
	CheckKey string // capability key to check
}

var linuxTips = []tipDefinition{
	{
		Feature:  "fuse",
		CheckKey: "fuse",
		Impact:   "Fine-grained filesystem control disabled",
		Action:   "Install FUSE3: apt install fuse3 (Debian/Ubuntu), dnf install fuse3 (Fedora), or pacman -S fuse3 (Arch)",
	},
	{
		Feature:  "seccomp",
		CheckKey: "seccomp",
		Impact:   "Syscall filtering disabled (likely nested container)",
		Action:   "Run in privileged container or on host for full seccomp support",
	},
	{
		Feature:  "landlock_network",
		CheckKey: "landlock_network",
		Impact:   "Kernel-level network restrictions disabled",
		Action:   "Requires kernel 6.7+ (Landlock ABI v4). Upgrade kernel or use proxy-based network control.",
	},
	{
		Feature:  "ebpf",
		CheckKey: "ebpf",
		Impact:   "Network monitoring disabled",
		Action:   "Requires CAP_BPF and cgroups v2. Run as root or with elevated privileges.",
	},
	{
		Feature:  "cgroups_v2",
		CheckKey: "cgroups_v2",
		Impact:   "Resource limits unavailable",
		Action:   "Enable cgroups v2 in kernel or container runtime",
	},
}

var darwinTips = []tipDefinition{
	{
		Feature:  "fuse_t",
		CheckKey: "fuse_t",
		Impact:   "File policy enforcement limited to observation-only",
		Action:   "Install FUSE-T: brew install fuse-t",
	},
	{
		Feature:  "esf",
		CheckKey: "esf",
		Impact:   "Using sandbox-exec instead of Endpoint Security",
		Action:   "ESF requires Apple developer approval. Submit business justification to Apple.",
	},
	{
		Feature:  "lima_available",
		CheckKey: "lima_available",
		Impact:   "No Linux VM isolation available",
		Action:   "Install Lima: brew install lima && limactl start default",
	},
}

var windowsTips = []tipDefinition{
	{
		Feature:  "winfsp",
		CheckKey: "winfsp",
		Impact:   "FUSE-style filesystem mounting disabled",
		Action:   "Install WinFsp: winget install WinFsp.WinFsp",
	},
	{
		Feature:  "minifilter",
		CheckKey: "minifilter",
		Impact:   "No kernel-level file interception",
		Action:   "Install agentsh minifilter driver (requires Administrator)",
	},
	{
		Feature:  "windivert",
		CheckKey: "windivert",
		Impact:   "Transparent network interception disabled",
		Action:   "Install WinDivert for transparent TCP/DNS proxy",
	},
}

// GenerateTips creates actionable tips based on missing capabilities.
func GenerateTips(platform string, caps map[string]any) []Tip {
	var definitions []tipDefinition

	switch platform {
	case "linux":
		definitions = linuxTips
	case "darwin":
		definitions = darwinTips
	case "windows":
		definitions = windowsTips
	default:
		return nil
	}

	var tips []Tip
	for _, def := range definitions {
		val, exists := caps[def.CheckKey]
		if !exists {
			continue
		}

		// Check if capability is missing/false
		isMissing := false
		switch v := val.(type) {
		case bool:
			isMissing = !v
		case int:
			isMissing = v == 0
		}

		if isMissing {
			tips = append(tips, Tip{
				Feature: def.Feature,
				Status:  "unavailable",
				Impact:  def.Impact,
				Action:  def.Action,
			})
		}
	}

	return tips
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestGenerateTips -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/tips.go internal/capabilities/tips_test.go
git commit -m "feat(detect): add tips generator for actionable guidance"
```

---

## Task 4: Create Linux Detect Function

**Files:**
- Modify: `internal/capabilities/security_caps.go`
- Create: `internal/capabilities/detect_linux.go`
- Create: `internal/capabilities/detect_linux_test.go`

**Step 1: Write the failing test**

```go
//go:build linux

package capabilities

import (
	"testing"
)

func TestDetect_Linux(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "linux" {
		t.Errorf("Platform = %q, want linux", result.Platform)
	}

	// SecurityMode should be one of the valid modes
	validModes := map[string]bool{
		"full": true, "landlock": true, "landlock-only": true, "minimal": true,
	}
	if !validModes[result.SecurityMode] {
		t.Errorf("SecurityMode = %q, not a valid mode", result.SecurityMode)
	}

	// ProtectionScore should be between 0 and 100
	if result.ProtectionScore < 0 || result.ProtectionScore > 100 {
		t.Errorf("ProtectionScore = %d, want 0-100", result.ProtectionScore)
	}

	// Should have capabilities map with expected keys
	expectedKeys := []string{"seccomp", "landlock", "fuse", "capabilities_drop"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}

	// capabilities_drop should always be true
	if cd, ok := result.Capabilities["capabilities_drop"].(bool); !ok || !cd {
		t.Error("capabilities_drop should be true")
	}
}

func TestDetect_Linux_Summary(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Summary.Available and Summary.Unavailable should not overlap
	availSet := make(map[string]bool)
	for _, a := range result.Summary.Available {
		availSet[a] = true
	}
	for _, u := range result.Summary.Unavailable {
		if availSet[u] {
			t.Errorf("Feature %q in both Available and Unavailable", u)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetect_Linux -v`
Expected: FAIL with "undefined: Detect"

**Step 3: Write minimal implementation**

```go
//go:build linux

package capabilities

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	// Use existing detection
	secCaps := DetectSecurityCapabilities()

	caps := map[string]any{
		"seccomp":             secCaps.Seccomp,
		"seccomp_user_notify": secCaps.Seccomp,
		"seccomp_basic":       secCaps.SeccompBasic,
		"landlock":            secCaps.Landlock,
		"landlock_abi":        secCaps.LandlockABI,
		"landlock_network":    secCaps.LandlockNetwork,
		"ebpf":                secCaps.EBPF,
		"fuse":                secCaps.FUSE,
		"cgroups_v2":          checkCgroupsV2().Available,
		"pid_namespace":       secCaps.PIDNamespace,
		"capabilities_drop":   secCaps.Capabilities,
	}

	mode := secCaps.SelectMode()
	score := modeToScore(mode)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if k == "landlock_abi" {
			continue // Skip ABI version in summary
		}
		switch val := v.(type) {
		case bool:
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		case int:
			if val > 0 {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("linux", caps)

	return &DetectResult{
		Platform:        "linux",
		SecurityMode:    mode,
		ProtectionScore: score,
		Capabilities:    caps,
		Summary: DetectSummary{
			Available:   available,
			Unavailable: unavailable,
		},
		Tips: tips,
	}, nil
}

func modeToScore(mode string) int {
	switch mode {
	case ModeFull:
		return 100
	case ModeLandlock:
		return 85
	case ModeLandlockOnly:
		return 80
	case ModeMinimal:
		return 50
	default:
		return 0
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestDetect_Linux -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/detect_linux.go internal/capabilities/detect_linux_test.go
git commit -m "feat(detect): add Linux detection function"
```

---

## Task 5: Create macOS Detect Function

**Files:**
- Create: `internal/capabilities/detect_darwin.go`
- Create: `internal/capabilities/detect_darwin_test.go`

**Step 1: Write the failing test**

```go
//go:build darwin

package capabilities

import (
	"testing"
)

func TestDetect_Darwin(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "darwin" {
		t.Errorf("Platform = %q, want darwin", result.Platform)
	}

	// Should have macOS-specific capability keys
	expectedKeys := []string{"sandbox_exec", "fuse_t", "esf"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}

	// sandbox_exec should always be true (built into macOS)
	if se, ok := result.Capabilities["sandbox_exec"].(bool); !ok || !se {
		t.Error("sandbox_exec should be true")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetect_Darwin -v`
Expected: FAIL (on macOS) with "undefined: Detect" or skip on Linux

**Step 3: Write minimal implementation**

```go
//go:build darwin

package capabilities

import (
	"os"
	"os/exec"
)

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"sandbox_exec":      true, // Always available on macOS
		"fuse_t":            checkFuseT(),
		"esf":               checkESF(),
		"network_extension": checkNetworkExtension(),
		"lima_available":    checkLima(),
	}

	mode, score := selectDarwinMode(caps)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if val, ok := v.(bool); ok {
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("darwin", caps)

	return &DetectResult{
		Platform:        "darwin",
		SecurityMode:    mode,
		ProtectionScore: score,
		Capabilities:    caps,
		Summary: DetectSummary{
			Available:   available,
			Unavailable: unavailable,
		},
		Tips: tips,
	}, nil
}

func checkFuseT() bool {
	// Check if FUSE-T is installed via Homebrew
	_, err := os.Stat("/usr/local/lib/libfuse-t.dylib")
	if err == nil {
		return true
	}
	// Also check ARM64 Homebrew path
	_, err = os.Stat("/opt/homebrew/lib/libfuse-t.dylib")
	return err == nil
}

func checkESF() bool {
	// ESF requires entitlement - check if we're running as entitled app
	// For now, return false as most CLI tools won't have ESF
	return false
}

func checkNetworkExtension() bool {
	// Network Extension is available if app is properly entitled
	// For CLI detection, assume false
	return false
}

func checkLima() bool {
	// Check if limactl is available and a VM is running
	_, err := exec.LookPath("limactl")
	if err != nil {
		return false
	}
	// Could also check if a VM is running, but presence of limactl is enough
	return true
}

func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if fuset, _ := caps["fuse_t"].(bool); fuset {
		return "fuse-t", 70
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}
	return "sandbox-exec", 60
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestDetect_Darwin -v`
Expected: PASS (on macOS) or skip (on Linux)

**Step 5: Commit**

```bash
git add internal/capabilities/detect_darwin.go internal/capabilities/detect_darwin_test.go
git commit -m "feat(detect): add macOS detection function"
```

---

## Task 6: Create Windows Detect Function

**Files:**
- Create: `internal/capabilities/detect_windows.go`
- Create: `internal/capabilities/detect_windows_test.go`

**Step 1: Write the failing test**

```go
//go:build windows

package capabilities

import (
	"testing"
)

func TestDetect_Windows(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "windows" {
		t.Errorf("Platform = %q, want windows", result.Platform)
	}

	// Should have Windows-specific capability keys
	expectedKeys := []string{"app_container", "winfsp", "minifilter"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestDetect_Windows -v`
Expected: FAIL (on Windows) or skip on Linux/macOS

**Step 3: Write minimal implementation**

```go
//go:build windows

package capabilities

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"app_container": checkAppContainer(),
		"winfsp":        checkWinFsp(),
		"minifilter":    checkMinifilter(),
		"windivert":     checkWinDivert(),
		"job_objects":   true, // Always available
	}

	mode, score := selectWindowsMode(caps)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if val, ok := v.(bool); ok {
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("windows", caps)

	return &DetectResult{
		Platform:        "windows",
		SecurityMode:    mode,
		ProtectionScore: score,
		Capabilities:    caps,
		Summary: DetectSummary{
			Available:   available,
			Unavailable: unavailable,
		},
		Tips: tips,
	}, nil
}

func checkAppContainer() bool {
	// AppContainer requires Windows 8+
	// Check Windows version
	ver := windows.RtlGetVersion()
	// Windows 8 is version 6.2
	return ver.MajorVersion > 6 || (ver.MajorVersion == 6 && ver.MinorVersion >= 2)
}

func checkWinFsp() bool {
	// Check if WinFsp DLL exists
	programFiles := os.Getenv("ProgramFiles(x86)")
	if programFiles == "" {
		programFiles = os.Getenv("ProgramFiles")
	}
	dllPath := filepath.Join(programFiles, "WinFsp", "bin", "winfsp-x64.dll")
	_, err := os.Stat(dllPath)
	return err == nil
}

func checkMinifilter() bool {
	// Check if our minifilter driver is loaded
	// This is a simplified check - in production would query SCM
	return false
}

func checkWinDivert() bool {
	// Check if WinDivert is available
	_, err := os.Stat(`C:\Windows\System32\WinDivert.dll`)
	return err == nil
}

func selectWindowsMode(caps map[string]any) (string, int) {
	appContainer, _ := caps["app_container"].(bool)
	winfsp, _ := caps["winfsp"].(bool)
	minifilter, _ := caps["minifilter"].(bool)

	if appContainer && minifilter && winfsp {
		return "full", 90
	}
	if appContainer && winfsp {
		return "appcontainer-winfsp", 75
	}
	if appContainer {
		return "appcontainer", 65
	}
	return "job-objects", 50
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestDetect_Windows -v`
Expected: PASS (on Windows) or skip on Linux/macOS

**Step 5: Commit**

```bash
git add internal/capabilities/detect_windows.go internal/capabilities/detect_windows_test.go
git commit -m "feat(detect): add Windows detection function"
```

---

## Task 7: Create Stub for Other Platforms

**Files:**
- Create: `internal/capabilities/detect_other.go`

**Step 1: Write the implementation**

No test needed - this is a stub for unsupported platforms.

```go
//go:build !linux && !darwin && !windows

package capabilities

import "fmt"

// Detect returns an error on unsupported platforms.
func Detect() (*DetectResult, error) {
	return nil, fmt.Errorf("platform not supported for detection")
}
```

**Step 2: Commit**

```bash
git add internal/capabilities/detect_other.go
git commit -m "feat(detect): add stub for unsupported platforms"
```

---

## Task 8: Create Config Generator

**Files:**
- Create: `internal/capabilities/config_generator.go`
- Create: `internal/capabilities/config_generator_test.go`

**Step 1: Write the failing test**

```go
//go:build linux || darwin || windows

package capabilities

import (
	"strings"
	"testing"
)

func TestGenerateConfig_LinuxLandlockOnly(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 80,
		Capabilities: map[string]any{
			"landlock":         true,
			"landlock_abi":     4,
			"landlock_network": true,
			"seccomp":          false,
			"fuse":             false,
		},
	}

	config, err := GenerateConfig(result)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}

	configStr := string(config)

	// Should have header comment
	if !strings.Contains(configStr, "Generated by: agentsh detect config") {
		t.Error("missing header comment")
	}

	// Should have security section
	if !strings.Contains(configStr, "security:") {
		t.Error("missing security section")
	}

	// Should have landlock section
	if !strings.Contains(configStr, "landlock:") {
		t.Error("missing landlock section")
	}

	// Should have network section (ABI v4)
	if !strings.Contains(configStr, "network:") {
		t.Error("missing network section for ABI v4")
	}

	// Should have capabilities section
	if !strings.Contains(configStr, "capabilities:") {
		t.Error("missing capabilities section")
	}
}

func TestGenerateConfig_LinuxLandlockNoNetwork(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 75,
		Capabilities: map[string]any{
			"landlock":         true,
			"landlock_abi":     3,
			"landlock_network": false,
		},
	}

	config, err := GenerateConfig(result)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}

	configStr := string(config)

	// Should NOT have network section (ABI v3)
	if strings.Contains(configStr, "allow_connect_tcp") {
		t.Error("should not have network config for ABI v3")
	}

	// Should have comment about network
	if !strings.Contains(configStr, "kernel 6.7") {
		t.Error("missing comment about network requiring kernel 6.7")
	}
}

func TestGenerateConfig_LinuxFull(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "full",
		ProtectionScore: 100,
		Capabilities: map[string]any{
			"seccomp": true,
			"ebpf":    true,
			"fuse":    true,
		},
	}

	config, err := GenerateConfig(result)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}

	configStr := string(config)

	// Should have mode: full
	if !strings.Contains(configStr, "mode: full") {
		t.Error("missing mode: full")
	}

	// Should NOT have landlock section (full mode uses seccomp)
	if strings.Contains(configStr, "landlock:") {
		t.Error("should not have landlock section in full mode")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestGenerateConfig -v`
Expected: FAIL with "undefined: GenerateConfig"

**Step 3: Write minimal implementation**

```go
//go:build linux || darwin || windows

package capabilities

import (
	"bytes"
	"fmt"
	"text/template"
)

const linuxLandlockConfigTemplate = `# Generated by: agentsh detect config
# Platform: {{ .Platform }}
# Security mode: {{ .SecurityMode }}
# Protection score: ~{{ .ProtectionScore }}%
{{- if .NetworkNote }}
# Note: {{ .NetworkNote }}
{{- end }}

security:
  mode: {{ .SecurityMode }}
  strict: true
  warn_degraded: true

landlock:
  enabled: true
  allow_execute:
    - /usr/bin
    - /bin
    - /usr/local/bin
  allow_read:
    - /etc
    - /lib
    - /lib64
    - /usr/lib
  deny_paths:
    - /var/run/docker.sock
    - /run/containerd/containerd.sock
{{- if .HasNetwork }}
  network:
    allow_connect_tcp: true
    allow_bind_tcp: false
{{- else }}
  # network section omitted - requires kernel 6.7+ (Landlock ABI v4)
{{- end }}

capabilities:
  allow: []
`

const linuxFullConfigTemplate = `# Generated by: agentsh detect config
# Platform: {{ .Platform }}
# Security mode: {{ .SecurityMode }}
# Protection score: {{ .ProtectionScore }}%

security:
  mode: full
  strict: true

# Full mode uses seccomp + eBPF + FUSE - no landlock section needed
# Configure sandbox settings in sandbox: section of main config

capabilities:
  allow: []
`

const linuxMinimalConfigTemplate = `# Generated by: agentsh detect config
# Platform: {{ .Platform }}
# Security mode: {{ .SecurityMode }}
# Protection score: ~{{ .ProtectionScore }}%
# Warning: Limited security - only capability dropping available

security:
  mode: minimal
  strict: false
  warn_degraded: true

capabilities:
  allow: []
`

const darwinConfigTemplate = `# Generated by: agentsh detect config
# Platform: {{ .Platform }}
# Security mode: {{ .SecurityMode }}
# Protection score: ~{{ .ProtectionScore }}%

security:
  mode: auto
  strict: false
  warn_degraded: true

sandbox:
  capabilities: []
  # Add 'network' capability if outbound access needed:
  # capabilities:
  #   - network
`

const windowsConfigTemplate = `# Generated by: agentsh detect config
# Platform: {{ .Platform }}
# Security mode: {{ .SecurityMode }}
# Protection score: ~{{ .ProtectionScore }}%

security:
  mode: auto
  strict: false

sandbox:
  windows:
    use_app_container: {{ .HasAppContainer }}
    use_minifilter: {{ .HasMinifilter }}
    network_access: none
`

type configData struct {
	Platform        string
	SecurityMode    string
	ProtectionScore int
	HasNetwork      bool
	NetworkNote     string
	HasAppContainer bool
	HasMinifilter   bool
	HasWinFsp       bool
}

// GenerateConfig creates a configuration snippet from detection results.
func GenerateConfig(result *DetectResult) ([]byte, error) {
	data := configData{
		Platform:        result.Platform,
		SecurityMode:    result.SecurityMode,
		ProtectionScore: result.ProtectionScore,
	}

	var tmplStr string

	switch result.Platform {
	case "linux":
		tmplStr = selectLinuxTemplate(result, &data)
	case "darwin":
		tmplStr = darwinConfigTemplate
	case "windows":
		data.HasAppContainer, _ = result.Capabilities["app_container"].(bool)
		data.HasMinifilter, _ = result.Capabilities["minifilter"].(bool)
		data.HasWinFsp, _ = result.Capabilities["winfsp"].(bool)
		tmplStr = windowsConfigTemplate
	default:
		return nil, fmt.Errorf("unsupported platform: %s", result.Platform)
	}

	tmpl, err := template.New("config").Parse(tmplStr)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return buf.Bytes(), nil
}

func selectLinuxTemplate(result *DetectResult, data *configData) string {
	switch result.SecurityMode {
	case "full":
		return linuxFullConfigTemplate
	case "minimal":
		return linuxMinimalConfigTemplate
	default:
		// landlock or landlock-only
		data.HasNetwork, _ = result.Capabilities["landlock_network"].(bool)
		if !data.HasNetwork {
			data.NetworkNote = "Network restrictions unavailable (requires kernel 6.7+)"
		}
		return linuxLandlockConfigTemplate
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestGenerateConfig -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/config_generator.go internal/capabilities/config_generator_test.go
git commit -m "feat(detect): add config generator for all platforms"
```

---

## Task 9: Create CLI Command

**Files:**
- Create: `internal/cli/detect.go`
- Create: `internal/cli/detect_test.go`
- Modify: `internal/cli/root.go`

**Step 1: Write the failing test**

```go
package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDetectCmd_Table(t *testing.T) {
	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Platform:") {
		t.Error("output missing Platform")
	}
	if !strings.Contains(output, "Security Mode:") {
		t.Error("output missing Security Mode")
	}
}

func TestDetectCmd_JSON(t *testing.T) {
	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--output", "json"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	output := buf.String()
	if !strings.HasPrefix(output, "{") {
		t.Error("JSON output should start with {")
	}
	if !strings.Contains(output, `"platform"`) {
		t.Error("JSON output missing platform field")
	}
}

func TestDetectCmd_YAML(t *testing.T) {
	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--output", "yaml"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "platform:") {
		t.Error("YAML output missing platform field")
	}
}

func TestDetectConfigCmd(t *testing.T) {
	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"config"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Generated by: agentsh detect config") {
		t.Error("config output missing header")
	}
	if !strings.Contains(output, "security:") {
		t.Error("config output missing security section")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestDetectCmd -v`
Expected: FAIL with "undefined: newDetectCmd"

**Step 3: Write minimal implementation**

```go
package cli

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/spf13/cobra"
)

func newDetectCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect available security capabilities",
		Long: `Detect available security capabilities for the current platform.

This command probes the system for available security primitives like
seccomp, Landlock, eBPF, FUSE, and capabilities. It helps you understand
what security features are available in your environment.

Use 'agentsh detect config' to generate an optimized configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := capabilities.Detect()
			if err != nil {
				return fmt.Errorf("detection failed: %w", err)
			}

			var output []byte
			switch outputFormat {
			case "json":
				output, err = result.JSON()
			case "yaml":
				output, err = result.YAML()
			case "table":
				output = []byte(result.Table())
			default:
				return fmt.Errorf("unknown output format: %s", outputFormat)
			}

			if err != nil {
				return fmt.Errorf("format output: %w", err)
			}

			cmd.Println(string(output))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")

	cmd.AddCommand(newDetectConfigCmd())

	return cmd
}

func newDetectConfigCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate an optimized configuration",
		Long: `Generate an optimized security configuration based on detected capabilities.

By default, outputs to stdout. Use --output to write to a file.

Example:
  agentsh detect config                    # Print to stdout
  agentsh detect config --output config.yaml  # Write to file
  agentsh detect config > security.yaml    # Redirect to file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := capabilities.Detect()
			if err != nil {
				return fmt.Errorf("detection failed: %w", err)
			}

			config, err := capabilities.GenerateConfig(result)
			if err != nil {
				return fmt.Errorf("generate config: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, config, 0644); err != nil {
					return fmt.Errorf("write config to %s: %w", outputPath, err)
				}
				cmd.Printf("Configuration written to %s\n", outputPath)
				return nil
			}

			cmd.Print(string(config))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	return cmd
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/ -run TestDetectCmd -v`
Expected: PASS

**Step 5: Add command to root**

Edit `internal/cli/root.go` to add the detect command:

```go
// In NewRoot function, add:
cmd.AddCommand(newDetectCmd())
```

**Step 6: Run all tests to verify nothing broke**

Run: `go test ./internal/cli/... ./internal/capabilities/... -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add internal/cli/detect.go internal/cli/detect_test.go internal/cli/root.go
git commit -m "feat(cli): add agentsh detect command with config subcommand"
```

---

## Task 10: Integration Test

**Files:**
- Create: `internal/cli/detect_integration_test.go`

**Step 1: Write integration test**

```go
//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDetect_Integration_AllFormats(t *testing.T) {
	formats := []string{"table", "json", "yaml"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cmd := newDetectCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"--output", format})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Execute() error: %v", err)
			}

			output := buf.String()
			if len(output) == 0 {
				t.Error("empty output")
			}

			// Validate format
			switch format {
			case "json":
				var result map[string]any
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Errorf("invalid JSON: %v", err)
				}
			case "yaml":
				var result map[string]any
				if err := yaml.Unmarshal([]byte(output), &result); err != nil {
					t.Errorf("invalid YAML: %v", err)
				}
			}
		})
	}
}

func TestDetectConfig_Integration_WriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"config", "--output", configPath})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// Verify file was created
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	if len(content) == 0 {
		t.Error("config file is empty")
	}

	// Verify it's valid YAML
	var config map[string]any
	if err := yaml.Unmarshal(content, &config); err != nil {
		t.Errorf("invalid YAML in config: %v", err)
	}

	// Verify security section exists
	if _, ok := config["security"]; !ok {
		t.Error("config missing security section")
	}
}

func TestDetectConfig_Integration_Stdout(t *testing.T) {
	cmd := newDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"config"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Generated by: agentsh detect config") {
		t.Error("output missing header")
	}
}
```

**Step 2: Run integration test**

Run: `go test ./internal/cli/ -tags=integration -run TestDetect_Integration -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/cli/detect_integration_test.go
git commit -m "test(detect): add integration tests for detect command"
```

---

## Task 11: Update Documentation

**Files:**
- Modify: `docs/cross-platform.md`

**Step 1: Add detect command documentation**

Add section to `docs/cross-platform.md`:

```markdown
## Detecting Available Capabilities

Use `agentsh detect` to probe your environment and see what security features are available:

```bash
# Show capabilities in table format (default)
agentsh detect

# Output as JSON for scripting
agentsh detect --output json

# Output as YAML
agentsh detect --output yaml
```

### Generating Optimized Configuration

Use `agentsh detect config` to generate a configuration snippet optimized for your environment:

```bash
# Print to stdout
agentsh detect config

# Write to file
agentsh detect config --output security.yaml

# Redirect to file
agentsh detect config > my-config.yaml
```

The generated config includes only security-related sections (`security:`, `landlock:`, `capabilities:`) that you can merge into your main configuration file.
```

**Step 2: Commit**

```bash
git add docs/cross-platform.md
git commit -m "docs: add agentsh detect command usage examples"
```

---

## Task 12: Final Verification

**Step 1: Run all tests**

```bash
go test ./internal/capabilities/... ./internal/cli/... -v
```

Expected: All PASS

**Step 2: Build and test manually**

```bash
go build -o agentsh ./cmd/agentsh
./agentsh detect
./agentsh detect --output json
./agentsh detect --output yaml
./agentsh detect config
./agentsh detect config --output /tmp/test-config.yaml
cat /tmp/test-config.yaml
```

**Step 3: Clean up**

```bash
rm -f /tmp/test-config.yaml
```

**Step 4: Final commit if any cleanup needed**

```bash
git status
# If clean, done. If changes, commit them.
```
