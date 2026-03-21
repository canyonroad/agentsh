# Detect Output Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace stub detections with real probes, group capabilities by protection domain, and compute a weighted score based on actual feature availability across all platforms.

**Architecture:** Add `ProtectionDomain` and `DetectedBackend` types to the detection result. Each platform's `Detect()` builds domains from its capability probes. The score is computed as the sum of domain weights where any backend is available. The flat `Capabilities` map is preserved for backward compatibility.

**Tech Stack:** Go, golang.org/x/sys/unix (Linux probes), golang.org/x/sys/windows (Windows probes)

**Spec:** `docs/superpowers/specs/2026-03-21-detect-redesign-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/capabilities/detect_result.go` | Modify | Add ProtectionDomain, DetectedBackend, ProbeResult types; new Table() format; weighted score |
| `internal/capabilities/detect_result_test.go` | Create | Score computation tests (all/none/4 partial combos), format tests (table + JSON), integration |
| `internal/capabilities/check.go` | Modify | Replace eBPF/cgroups stubs with real probes; wire SecurityCapabilities |
| `internal/capabilities/check_ebpf_linux.go` | Create | eBPF BPF_PROG_LOAD probe |
| `internal/capabilities/check_cgroups_linux.go` | Create | cgroups v2 statfs probe |
| `internal/capabilities/check_pidns_linux.go` | Create | PID namespace NSpid probe |
| `internal/capabilities/check_caps_linux.go` | Create | Capability drop capget+prctl probe |
| `internal/capabilities/check_test.go` | Modify | Tests for new probes |
| `internal/capabilities/detect_linux.go` | Modify | Build domains, weighted score, backward compat map |
| `internal/capabilities/detect_linux_test.go` | Modify | Update existing tests for new Domains field |
| `internal/capabilities/detect_darwin.go` | Modify | Build domains for Darwin |
| `internal/capabilities/detect_windows.go` | Modify | Build domains for Windows |
| `internal/capabilities/tips.go` | Modify | Generate tips from domains (only for 0-score domains); add lookupTip + tests |
| `internal/capabilities/security_caps.go` | Modify | Wire new probe functions, cache results on SecurityCapabilities |

---

### Task 1: Data Model — ProtectionDomain + DetectedBackend

**Files:**
- Modify: `internal/capabilities/detect_result.go`
- Create: `internal/capabilities/detect_result_test.go`

- [ ] **Step 1: Add new types to detect_result.go**

Add after the existing `Tip` struct (NOTE: `ProbeResult` goes here, not in check_ebpf_linux.go, since all probe files and detect_linux.go use it):

```go
// ProbeResult holds the result of a capability probe.
type ProbeResult struct {
	Available bool   `json:"available" yaml:"available"`
	Detail    string `json:"detail" yaml:"detail"`
}

// ProtectionDomain groups related security backends by what they protect.
type ProtectionDomain struct {
	Name     string            `json:"name" yaml:"name"`
	Weight   int               `json:"weight" yaml:"weight"`
	Score    int               `json:"score" yaml:"score"`
	Backends []DetectedBackend `json:"backends" yaml:"backends"`
	Active   string            `json:"active" yaml:"active"`
}

// DetectedBackend represents a single security mechanism within a domain.
type DetectedBackend struct {
	Name        string `json:"name" yaml:"name"`
	Available   bool   `json:"available" yaml:"available"`
	Detail      string `json:"detail" yaml:"detail"`
	Description string `json:"description" yaml:"description"`
	CheckMethod string `json:"check_method" yaml:"check_method"`
}

// Domain weight constants.
const (
	WeightFileProtection = 25
	WeightCommandControl = 25
	WeightNetwork        = 20
	WeightResourceLimits = 15
	WeightIsolation      = 15
)
```

Add `Domains` field to `DetectResult`:

```go
type DetectResult struct {
	Platform        string             `json:"platform" yaml:"platform"`
	SecurityMode    string             `json:"security_mode" yaml:"security_mode"`
	ProtectionScore int                `json:"protection_score" yaml:"protection_score"`
	Domains         []ProtectionDomain `json:"domains" yaml:"domains"`
	Capabilities    map[string]any     `json:"capabilities" yaml:"capabilities"`
	Summary         DetectSummary      `json:"summary" yaml:"summary"`
	Tips            []Tip              `json:"tips" yaml:"tips"`
}
```

Add score computation:

```go
// ComputeScore calculates the protection score from domain availability.
func ComputeScore(domains []ProtectionDomain) int {
	score := 0
	for i := range domains {
		hasAny := false
		for _, b := range domains[i].Backends {
			if b.Available {
				hasAny = true
				break
			}
		}
		if hasAny {
			domains[i].Score = domains[i].Weight
		} else {
			domains[i].Score = 0
		}
		score += domains[i].Score
	}
	return score
}
```

- [ ] **Step 2: Write tests**

Create `internal/capabilities/detect_result_test.go`:

```go
//go:build linux || darwin || windows

package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeScore_AllAvailable(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Command Control", Weight: 25, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Network", Weight: 20, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Resource Limits", Weight: 15, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Isolation", Weight: 15, Backends: []DetectedBackend{{Available: true}}},
	}
	assert.Equal(t, 100, ComputeScore(domains))
}

func TestComputeScore_NoneAvailable(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Command Control", Weight: 25, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Network", Weight: 20, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Resource Limits", Weight: 15, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Isolation", Weight: 15, Backends: []DetectedBackend{{Available: false}}},
	}
	assert.Equal(t, 0, ComputeScore(domains))
}

func TestComputeScore_Partial(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Backends: []DetectedBackend{
			{Name: "fuse", Available: false},
			{Name: "landlock", Available: true}, // one backend enough
		}},
		{Name: "Command Control", Weight: 25, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Network", Weight: 20, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Resource Limits", Weight: 15, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Isolation", Weight: 15, Backends: []DetectedBackend{{Available: true}}},
	}
	assert.Equal(t, 60, ComputeScore(domains)) // 25 + 20 + 15
}
```

- [ ] **Step 3: Build and test**

Run: `go build ./internal/capabilities/... && go test ./internal/capabilities/... -run TestComputeScore -v -count=1`

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/detect_result.go internal/capabilities/detect_result_test.go
git commit -m "feat(detect): add ProtectionDomain data model and weighted score computation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Linux Real Probes — eBPF, cgroups v2, PID namespace, capabilities

**Files:**
- Create: `internal/capabilities/check_ebpf_linux.go`
- Create: `internal/capabilities/check_cgroups_linux.go`
- Create: `internal/capabilities/check_pidns_linux.go`
- Create: `internal/capabilities/check_caps_linux.go`
- Modify: `internal/capabilities/check.go` (wire new probes)
- Modify: `internal/capabilities/security_caps.go` (use new probes)
- Modify: `internal/capabilities/check_test.go`

- [ ] **Step 1: Write probe test stubs**

In `check_test.go`, add:

```go
func TestProbeEBPF(t *testing.T) {
	result := probeEBPF()
	// Result depends on environment — just verify no panic and valid structure
	assert.NotEmpty(t, result.Detail)
}

func TestProbeCgroupsV2(t *testing.T) {
	result := probeCgroupsV2()
	assert.NotEmpty(t, result.Detail)
}

func TestProbePIDNamespace(t *testing.T) {
	result := probePIDNamespace()
	assert.NotEmpty(t, result.Detail)
}

func TestProbeCapabilityDrop(t *testing.T) {
	result := probeCapabilityDrop()
	assert.NotEmpty(t, result.Detail)
}
```

- [ ] **Step 2: Implement eBPF probe**

Create `check_ebpf_linux.go`:

```go
//go:build linux

package capabilities

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeEBPF checks if BPF cgroup_skb programs can be loaded.
func probeEBPF() ProbeResult {
	// Minimal BPF program: single BPF_EXIT instruction
	insn := [8]byte{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	license := [4]byte{'G', 'P', 'L', 0}

	// bpf_attr for BPF_PROG_LOAD
	type bpfProgLoadAttr struct {
		progType    uint32
		insnCnt     uint32
		insns       uint64
		license     uint64
		logLevel    uint32
		logSize     uint32
		logBuf      uint64
		kernVersion uint32
	}

	attr := bpfProgLoadAttr{
		progType: 13, // BPF_PROG_TYPE_CGROUP_SKB
		insnCnt:  1,
		insns:    uint64(uintptr(unsafe.Pointer(&insn[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}

	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		5, // BPF_PROG_LOAD
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno == 0 {
		unix.Close(int(fd))
		return ProbeResult{Available: true, Detail: "cgroup_skb"}
	}
	switch errno {
	case unix.EPERM:
		return ProbeResult{Available: false, Detail: "EPERM (missing CAP_BPF)"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (kernel too old)"}
	default:
		return ProbeResult{Available: false, Detail: errno.Error()}
	}
}
```

- [ ] **Step 3: Implement cgroups v2 probe**

Create `check_cgroups_linux.go`:

```go
//go:build linux

package capabilities

import (
	"os"

	"golang.org/x/sys/unix"
)

const cgroup2SuperMagic = 0x63677270

// probeCgroupsV2 checks if cgroups v2 is mounted and accessible.
func probeCgroupsV2() ProbeResult {
	var statfs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &statfs); err != nil {
		return ProbeResult{Available: false, Detail: "not mounted"}
	}
	if statfs.Type != cgroup2SuperMagic {
		return ProbeResult{Available: false, Detail: "cgroup v1"}
	}
	f, err := os.OpenFile("/sys/fs/cgroup/cgroup.procs", os.O_RDONLY, 0)
	if err != nil {
		return ProbeResult{Available: false, Detail: "not readable"}
	}
	f.Close()
	return ProbeResult{Available: true, Detail: "cgroup2"}
}
```

- [ ] **Step 4: Implement PID namespace probe**

Create `check_pidns_linux.go`:

```go
//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"strings"
)

// probePIDNamespace checks if the process is in a PID namespace.
func probePIDNamespace() ProbeResult {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ProbeResult{Available: false, Detail: "cannot read /proc/self/status"}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			levels := len(fields) - 1 // subtract "NSpid:" label
			if levels > 1 {
				return ProbeResult{Available: true, Detail: fmt.Sprintf("NSpid: %d levels", levels)}
			}
			return ProbeResult{Available: false, Detail: "host namespace"}
		}
	}
	return ProbeResult{Available: false, Detail: "NSpid not supported"}
}
```

- [ ] **Step 5: Implement capability drop probe**

Create `check_caps_linux.go`:

```go
//go:build linux

package capabilities

import "golang.org/x/sys/unix"

// probeCapabilityDrop checks if capabilities can be read and dropped.
func probeCapabilityDrop() ProbeResult {
	// NOTE: LINUX_CAPABILITY_VERSION_3 requires two CapUserData structs
	// (one per 32-bit word of capabilities). Using a single struct is a
	// known footgun — use an array of two.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return ProbeResult{Available: false, Detail: "capget failed: " + err.Error()}
	}
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, 0, 0, 0, 0, 0)
	if errno != 0 {
		return ProbeResult{Available: false, Detail: "prctl failed: " + errno.Error()}
	}
	return ProbeResult{Available: true, Detail: "capget+prctl"}
}
```

- [ ] **Step 6: Wire probes into check.go and security_caps.go**

In `check.go`, replace the stub implementations:

```go
func realCheckCgroupsV2() CheckResult {
	probe := probeCgroupsV2()
	return CheckResult{Feature: "cgroups-v2", Available: probe.Available}
}

func realCheckeBPF() CheckResult {
	probe := probeEBPF()
	return CheckResult{Feature: "ebpf", Available: probe.Available}
}
```

In `security_caps.go`, update `DetectSecurityCapabilities()` to run probes once and store results:

```go
// Run probes once and cache results on the struct
ebpfProbe := probeEBPF()
cgroupProbe := probeCgroupsV2()
pidnsProbe := probePIDNamespace()
capProbe := probeCapabilityDrop()

caps.EBPF = ebpfProbe.Available
caps.PIDNamespace = pidnsProbe.Available
caps.Capabilities = capProbe.Available
// Store ProbeResults for buildLinuxDomains to reuse (avoid double-probing)
caps.EBPFProbe = ebpfProbe
caps.CgroupProbe = cgroupProbe
caps.PIDNSProbe = pidnsProbe
caps.CapProbe = capProbe
```

Add corresponding `ProbeResult` fields to `SecurityCapabilities` struct. The `buildLinuxDomains` function should read these cached results instead of re-running probes.

And update `checkSeccompBasic()` if it's still a stub mirroring seccomp.

- [ ] **Step 7: Build and test**

Run: `go build ./internal/capabilities/... && go test ./internal/capabilities/... -run "TestProbe" -v -count=1`

- [ ] **Step 8: Commit**

```bash
git add internal/capabilities/check_ebpf_linux.go internal/capabilities/check_cgroups_linux.go internal/capabilities/check_pidns_linux.go internal/capabilities/check_caps_linux.go internal/capabilities/check.go internal/capabilities/security_caps.go internal/capabilities/check_test.go
git commit -m "feat(detect): replace stub probes with real eBPF/cgroups/pidns/caps detection

eBPF: BPF_PROG_LOAD with BPF_PROG_TYPE_CGROUP_SKB
cgroups v2: statfs + cgroup.procs readability
PID namespace: /proc/self/status NSpid field
Capabilities: capget + prctl(PR_CAPBSET_READ)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Linux Domain Builder — Build domains from SecurityCapabilities

**Files:**
- Modify: `internal/capabilities/detect_linux.go`

- [ ] **Step 1: Add buildLinuxDomains function**

```go
// buildLinuxDomains constructs protection domains from detected capabilities.
func buildLinuxDomains(caps *SecurityCapabilities) []ProtectionDomain {
	ebpfProbe := probeEBPF()
	cgroupProbe := probeCgroupsV2()
	pidnsProbe := probePIDNamespace()
	capProbe := probeCapabilityDrop()

	fuseMountMethod := "none"
	if caps.FUSE {
		if hasFusermount() {
			fuseMountMethod = "fusermount"
		} else if checkNewMountAPIAvailable() {
			fuseMountMethod = "new-api"
		} else {
			fuseMountMethod = "direct"
		}
	}

	landlockDetail := "not available"
	if caps.Landlock {
		landlockDetail = fmt.Sprintf("ABI v%d", caps.LandlockABI)
	}

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "fuse", Available: caps.FUSE, Detail: fuseMountMethod, Description: "file interception, soft-delete, redirect", CheckMethod: "probe"},
				{Name: "landlock", Available: caps.Landlock, Detail: landlockDetail, Description: "kernel path restrictions", CheckMethod: "syscall"},
				{Name: "seccomp-notify", Available: caps.Seccomp, Detail: "", Description: "openat/stat enforcement", CheckMethod: "probe"},
			},
			Active: caps.FileEnforcement,
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "seccomp-execve", Available: caps.Seccomp, Detail: "", Description: "execve interception", CheckMethod: "probe"},
				{Name: "ptrace", Available: caps.Ptrace, Detail: "", Description: "syscall tracing", CheckMethod: "probe"},
			},
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "ebpf", Available: ebpfProbe.Available, Detail: ebpfProbe.Detail, Description: "network monitoring", CheckMethod: "probe"},
				{Name: "landlock-network", Available: caps.LandlockNetwork, Detail: "", Description: "TCP bind/connect filtering", CheckMethod: "syscall"},
			},
		},
		{
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "cgroups-v2", Available: cgroupProbe.Available, Detail: cgroupProbe.Detail, Description: "CPU/memory/process limits", CheckMethod: "probe"},
			},
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "pid-namespace", Available: pidnsProbe.Available, Detail: pidnsProbe.Detail, Description: "process isolation", CheckMethod: "probe"},
				{Name: "capability-drop", Available: capProbe.Available, Detail: capProbe.Detail, Description: "privilege reduction", CheckMethod: "probe"},
			},
		},
	}
}
```

- [ ] **Step 2: Update Detect() to use domains and weighted score**

Replace the `Detect()` function body to:
1. Call `buildLinuxDomains(secCaps)`
2. Call `ComputeScore(domains)` instead of `modeToScore`
3. Build the backward compat `caps` map from domains
4. Still use `SelectMode()` for `SecurityMode`

```go
func Detect() (*DetectResult, error) {
	secCaps := DetectSecurityCapabilities()
	secCaps.FileEnforcement = detectFileEnforcementBackend(secCaps)

	domains := buildLinuxDomains(secCaps)
	score := ComputeScore(domains)
	mode := secCaps.SelectMode()

	// Backward compat: populate flat capabilities map from domains
	caps := backwardCompatCaps(secCaps, domains)

	// Build summary from domains
	var available, unavailable []string
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Available {
				available = append(available, b.Name)
			} else {
				unavailable = append(unavailable, b.Name)
			}
		}
	}

	tips := GenerateTipsFromDomains(domains)

	return &DetectResult{
		Platform:        "linux",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
	}, nil
}

// backwardCompatCaps builds the flat capabilities map for JSON backward compat.
func backwardCompatCaps(caps *SecurityCapabilities, domains []ProtectionDomain) map[string]any {
	m := map[string]any{
		"seccomp":             caps.Seccomp,
		"seccomp_user_notify": caps.Seccomp,
		"seccomp_basic":       caps.SeccompBasic,
		"landlock":            caps.Landlock,
		"landlock_abi":        caps.LandlockABI,
		"landlock_network":    caps.LandlockNetwork,
		"fuse":                caps.FUSE,
		"ptrace":              caps.Ptrace,
		"file_enforcement":    caps.FileEnforcement,
	}
	// Add probe-based values from domains
	for _, d := range domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "ebpf":
				m["ebpf"] = b.Available
			case "cgroups-v2":
				m["cgroups_v2"] = b.Available
			case "pid-namespace":
				m["pid_namespace"] = b.Available
			case "capability-drop":
				m["capabilities_drop"] = b.Available
			}
		}
	}
	// FUSE mount method
	for _, b := range domains[0].Backends {
		if b.Name == "fuse" && b.Available {
			m["fuse_mount_method"] = b.Detail
		}
	}
	return m
}
```

Remove the old `modeToScore()` function.

- [ ] **Step 3: Build and test**

Run: `go build ./internal/capabilities/... && go test ./internal/capabilities/... -v -count=1`

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/detect_linux.go
git commit -m "feat(detect): build Linux domains with weighted score and backward compat

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Output Formatting — Grouped table

**Files:**
- Modify: `internal/capabilities/detect_result.go` (Table method)
- Modify: `internal/capabilities/detect_result_test.go`

- [ ] **Step 1: Replace Table() method**

```go
func (r *DetectResult) Table() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Platform:         %s\n", r.Platform))
	sb.WriteString(fmt.Sprintf("Security Mode:    %s\n", r.SecurityMode))
	sb.WriteString(fmt.Sprintf("Protection Score: %d/100\n", r.ProtectionScore))
	sb.WriteString("\n")

	for _, d := range r.Domains {
		sb.WriteString(fmt.Sprintf("%-40s %d/%d\n", strings.ToUpper(d.Name), d.Score, d.Weight))
		for _, b := range d.Backends {
			status := "-"
			if b.Available {
				status = "✓"
			}
			detail := b.Detail
			if detail == "" {
				detail = " "
			}
			sb.WriteString(fmt.Sprintf("  %-20s %s  %-16s %s\n", b.Name, status, detail, b.Description))
		}
		if d.Active != "" && d.Active != "none" {
			sb.WriteString(fmt.Sprintf("  active backend:    %s\n", d.Active))
		}
		sb.WriteString("\n")
	}

	if len(r.Tips) > 0 {
		sb.WriteString("TIPS\n")
		for _, tip := range r.Tips {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", tip.Feature, tip.Impact))
			sb.WriteString(fmt.Sprintf("    -> %s\n", tip.Action))
		}
	}

	sb.WriteString("\nRun 'agentsh detect config' to generate an optimized configuration.\n")
	return sb.String()
}
```

- [ ] **Step 2: Add format test**

```go
func TestTableFormat_Grouped(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "full",
		ProtectionScore: 85,
		Domains: []ProtectionDomain{
			{Name: "File Protection", Weight: 25, Score: 25, Backends: []DetectedBackend{
				{Name: "fuse", Available: true, Detail: "fusermount3", Description: "file interception"},
			}, Active: "fuse"},
		},
	}
	table := result.Table()
	assert.Contains(t, table, "FILE PROTECTION")
	assert.Contains(t, table, "25/25")
	assert.Contains(t, table, "fuse")
	assert.Contains(t, table, "✓")
	assert.Contains(t, table, "active backend:")
}
```

- [ ] **Step 3: Build and test**

Run: `go test ./internal/capabilities/... -run TestTableFormat -v -count=1`

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/detect_result.go internal/capabilities/detect_result_test.go
git commit -m "feat(detect): grouped domain table output

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Tips — Generate from domains

**Files:**
- Modify: `internal/capabilities/tips.go`

- [ ] **Step 1: Add GenerateTipsFromDomains**

```go
// GenerateTipsFromDomains generates tips only for domains that score 0.
func GenerateTipsFromDomains(domains []ProtectionDomain) []Tip {
	var tips []Tip
	for _, d := range domains {
		if d.Score > 0 {
			continue // domain already covered
		}
		for _, b := range d.Backends {
			if b.Available {
				continue
			}
			tip := lookupTip(b.Name)
			if tip != nil {
				tip.Impact = fmt.Sprintf("%s (+%d pts)", tip.Impact, d.Weight)
				tips = append(tips, *tip)
			}
		}
	}
	return tips
}
```

Add a `lookupTip(backendName string) *Tip` helper that maps backend names to tip definitions, combining the existing platform tip lists.

- [ ] **Step 2: Build and test**

Run: `go build ./internal/capabilities/... && go test ./internal/capabilities/... -v -count=1`

- [ ] **Step 3: Commit**

```bash
git add internal/capabilities/tips.go
git commit -m "feat(detect): generate tips from domains with point impact

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Darwin + Windows — Domain builders

**Files:**
- Modify: `internal/capabilities/detect_darwin.go`
- Modify: `internal/capabilities/detect_windows.go`

- [ ] **Step 1: Darwin domain builder**

Add `buildDarwinDomains(caps map[string]any)` that maps the existing Darwin checks into the five protection domains. Use `CheckMethod: "binary"` for file checks and `CheckMethod: "entitlement"` for ESF/NetworkExtension stubs.

Update `Detect()` to build domains, compute weighted score, populate backward compat caps.

- [ ] **Step 2: Windows domain builder**

Same pattern for Windows: `buildWindowsDomains(caps map[string]any)`.

- [ ] **Step 3: Build and test**

Run: `go build ./... && GOOS=darwin go build ./internal/capabilities/... && GOOS=windows go build ./internal/capabilities/...`

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/detect_darwin.go internal/capabilities/detect_windows.go
git commit -m "feat(detect): add domain builders for Darwin and Windows

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Full build + cross-compile + test

- [ ] **Step 1: Full build**

Run: `go build ./...`

- [ ] **Step 2: Cross-compile**

Run: `GOOS=windows go build ./... && GOOS=darwin go build ./internal/capabilities/...`

- [ ] **Step 3: Full test suite**

Run: `go test ./...`

- [ ] **Step 4: Run detect manually**

Run: `go run ./cmd/agentsh detect` and verify the new grouped output.

- [ ] **Step 5: Commit any fixups**

---

## Implementation Notes

These apply across all tasks — implementers should follow these:

1. **`ProbeResult` type lives in `detect_result.go`** (not in individual probe files) since all probe files and `detect_linux.go` depend on it.

2. **Avoid double-probing**: `DetectSecurityCapabilities()` runs probes and caches `ProbeResult` values on the `SecurityCapabilities` struct. `buildLinuxDomains` reads cached results — never re-runs probes.

3. **Capget requires two structs**: `LINUX_CAPABILITY_VERSION_3` uses 64-bit capability masks split across two `CapUserData` structs. Use `var data [2]unix.CapUserData` and pass `&data[0]`.

4. **`Active` field**: Set for all five domains, not just File Protection. Derive from: File→`FileEnforcement`, Command→`SelectMode()` result, Network→first available backend, Resource→`"cgroups-v2"` if available, Isolation→first available backend.

5. **Existing tests need updates**: `TestDetectResult_Table` checks for the old flat "CAPABILITIES" header. `TestDetect_Linux` asserts `capabilities_drop: true` which may now fail. Update both in the task that changes their file.

6. **`lookupTip` mapping**: Backend names use hyphens (`"cgroups-v2"`, `"pid-namespace"`) but existing tip CheckKeys use underscores (`"cgroups_v2"`). The `lookupTip` helper must map between them. Add tip definitions for new backends that have no existing tip (`"capability-drop"`, `"pid-namespace"`, `"seccomp-execve"`, `"seccomp-notify"`, `"landlock-network"`).

7. **`GenerateTipsFromDomains` needs a test**: Add `TestGenerateTipsFromDomains` verifying: tips generated for 0-score domains only, no tips for domains with any available backend, point impact text included.

8. **Darwin/Windows domain builders**: Must replace `GenerateTips("darwin", caps)` with `GenerateTipsFromDomains(domains)`. Provide concrete domain mappings (which existing check functions map to which backends in which domains). The implementer should read the existing `detect_darwin.go` and `detect_windows.go` functions and map them.

9. **JSON backward compat test**: Add `TestJSONFormat_Domains` verifying both `domains` (new) and `capabilities` (old) fields are present in JSON output.

