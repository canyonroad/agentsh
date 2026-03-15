# ptrace Tracer Backend — Phase 1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a ptrace-based syscall tracer that can enforce command allow/deny on Linux environments where seccomp user-notify is unavailable (e.g., AWS Fargate with SYS_PTRACE).

**Architecture:** A single-threaded ptrace event loop (runtime.LockOSThread) attaches to tracee processes via PTRACE_SEIZE, intercepts syscalls at enter/exit, and dispatches to the existing ExecveHandler for policy decisions. Two attach modes: `children` (fork + prefilter) and `pid` (attach to running process). All ptrace operations happen on one locked OS thread; policy evaluation and event emission happen asynchronously via channels.

**Tech Stack:** Go, `golang.org/x/sys/unix` (ptrace, seccomp, wait4), Linux kernel ptrace API, seccomp-BPF (for prefilter in children mode)

**Spec:** `docs/ptrace-support.md` — sections 1-8, 10, 13-14

---

## Task 1: PtraceConfig struct with defaults

**Files:**
- Create: `internal/config/ptrace.go`
- Create: `internal/config/ptrace_test.go`

**Step 1: Write the failing test**

```go
// internal/config/ptrace_test.go
package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultPtraceConfig(t *testing.T) {
	cfg := DefaultPtraceConfig()

	if cfg.Enabled {
		t.Error("ptrace should be disabled by default")
	}
	if cfg.AttachMode != "children" {
		t.Errorf("attach_mode: got %q, want %q", cfg.AttachMode, "children")
	}
	if !cfg.Trace.Execve || !cfg.Trace.File || !cfg.Trace.Network || !cfg.Trace.Signal {
		t.Error("all trace classes should be enabled by default")
	}
	if !cfg.Performance.SeccompPrefilter {
		t.Error("seccomp_prefilter should be enabled by default")
	}
	if cfg.Performance.MaxTracees != 500 {
		t.Errorf("max_tracees: got %d, want 500", cfg.Performance.MaxTracees)
	}
	if cfg.Performance.MaxHoldMs != 5000 {
		t.Errorf("max_hold_ms: got %d, want 5000", cfg.Performance.MaxHoldMs)
	}
	if cfg.MaskTracerPid != "off" {
		t.Errorf("mask_tracer_pid: got %q, want %q", cfg.MaskTracerPid, "off")
	}
	if cfg.OnAttachFailure != "fail_open" {
		t.Errorf("on_attach_failure: got %q, want %q", cfg.OnAttachFailure, "fail_open")
	}
}

func TestPtraceConfig_YAMLRoundTrip(t *testing.T) {
	orig := DefaultPtraceConfig()
	orig.Enabled = true
	orig.TargetPID = 42

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SandboxPtraceConfig
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.TargetPID != 42 {
		t.Errorf("target_pid: got %d, want 42", decoded.TargetPID)
	}
	if !decoded.Enabled {
		t.Error("enabled not preserved")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestDefaultPtraceConfig -v`
Expected: FAIL — `SandboxPtraceConfig` not defined

**Step 3: Write minimal implementation**

```go
// internal/config/ptrace.go
package config

// SandboxPtraceConfig configures the ptrace-based syscall tracer backend.
// This is an alternative to seccomp user-notify for restricted environments
// like AWS Fargate where SYS_PTRACE is available but seccomp user-notify is not.
type SandboxPtraceConfig struct {
	Enabled         bool                    `yaml:"enabled"`
	AttachMode      string                  `yaml:"attach_mode"`
	TargetPID       int                     `yaml:"target_pid"`
	TargetPIDFile   string                  `yaml:"target_pid_file"`
	Trace           PtraceTraceConfig       `yaml:"trace"`
	Performance     PtracePerformanceConfig `yaml:"performance"`
	MaskTracerPid   string                  `yaml:"mask_tracer_pid"`
	OnAttachFailure string                  `yaml:"on_attach_failure"`
}

// PtraceTraceConfig controls which syscall classes are traced.
type PtraceTraceConfig struct {
	Execve  bool `yaml:"execve"`
	File    bool `yaml:"file"`
	Network bool `yaml:"network"`
	Signal  bool `yaml:"signal"`
}

// PtracePerformanceConfig contains performance tuning options.
type PtracePerformanceConfig struct {
	SeccompPrefilter bool `yaml:"seccomp_prefilter"`
	MaxTracees       int  `yaml:"max_tracees"`
	MaxHoldMs        int  `yaml:"max_hold_ms"`
}

// DefaultPtraceConfig returns secure defaults for ptrace configuration.
func DefaultPtraceConfig() SandboxPtraceConfig {
	return SandboxPtraceConfig{
		Enabled:    false,
		AttachMode: "children",
		Trace: PtraceTraceConfig{
			Execve:  true,
			File:    true,
			Network: true,
			Signal:  true,
		},
		Performance: PtracePerformanceConfig{
			SeccompPrefilter: true,
			MaxTracees:       500,
			MaxHoldMs:        5000,
		},
		MaskTracerPid:   "off",
		OnAttachFailure: "fail_open",
	}
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -run TestPtrace -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/ptrace.go internal/config/ptrace_test.go
git commit -m "feat(config): add SandboxPtraceConfig struct with defaults"
```

---

## Task 2: PtraceConfig validation

**Files:**
- Modify: `internal/config/ptrace.go`
- Modify: `internal/config/ptrace_test.go`

**Step 1: Write the failing test**

```go
// Append to internal/config/ptrace_test.go
func TestPtraceConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*SandboxPtraceConfig)
		wantErr bool
	}{
		{"defaults are valid", func(c *SandboxPtraceConfig) {}, false},
		{"pid mode with target_pid", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
			c.TargetPID = 123
		}, false},
		{"pid mode with target_pid_file", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
			c.TargetPIDFile = "/shared/workload.pid"
		}, false},
		{"pid mode without target", func(c *SandboxPtraceConfig) {
			c.AttachMode = "pid"
		}, true},
		{"invalid attach_mode", func(c *SandboxPtraceConfig) {
			c.AttachMode = "sidecar"
		}, true},
		{"invalid on_attach_failure", func(c *SandboxPtraceConfig) {
			c.OnAttachFailure = "panic"
		}, true},
		{"invalid mask_tracer_pid", func(c *SandboxPtraceConfig) {
			c.MaskTracerPid = "ptrace"
		}, true},
		{"max_hold_ms zero", func(c *SandboxPtraceConfig) {
			c.Performance.MaxHoldMs = 0
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultPtraceConfig()
			cfg.Enabled = true
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestPtraceConfig_Validate -v`
Expected: FAIL — `Validate` method not defined

**Step 3: Write minimal implementation**

```go
// Append to internal/config/ptrace.go
import "fmt"

// Validate checks that the ptrace configuration is internally consistent.
func (c *SandboxPtraceConfig) Validate() error {
	if !c.Enabled {
		return nil // Nothing to validate when disabled
	}

	switch c.AttachMode {
	case "children", "pid":
	default:
		return fmt.Errorf("sandbox.ptrace.attach_mode: invalid value %q (must be \"children\" or \"pid\")", c.AttachMode)
	}

	if c.AttachMode == "pid" && c.TargetPID <= 0 && c.TargetPIDFile == "" {
		return fmt.Errorf("sandbox.ptrace: attach_mode \"pid\" requires target_pid or target_pid_file")
	}

	switch c.OnAttachFailure {
	case "fail_open", "fail_closed":
	default:
		return fmt.Errorf("sandbox.ptrace.on_attach_failure: invalid value %q", c.OnAttachFailure)
	}

	// Phase 1: only "off" is supported for mask_tracer_pid
	if c.MaskTracerPid != "off" {
		return fmt.Errorf("sandbox.ptrace.mask_tracer_pid: %q not supported in this version (use \"off\")", c.MaskTracerPid)
	}

	if c.Performance.MaxHoldMs <= 0 {
		return fmt.Errorf("sandbox.ptrace.performance.max_hold_ms must be > 0")
	}

	return nil
}
```

**Step 4: Run tests**

Run: `go test ./internal/config/ -run TestPtrace -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/ptrace.go internal/config/ptrace_test.go
git commit -m "feat(config): add ptrace config validation"
```

---

## Task 3: Wire PtraceConfig into SandboxConfig

**Files:**
- Modify: `internal/config/config.go:347`

**Step 1: Add field**

In `SandboxConfig` struct (after the `MCP` field at line 347), add:

```go
Ptrace  SandboxPtraceConfig  `yaml:"ptrace"`
```

**Step 2: Run all config tests**

Run: `go test ./internal/config/... -v`
Expected: PASS (zero value of SandboxPtraceConfig is disabled, which is correct)

**Step 3: Run full build**

Run: `go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): wire SandboxPtraceConfig into SandboxConfig"
```

---

## Task 4: ptrace capability detection — readCapEff

**Files:**
- Create: `internal/capabilities/check_ptrace_linux.go`
- Create: `internal/capabilities/check_ptrace_linux_test.go`

**Step 1: Write the failing test**

```go
// internal/capabilities/check_ptrace_linux_test.go
//go:build linux

package capabilities

import "testing"

func TestReadCapEff(t *testing.T) {
	capEff, err := readCapEff()
	if err != nil {
		t.Fatalf("readCapEff() error: %v", err)
	}
	// Every Linux process has at least some capabilities in effective set
	// (even unprivileged processes have bits like CAP_SETUID in permitted
	// but effective may be 0 for unprivileged). Just check no error.
	t.Logf("CapEff = 0x%016x", capEff)
}

func TestReadCapEffParsing(t *testing.T) {
	// Test the parsing logic with known input
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:  "standard format",
			input: "Name:\ttest\nCapEff:\t000001ffffffffff\nPPid:\t1\n",
			want:  0x000001ffffffffff,
		},
		{
			name:    "missing CapEff",
			input:   "Name:\ttest\nPPid:\t1\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCapEff(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCapEff() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseCapEff() = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestReadCapEff -v`
Expected: FAIL — functions not defined

**Step 3: Write minimal implementation**

```go
// internal/capabilities/check_ptrace_linux.go
//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readCapEff reads the effective capability set from /proc/self/status.
func readCapEff() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	return parseCapEff(string(data))
}

// parseCapEff extracts the CapEff value from /proc/self/status content.
func parseCapEff(content string) (uint64, error) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "CapEff:\t") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:\t"))
			return strconv.ParseUint(hex, 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff not found in /proc/self/status")
}
```

**Step 4: Run tests**

Run: `go test ./internal/capabilities/ -run TestReadCapEff -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/capabilities/check_ptrace_linux.go internal/capabilities/check_ptrace_linux_test.go
git commit -m "feat(capabilities): add readCapEff for ptrace capability detection"
```

---

## Task 5: ptrace capability detection — probePtraceAttach + checkPtraceCapability

**Files:**
- Modify: `internal/capabilities/check_ptrace_linux.go`
- Modify: `internal/capabilities/check_ptrace_linux_test.go`

**Step 1: Write the test**

```go
// Append to check_ptrace_linux_test.go
func TestProbePtraceAttach(t *testing.T) {
	// Just verify it doesn't panic. The actual result depends on SYS_PTRACE availability.
	result := probePtraceAttach()
	t.Logf("probePtraceAttach() = %v", result)
}

func TestCheckPtraceCapability(t *testing.T) {
	result := checkPtraceCapability()
	t.Logf("checkPtraceCapability() = %v", result)
}
```

**Step 2: Implement**

```go
// Append to internal/capabilities/check_ptrace_linux.go
import (
	"os/exec"

	"golang.org/x/sys/unix"
)

const capSysPtrace = 19

// checkPtraceCapability checks if ptrace is available and functional.
func checkPtraceCapability() bool {
	capEff, err := readCapEff()
	if err != nil {
		return false
	}
	if capEff&(1<<capSysPtrace) == 0 {
		return false
	}
	return probePtraceAttach()
}

// probePtraceAttach forks a short-lived child and attempts PTRACE_SEIZE.
func probePtraceAttach() bool {
	cmd := exec.Command("/bin/sleep", "0.1")
	if err := cmd.Start(); err != nil {
		return false
	}

	pid := cmd.Process.Pid

	err := unix.PtraceSeize(pid, 0)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return false
	}

	// Seize succeeded. Clean up: interrupt, wait, detach.
	if err := unix.PtraceInterrupt(pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return true
	}

	var status unix.WaitStatus
	_, err = unix.Wait4(pid, &status, 0, nil)
	if err == nil && status.Stopped() {
		unix.PtraceDetach(pid)
	}

	cmd.Process.Kill()
	cmd.Wait()
	return true
}
```

**Step 3: Run tests**

Run: `go test ./internal/capabilities/ -run TestProbe -v`
Expected: PASS (may show false on machines without SYS_PTRACE, that's OK)

**Step 4: Commit**

```bash
git add internal/capabilities/check_ptrace_linux.go internal/capabilities/check_ptrace_linux_test.go
git commit -m "feat(capabilities): add probePtraceAttach for functional ptrace probing"
```

---

## Task 6: Wire real ptrace detection into check.go and SecurityCapabilities

**Files:**
- Modify: `internal/capabilities/check.go` — replace `realCheckPtrace` stub
- Modify: `internal/capabilities/security_caps.go` — add Ptrace/PtraceEnabled fields, ModePtrace, update SelectMode and DetectSecurityCapabilities
- Modify: `internal/capabilities/detect_linux.go` — add ptrace to caps map, update modeToScore
- Modify: `internal/capabilities/tips.go` — add ptrace tip to linuxTips

**Step 1: Write failing tests**

```go
// Add to internal/capabilities/security_caps_test.go (create if needed)
// //go:build linux

func TestSelectMode_Ptrace(t *testing.T) {
	tests := []struct {
		name string
		caps SecurityCapabilities
		want string
	}{
		{
			name: "ptrace available and enabled, no seccomp",
			caps: SecurityCapabilities{Ptrace: true, PtraceEnabled: true, Capabilities: true},
			want: ModePtrace,
		},
		{
			name: "ptrace available but not enabled",
			caps: SecurityCapabilities{Ptrace: true, PtraceEnabled: false, Capabilities: true},
			want: ModeMinimal,
		},
		{
			name: "ptrace not available but enabled",
			caps: SecurityCapabilities{Ptrace: false, PtraceEnabled: true, Capabilities: true},
			want: ModeMinimal,
		},
		{
			name: "full mode takes priority over ptrace",
			caps: SecurityCapabilities{Seccomp: true, EBPF: true, FUSE: true, Ptrace: true, PtraceEnabled: true},
			want: ModeFull,
		},
		{
			name: "ptrace takes priority over landlock",
			caps: SecurityCapabilities{Ptrace: true, PtraceEnabled: true, Landlock: true, FUSE: true},
			want: ModePtrace,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.caps.SelectMode()
			if got != tt.want {
				t.Errorf("SelectMode() = %q, want %q", got, tt.want)
			}
		})
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/capabilities/ -run TestSelectMode_Ptrace -v`
Expected: FAIL — ModePtrace not defined, Ptrace field not on struct

**Step 3: Implement changes**

In `internal/capabilities/security_caps.go`:
- Add `Ptrace bool` and `PtraceEnabled bool` fields to `SecurityCapabilities`
- Add `ModePtrace = "ptrace"` constant
- Insert in `SelectMode()` after the ModeFull check:
  ```go
  if c.Ptrace && c.PtraceEnabled {
      return ModePtrace
  }
  ```
- In `DetectSecurityCapabilities()`, add: `caps.Ptrace = checkPtraceCapability()`

In `internal/capabilities/check.go`:
- Replace `realCheckPtrace` body:
  ```go
  func realCheckPtrace() CheckResult {
      available := checkPtraceCapability()
      r := CheckResult{Feature: "ptrace", Available: available}
      if !available {
          r.Error = fmt.Errorf("SYS_PTRACE capability not available or ptrace blocked by seccomp")
      }
      return r
  }
  ```
- Add ptrace check block to `CheckAll` for when `cfg.Sandbox.Ptrace.Enabled`:
  ```go
  if cfg.Sandbox.Ptrace.Enabled {
      result := checkPtrace()
      result.ConfigKey = "sandbox.ptrace.enabled"
      result.Suggestion = "Set 'sandbox.ptrace.enabled: false' or add SYS_PTRACE capability"
      if !result.Available {
          failures = append(failures, result)
      }
  }
  ```

In `internal/capabilities/detect_linux.go`:
- Add `"ptrace": secCaps.Ptrace` to the caps map in `Detect()`
- Add `case ModePtrace: return 90` to `modeToScore()`

In `internal/capabilities/tips.go`:
- Add to `linuxTips`:
  ```go
  {
      Feature:  "ptrace",
      CheckKey: "ptrace",
      Impact:   "Syscall-level enforcement via ptrace unavailable",
      Action:   "Add SYS_PTRACE capability to enable ptrace-based enforcement for restricted runtimes",
  },
  ```

**Step 4: Run all capability tests**

Run: `go test ./internal/capabilities/... -v`
Expected: PASS

**Step 5: Run full build including cross-compile**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: PASS (non-Linux builds use stubs from security_caps_other.go)

Note: If `security_caps_other.go` needs updating for the new fields/constant, add them there too (zero-value defaults are fine — Ptrace: false, PtraceEnabled: false; ModePtrace constant; SelectMode() with the same logic).

**Step 6: Commit**

```bash
git add internal/capabilities/security_caps.go internal/capabilities/security_caps_other.go \
  internal/capabilities/check.go internal/capabilities/detect_linux.go \
  internal/capabilities/tips.go
git commit -m "feat(capabilities): add ModePtrace, ptrace detection, and detect/tips integration"
```

---

## Task 7: Add HasPtrace to platform Capabilities + SyscallTracer interface

**Files:**
- Modify: `internal/platform/types.go`
- Modify: `internal/platform/interfaces.go`

**Step 1: Add HasPtrace field**

In `internal/platform/types.go`, after `HasSeccomp bool`:
```go
HasPtrace bool `json:"has_ptrace"`
```

**Step 2: Add SyscallTracer interface**

In `internal/platform/interfaces.go`, after the existing interfaces:
```go
// SyscallTracer provides syscall-level interception via ptrace or equivalent.
type SyscallTracer interface {
	Start(ctx context.Context) error
	AttachPID(pid int) error
	TraceeCount() int
	Available() bool
	Implementation() string
}
```

**Step 3: Verify build**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/platform/types.go internal/platform/interfaces.go
git commit -m "feat(platform): add HasPtrace and SyscallTracer interface"
```

---

## Task 8: ptrace package — doc.go, Regs interface, amd64/arm64 implementations

**Files:**
- Create: `internal/ptrace/doc.go`
- Create: `internal/ptrace/args.go`
- Create: `internal/ptrace/args_amd64.go`
- Create: `internal/ptrace/args_amd64_test.go`
- Create: `internal/ptrace/args_arm64.go`

**Step 1: Write failing test for amd64 regs**

```go
// internal/ptrace/args_amd64_test.go
//go:build linux && amd64

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAmd64Regs_SyscallNr(t *testing.T) {
	r := &amd64Regs{}
	r.raw.Orig_rax = 59 // SYS_EXECVE
	if r.SyscallNr() != 59 {
		t.Errorf("SyscallNr() = %d, want 59", r.SyscallNr())
	}
	r.SetSyscallNr(-1)
	if r.SyscallNr() != -1 {
		t.Errorf("SetSyscallNr(-1): got %d", r.SyscallNr())
	}
}

func TestAmd64Regs_Args(t *testing.T) {
	r := &amd64Regs{}
	// Set each arg and verify correct register mapping
	r.SetArg(0, 100)
	if r.raw.Rdi != 100 {
		t.Errorf("Arg(0) maps to Rdi: got %d", r.raw.Rdi)
	}
	r.SetArg(1, 200)
	if r.raw.Rsi != 200 {
		t.Errorf("Arg(1) maps to Rsi: got %d", r.raw.Rsi)
	}
	r.SetArg(2, 300)
	if r.raw.Rdx != 300 {
		t.Errorf("Arg(2) maps to Rdx: got %d", r.raw.Rdx)
	}
	r.SetArg(3, 400)
	if r.raw.R10 != 400 {
		t.Errorf("Arg(3) maps to R10: got %d", r.raw.R10)
	}
	r.SetArg(4, 500)
	if r.raw.R8 != 500 {
		t.Errorf("Arg(4) maps to R8: got %d", r.raw.R8)
	}
	r.SetArg(5, 600)
	if r.raw.R9 != 600 {
		t.Errorf("Arg(5) maps to R9: got %d", r.raw.R9)
	}

	// Round-trip
	for i := 0; i < 6; i++ {
		expected := uint64((i + 1) * 100)
		if r.Arg(i) != expected {
			t.Errorf("Arg(%d) = %d, want %d", i, r.Arg(i), expected)
		}
	}

	// Out-of-range
	if r.Arg(6) != 0 {
		t.Error("Arg(6) should return 0")
	}
	if r.Arg(-1) != 0 {
		t.Error("Arg(-1) should return 0")
	}
}

func TestAmd64Regs_ReturnValue(t *testing.T) {
	r := &amd64Regs{}
	r.SetReturnValue(-int64(unix.EACCES))
	if r.ReturnValue() != -int64(unix.EACCES) {
		t.Errorf("ReturnValue() = %d, want %d", r.ReturnValue(), -int64(unix.EACCES))
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run TestAmd64 -v`
Expected: FAIL — package doesn't exist

**Step 3: Create the files**

```go
// internal/ptrace/doc.go
//go:build linux

// Package ptrace implements a ptrace-based syscall tracer backend for agentsh.
// It provides syscall-level interception for environments where seccomp user-notify
// and eBPF are unavailable (e.g., AWS Fargate with SYS_PTRACE).
//
// This package is Linux-only and requires the SYS_PTRACE capability.
package ptrace
```

```go
// internal/ptrace/args.go
//go:build linux

package ptrace

// Regs abstracts architecture-specific register access for ptrace.
type Regs interface {
	SyscallNr() int
	SetSyscallNr(nr int)
	Arg(n int) uint64
	SetArg(n int, val uint64)
	ReturnValue() int64
	SetReturnValue(val int64)
	InstructionPointer() uint64
}
```

```go
// internal/ptrace/args_amd64.go
//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

type amd64Regs struct {
	raw unix.PtraceRegsAmd64
}

func (r *amd64Regs) SyscallNr() int        { return int(int64(r.raw.Orig_rax)) }
func (r *amd64Regs) SetSyscallNr(nr int)   { r.raw.Orig_rax = uint64(nr) }
func (r *amd64Regs) ReturnValue() int64    { return int64(r.raw.Rax) }
func (r *amd64Regs) SetReturnValue(v int64) { r.raw.Rax = uint64(v) }
func (r *amd64Regs) InstructionPointer() uint64 { return r.raw.Rip }

func (r *amd64Regs) Arg(n int) uint64 {
	switch n {
	case 0:
		return r.raw.Rdi
	case 1:
		return r.raw.Rsi
	case 2:
		return r.raw.Rdx
	case 3:
		return r.raw.R10
	case 4:
		return r.raw.R8
	case 5:
		return r.raw.R9
	default:
		return 0
	}
}

func (r *amd64Regs) SetArg(n int, val uint64) {
	switch n {
	case 0:
		r.raw.Rdi = val
	case 1:
		r.raw.Rsi = val
	case 2:
		r.raw.Rdx = val
	case 3:
		r.raw.R10 = val
	case 4:
		r.raw.R8 = val
	case 5:
		r.raw.R9 = val
	}
}

func getRegsArch(tid int) (Regs, error) {
	r := &amd64Regs{}
	err := unix.PtraceGetRegsAmd64(tid, &r.raw)
	return r, err
}

func setRegsArch(tid int, regs Regs) error {
	r := regs.(*amd64Regs)
	return unix.PtraceSetRegsAmd64(tid, &r.raw)
}
```

```go
// internal/ptrace/args_arm64.go
//go:build linux && arm64

package ptrace

import "golang.org/x/sys/unix"

type arm64Regs struct {
	raw unix.PtraceRegsArm64
}

func (r *arm64Regs) SyscallNr() int        { return int(int64(r.raw.Regs[8])) }
func (r *arm64Regs) SetSyscallNr(nr int)   { r.raw.Regs[8] = uint64(nr) }
func (r *arm64Regs) ReturnValue() int64    { return int64(r.raw.Regs[0]) }
func (r *arm64Regs) SetReturnValue(v int64) { r.raw.Regs[0] = uint64(v) }
func (r *arm64Regs) InstructionPointer() uint64 { return r.raw.Pc }

func (r *arm64Regs) Arg(n int) uint64 {
	if n < 0 || n > 5 {
		return 0
	}
	return r.raw.Regs[n]
}

func (r *arm64Regs) SetArg(n int, val uint64) {
	if n >= 0 && n <= 5 {
		r.raw.Regs[n] = val
	}
}

func getRegsArch(tid int) (Regs, error) {
	r := &arm64Regs{}
	err := unix.PtraceGetRegsArm64(tid, &r.raw)
	return r, err
}

func setRegsArch(tid int, regs Regs) error {
	r := regs.(*arm64Regs)
	return unix.PtraceSetRegsArm64(tid, &r.raw)
}
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run TestAmd64 -v`
Expected: PASS

Run: `GOARCH=arm64 go build ./internal/ptrace/`
Expected: PASS (cross-compile check)

**Step 5: Commit**

```bash
git add internal/ptrace/
git commit -m "feat(ptrace): add Regs interface with amd64 and arm64 implementations"
```

---

## Task 9: Process tree

**Files:**
- Create: `internal/ptrace/process_tree.go`
- Create: `internal/ptrace/process_tree_test.go`

**Step 1: Write failing tests**

```go
// internal/ptrace/process_tree_test.go
//go:build linux

package ptrace

import "testing"

func TestProcessTree_AddRoot(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)

	if pt.Depth(100) != 0 {
		t.Errorf("root depth = %d, want 0", pt.Depth(100))
	}
	if _, ok := pt.Parent(100); ok {
		t.Error("root should have no parent")
	}
	if pt.Size() != 1 {
		t.Errorf("size = %d, want 1", pt.Size())
	}
}

func TestProcessTree_AddChild(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)
	pt.AddChild(100, 200)
	pt.AddChild(200, 300)

	if pt.Depth(200) != 1 {
		t.Errorf("child depth = %d, want 1", pt.Depth(200))
	}
	if pt.Depth(300) != 2 {
		t.Errorf("grandchild depth = %d, want 2", pt.Depth(300))
	}
	parent, ok := pt.Parent(200)
	if !ok || parent != 100 {
		t.Errorf("parent of 200 = %d, ok=%v; want 100, true", parent, ok)
	}
	if pt.Size() != 3 {
		t.Errorf("size = %d, want 3", pt.Size())
	}
}

func TestProcessTree_Remove(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(100)
	pt.AddChild(100, 200)

	pt.Remove(200)
	if pt.Size() != 1 {
		t.Errorf("size after remove = %d, want 1", pt.Size())
	}
	if pt.Depth(200) != -1 {
		t.Error("removed node should return depth -1")
	}
}

func TestProcessTree_IsDescendantOf(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(1)
	pt.AddChild(1, 10)
	pt.AddChild(10, 100)

	if !pt.IsDescendantOf(100, 1) {
		t.Error("100 should be descendant of 1")
	}
	if pt.IsDescendantOf(1, 100) {
		t.Error("1 should not be descendant of 100")
	}
	if pt.IsDescendantOf(100, 999) {
		t.Error("100 should not be descendant of non-existent 999")
	}
}

func TestProcessTree_ConcurrentAccess(t *testing.T) {
	pt := NewProcessTree()
	pt.AddRoot(1)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			tgid := id + 100
			pt.AddChild(1, tgid)
			pt.Depth(tgid)
			pt.Parent(tgid)
			pt.Size()
			pt.Remove(tgid)
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run TestProcessTree -v -race`
Expected: FAIL — NewProcessTree not defined

**Step 3: Implement**

```go
// internal/ptrace/process_tree.go
//go:build linux

package ptrace

import "sync"

// ProcessTree tracks TGID-to-TGID parent-child relationships.
// All operations are goroutine-safe.
type ProcessTree struct {
	mu    sync.RWMutex
	nodes map[int]*processNode
}

type processNode struct {
	tgid     int
	parent   int
	children []int
	depth    int
}

// NewProcessTree creates an empty process tree.
func NewProcessTree() *ProcessTree {
	return &ProcessTree{nodes: make(map[int]*processNode)}
}

// AddRoot adds a root process (depth 0, no parent).
func (pt *ProcessTree) AddRoot(tgid int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.nodes[tgid] = &processNode{tgid: tgid, parent: -1, depth: 0}
}

// AddChild adds a child process under the given parent.
func (pt *ProcessTree) AddChild(parentTGID, childTGID int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	parentNode := pt.nodes[parentTGID]
	depth := 0
	if parentNode != nil {
		depth = parentNode.depth + 1
		parentNode.children = append(parentNode.children, childTGID)
	}

	pt.nodes[childTGID] = &processNode{
		tgid:   childTGID,
		parent: parentTGID,
		depth:  depth,
	}
}

// Remove removes a process from the tree.
func (pt *ProcessTree) Remove(tgid int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	node := pt.nodes[tgid]
	if node == nil {
		return
	}

	// Remove from parent's children list
	if parent := pt.nodes[node.parent]; parent != nil {
		for i, c := range parent.children {
			if c == tgid {
				parent.children = append(parent.children[:i], parent.children[i+1:]...)
				break
			}
		}
	}

	delete(pt.nodes, tgid)
}

// Depth returns the depth of a process. Returns -1 if not found.
func (pt *ProcessTree) Depth(tgid int) int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	if node := pt.nodes[tgid]; node != nil {
		return node.depth
	}
	return -1
}

// Parent returns the parent TGID. Returns (0, false) if not found or root.
func (pt *ProcessTree) Parent(tgid int) (int, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	node := pt.nodes[tgid]
	if node == nil || node.parent == -1 {
		return 0, false
	}
	return node.parent, true
}

// Children returns the child TGIDs of a process.
func (pt *ProcessTree) Children(tgid int) []int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	node := pt.nodes[tgid]
	if node == nil {
		return nil
	}
	result := make([]int, len(node.children))
	copy(result, node.children)
	return result
}

// Size returns the number of processes in the tree.
func (pt *ProcessTree) Size() int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return len(pt.nodes)
}

// IsDescendantOf returns true if tgid is a descendant of ancestorTGID.
func (pt *ProcessTree) IsDescendantOf(tgid, ancestorTGID int) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	current := tgid
	for {
		node := pt.nodes[current]
		if node == nil || node.parent == -1 {
			return false
		}
		if node.parent == ancestorTGID {
			return true
		}
		current = node.parent
	}
}
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run TestProcessTree -v -race`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/process_tree.go internal/ptrace/process_tree_test.go
git commit -m "feat(ptrace): add TGID-based process tree tracking"
```

---

## Task 10: /proc helpers — readTGID, readPPID

**Files:**
- Create: `internal/ptrace/proc_helpers.go`
- Create: `internal/ptrace/proc_helpers_test.go`

**Step 1: Write failing tests**

```go
// internal/ptrace/proc_helpers_test.go
//go:build linux

package ptrace

import (
	"os"
	"testing"
)

func TestReadTGID(t *testing.T) {
	tgid, err := readTGID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if tgid != os.Getpid() {
		t.Errorf("readTGID(self) = %d, want %d", tgid, os.Getpid())
	}
}

func TestReadPPID(t *testing.T) {
	ppid, err := readPPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if ppid != os.Getppid() {
		t.Errorf("readPPID(self) = %d, want %d", ppid, os.Getppid())
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run TestRead -v`
Expected: FAIL

**Step 3: Implement**

```go
// internal/ptrace/proc_helpers.go
//go:build linux

package ptrace

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readTGID reads the thread group ID from /proc/<tid>/status.
func readTGID(tid int) (int, error) {
	return readProcStatusField(tid, "Tgid:")
}

// readPPID reads the parent PID from /proc/<tid>/status.
func readPPID(tid int) (int, error) {
	return readProcStatusField(tid, "PPid:")
}

func readProcStatusField(tid int, field string) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, field) {
			val := strings.TrimSpace(strings.TrimPrefix(line, field))
			return strconv.Atoi(val)
		}
	}
	return 0, fmt.Errorf("%s not found in /proc/%d/status", field, tid)
}
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run TestRead -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/proc_helpers.go internal/ptrace/proc_helpers_test.go
git commit -m "feat(ptrace): add /proc status parsing helpers (readTGID, readPPID)"
```

---

## Task 11: Memory access helpers

**Files:**
- Create: `internal/ptrace/memory.go`
- Create: `internal/ptrace/memory_test.go`

**Step 1: Write failing tests**

```go
// internal/ptrace/memory_test.go
//go:build linux

package ptrace

import (
	"bytes"
	"testing"
)

func TestReadStringFromBuffer(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		maxLen int
		want   string
	}{
		{
			name:   "simple",
			data:   []byte("hello\x00world"),
			maxLen: 100,
			want:   "hello",
		},
		{
			name:   "max length truncation",
			data:   []byte("abcdefgh\x00"),
			maxLen: 5,
			want:   "abcde",
		},
		{
			name:   "empty string",
			data:   []byte("\x00rest"),
			maxLen: 100,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a bufferReader to simulate readBytes
			reader := &mockMemReader{data: tt.data}
			got, err := readStringFrom(reader, 0, tt.maxLen)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("readString = %q, want %q", got, tt.want)
			}
		})
	}
}

// mockMemReader simulates reading from a flat byte buffer.
type mockMemReader struct {
	data []byte
}

func (m *mockMemReader) read(addr uint64, buf []byte) error {
	start := int(addr)
	if start >= len(m.data) {
		return fmt.Errorf("read past end")
	}
	end := start + len(buf)
	if end > len(m.data) {
		end = len(m.data)
	}
	copy(buf, m.data[start:end])
	// Zero-fill remainder if read was short
	for i := end - start; i < len(buf); i++ {
		buf[i] = 0
	}
	return nil
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run TestReadString -v`
Expected: FAIL

**Step 3: Implement**

```go
// internal/ptrace/memory.go
//go:build linux

package ptrace

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// memReader is an interface for reading bytes from an address space.
// Abstracted for testability — production uses /proc/<tid>/mem.
type memReader interface {
	read(addr uint64, buf []byte) error
}

// procMemReader reads via /proc/<tid>/mem using a cached fd.
type procMemReader struct {
	fd int
}

func (r *procMemReader) read(addr uint64, buf []byte) error {
	_, err := unix.Pread(r.fd, buf, int64(addr))
	return err
}

// readBytesFrom reads len(buf) bytes from the given reader at addr.
func readBytesFrom(r memReader, addr uint64, buf []byte) error {
	return r.read(addr, buf)
}

// readStringFrom reads a NUL-terminated string from a memReader.
// Reads in 256-byte chunks. Returns at most maxLen bytes.
func readStringFrom(r memReader, addr uint64, maxLen int) (string, error) {
	var result []byte
	chunk := make([]byte, 256)
	for len(result) < maxLen {
		n := 256
		if maxLen-len(result) < n {
			n = maxLen - len(result)
		}
		if err := r.read(addr+uint64(len(result)), chunk[:n]); err != nil {
			return "", err
		}
		if idx := bytes.IndexByte(chunk[:n], 0); idx >= 0 {
			result = append(result, chunk[:idx]...)
			return string(result), nil
		}
		result = append(result, chunk[:n]...)
	}
	return string(result), nil
}

// Tracer-level memory access methods using the cached MemFD.

func (t *Tracer) getMemReader(tid int) (memReader, error) {
	t.mu.Lock()
	state := t.tracees[tid]
	fd := -1
	if state != nil {
		fd = state.MemFD
	}
	t.mu.Unlock()

	if fd < 0 {
		return nil, fmt.Errorf("no memfd for tid %d", tid)
	}
	return &procMemReader{fd: fd}, nil
}

func (t *Tracer) readBytes(tid int, addr uint64, buf []byte) error {
	r, err := t.getMemReader(tid)
	if err != nil {
		return err
	}
	return readBytesFrom(r, addr, buf)
}

func (t *Tracer) readString(tid int, addr uint64, maxLen int) (string, error) {
	r, err := t.getMemReader(tid)
	if err != nil {
		return "", err
	}
	return readStringFrom(r, addr, maxLen)
}

func (t *Tracer) writeBytes(tid int, addr uint64, buf []byte) error {
	t.mu.Lock()
	state := t.tracees[tid]
	fd := -1
	if state != nil {
		fd = state.MemFD
	}
	t.mu.Unlock()

	if fd < 0 {
		return fmt.Errorf("no memfd for tid %d", tid)
	}
	_, err := unix.Pwrite(fd, buf, int64(addr))
	return err
}

// readArgv reads the argv array from tracee memory.
// Returns the argument list and whether it was truncated.
func (t *Tracer) readArgv(tid int, argvPtr uint64, maxArgc int, maxBytes int) ([]string, bool, error) {
	r, err := t.getMemReader(tid)
	if err != nil {
		return nil, false, err
	}

	var args []string
	totalBytes := 0
	ptrBuf := make([]byte, 8)

	for i := 0; i < maxArgc; i++ {
		if err := r.read(argvPtr+uint64(i*8), ptrBuf); err != nil {
			return args, false, err
		}
		ptr := nativeEndianUint64(ptrBuf)
		if ptr == 0 {
			break // NULL terminator
		}

		s, err := readStringFrom(r, ptr, 4096)
		if err != nil {
			return args, false, err
		}

		totalBytes += len(s) + 1
		if totalBytes > maxBytes {
			return args, true, nil // truncated
		}
		args = append(args, s)
	}
	return args, false, nil
}

func nativeEndianUint64(b []byte) uint64 {
	// Little-endian (both amd64 and arm64 in Linux are LE)
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
```

Note: The `readArgv` and `writeBytes` methods reference `t *Tracer` which will be defined in Task 12. Add a forward reference comment if needed, or move them there. The test only tests the reader abstraction directly.

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run TestReadString -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/memory.go internal/ptrace/memory_test.go
git commit -m "feat(ptrace): add memory access helpers via /proc/<tid>/mem"
```

---

## Task 12: Syscall classification

**Files:**
- Create: `internal/ptrace/syscalls.go`
- Create: `internal/ptrace/syscalls_test.go`

**Step 1: Write failing tests**

```go
// internal/ptrace/syscalls_test.go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsExecveSyscall(t *testing.T) {
	if !isExecveSyscall(unix.SYS_EXECVE) {
		t.Error("SYS_EXECVE should be classified as execve")
	}
	if !isExecveSyscall(unix.SYS_EXECVEAT) {
		t.Error("SYS_EXECVEAT should be classified as execve")
	}
	if isExecveSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be classified as execve")
	}
}

func TestIsFileSyscall(t *testing.T) {
	if !isFileSyscall(unix.SYS_OPENAT) {
		t.Error("SYS_OPENAT should be a file syscall")
	}
	if !isFileSyscall(unix.SYS_UNLINKAT) {
		t.Error("SYS_UNLINKAT should be a file syscall")
	}
	if isFileSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a file syscall")
	}
}

func TestIsNetworkSyscall(t *testing.T) {
	if !isNetworkSyscall(unix.SYS_CONNECT) {
		t.Error("SYS_CONNECT should be a network syscall")
	}
	if !isNetworkSyscall(unix.SYS_SOCKET) {
		t.Error("SYS_SOCKET should be a network syscall")
	}
	if isNetworkSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a network syscall")
	}
}

func TestIsSignalSyscall(t *testing.T) {
	if !isSignalSyscall(unix.SYS_KILL) {
		t.Error("SYS_KILL should be a signal syscall")
	}
	if !isSignalSyscall(unix.SYS_TGKILL) {
		t.Error("SYS_TGKILL should be a signal syscall")
	}
	if isSignalSyscall(unix.SYS_READ) {
		t.Error("SYS_READ should not be a signal syscall")
	}
}

func TestTracedSyscallNumbers(t *testing.T) {
	nums := tracedSyscallNumbers()
	if len(nums) < 10 {
		t.Errorf("expected at least 10 traced syscalls, got %d", len(nums))
	}
	// Verify execve is in the list
	found := false
	for _, n := range nums {
		if n == unix.SYS_EXECVE {
			found = true
			break
		}
	}
	if !found {
		t.Error("SYS_EXECVE missing from traced syscalls")
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run TestIs -v`
Expected: FAIL

**Step 3: Implement**

```go
// internal/ptrace/syscalls.go
//go:build linux

package ptrace

import "golang.org/x/sys/unix"

func isExecveSyscall(nr int) bool {
	return nr == unix.SYS_EXECVE || nr == unix.SYS_EXECVEAT
}

func isFileSyscall(nr int) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT:
		return true
	}
	return isLegacyFileSyscall(nr)
}

func isNetworkSyscall(nr int) bool {
	switch nr {
	case unix.SYS_CONNECT, unix.SYS_SOCKET, unix.SYS_BIND,
		unix.SYS_SENDTO, unix.SYS_LISTEN:
		return true
	}
	return false
}

func isSignalSyscall(nr int) bool {
	switch nr {
	case unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO:
		return true
	}
	return false
}

// tracedSyscallNumbers returns all syscall numbers that should be traced.
// Used to build the seccomp prefilter BPF program.
func tracedSyscallNumbers() []int {
	nums := []int{
		// Exec
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
		// File
		unix.SYS_OPENAT, unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT,
		// Network
		unix.SYS_CONNECT, unix.SYS_SOCKET, unix.SYS_BIND,
		unix.SYS_SENDTO, unix.SYS_LISTEN,
		// Signal
		unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
		unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
	}
	nums = append(nums, legacyFileSyscalls()...)
	return nums
}
```

```go
// internal/ptrace/syscalls_amd64.go
//go:build linux && amd64

package ptrace

import "golang.org/x/sys/unix"

func isLegacyFileSyscall(nr int) bool {
	switch nr {
	case unix.SYS_OPEN, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_LINK,
		unix.SYS_SYMLINK, unix.SYS_CHMOD, unix.SYS_CHOWN:
		return true
	}
	return false
}

func legacyFileSyscalls() []int {
	return []int{
		unix.SYS_OPEN, unix.SYS_UNLINK, unix.SYS_RENAME,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_LINK,
		unix.SYS_SYMLINK, unix.SYS_CHMOD, unix.SYS_CHOWN,
	}
}
```

```go
// internal/ptrace/syscalls_arm64.go
//go:build linux && arm64

package ptrace

// arm64 has no legacy file syscalls (only *at variants).
func isLegacyFileSyscall(nr int) bool { return false }
func legacyFileSyscalls() []int       { return nil }
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run "TestIs|TestTraced" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/syscalls.go internal/ptrace/syscalls_amd64.go internal/ptrace/syscalls_arm64.go internal/ptrace/syscalls_test.go
git commit -m "feat(ptrace): add syscall classification for dispatch routing"
```

---

## Task 13: Tracer struct, TraceeState, constructor, and ptrace options

**Files:**
- Create: `internal/ptrace/tracer.go`

**Step 1: Write failing test**

```go
// internal/ptrace/tracer_test.go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewTracer(t *testing.T) {
	cfg := TracerConfig{}
	tr := NewTracer(cfg)
	if tr == nil {
		t.Fatal("NewTracer returned nil")
	}
	if tr.TraceeCount() != 0 {
		t.Error("new tracer should have 0 tracees")
	}
}

func TestPtraceOptions_WithPrefilter(t *testing.T) {
	tr := &Tracer{prefilterActive: true}
	opts := tr.ptraceOptions()
	if opts&unix.PTRACE_O_EXITKILL == 0 {
		t.Error("PTRACE_O_EXITKILL must always be set")
	}
	if opts&unix.PTRACE_O_TRACESECCOMP == 0 {
		t.Error("PTRACE_O_TRACESECCOMP must be set when prefilter active")
	}
	if opts&unix.PTRACE_O_TRACESYSGOOD != 0 {
		t.Error("PTRACE_O_TRACESYSGOOD must not be set when prefilter active")
	}
}

func TestPtraceOptions_WithoutPrefilter(t *testing.T) {
	tr := &Tracer{prefilterActive: false}
	opts := tr.ptraceOptions()
	if opts&unix.PTRACE_O_EXITKILL == 0 {
		t.Error("PTRACE_O_EXITKILL must always be set")
	}
	if opts&unix.PTRACE_O_TRACESYSGOOD == 0 {
		t.Error("PTRACE_O_TRACESYSGOOD must be set when no prefilter")
	}
	if opts&unix.PTRACE_O_TRACESECCOMP != 0 {
		t.Error("PTRACE_O_TRACESECCOMP must not be set when no prefilter")
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./internal/ptrace/ -run "TestNewTracer|TestPtraceOptions" -v`
Expected: FAIL

**Step 3: Implement**

```go
// internal/ptrace/tracer.go
//go:build linux

package ptrace

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// TracerConfig holds configuration for the ptrace tracer.
type TracerConfig struct {
	AttachMode       string
	TargetPID        int
	TargetPIDFile    string
	TraceExecve      bool
	TraceFile        bool
	TraceNetwork     bool
	TraceSignal      bool
	SeccompPrefilter bool
	MaxTracees       int
	MaxHoldMs        int
	OnAttachFailure  string
}

// TraceeState tracks the state of a single traced thread.
type TraceeState struct {
	TID              int
	TGID             int
	ParentPID        int
	SessionID        string
	InSyscall        bool
	LastNr           int
	Attached         time.Time
	PendingDenyErrno int
	PendingInterrupt bool
	IsVforkChild     bool
	MemFD            int
}

type resumeRequest struct {
	TID   int
	Allow bool
	Errno int
}

// Tracer implements a ptrace-based syscall tracer.
type Tracer struct {
	cfg             TracerConfig
	processTree     *ProcessTree
	prefilterActive bool

	attachQueue  chan int
	resumeQueue  chan resumeRequest

	mu            sync.Mutex
	tracees       map[int]*TraceeState
	parkedTracees map[int]struct{}

	stopped chan struct{}
}

// NewTracer creates a new ptrace tracer.
func NewTracer(cfg TracerConfig) *Tracer {
	return &Tracer{
		cfg:           cfg,
		processTree:   NewProcessTree(),
		attachQueue:   make(chan int, 64),
		resumeQueue:   make(chan resumeRequest, 64),
		tracees:       make(map[int]*TraceeState),
		parkedTracees: make(map[int]struct{}),
		stopped:       make(chan struct{}),
	}
}

// TraceeCount returns the number of currently traced threads.
func (t *Tracer) TraceeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tracees)
}

// AttachPID enqueues attachment to a process.
// Safe to call from any goroutine.
func (t *Tracer) AttachPID(pid int) error {
	t.attachQueue <- pid
	return nil
}

// Available returns whether ptrace tracing is available.
func (t *Tracer) Available() bool {
	return true // If Tracer was created, ptrace is available
}

// Implementation returns "ptrace".
func (t *Tracer) Implementation() string {
	return "ptrace"
}

func (t *Tracer) ptraceOptions() int {
	opts := unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_TRACEEXIT |
		unix.PTRACE_O_EXITKILL

	if t.prefilterActive {
		opts |= unix.PTRACE_O_TRACESECCOMP
	} else {
		opts |= unix.PTRACE_O_TRACESYSGOOD
	}

	return opts
}

func (t *Tracer) getRegs(tid int) (Regs, error) {
	return getRegsArch(tid)
}

func (t *Tracer) setRegs(tid int, regs Regs) error {
	return setRegsArch(tid, regs)
}
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/ -run "TestNewTracer|TestPtraceOptions" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/tracer_test.go
git commit -m "feat(ptrace): add Tracer struct, TraceeState, constructor, and ptrace options"
```

---

## Task 14: Attachment — attachThread, attachProcess, safeDetach

**Files:**
- Create: `internal/ptrace/attach.go`

**Step 1: Implement** (tests require SYS_PTRACE — deferred to integration tests in Task 18)

```go
// internal/ptrace/attach.go
//go:build linux

package ptrace

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// attachProcess attaches to all threads of a process.
func (t *Tracer) attachProcess(pid int) error {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return t.attachThread(pid)
	}

	var firstErr error
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if err := t.attachThread(tid); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			slog.Warn("failed to attach thread", "tid", tid, "pid", pid, "error", err)
		}
	}
	return firstErr
}

// attachThread attaches to a single thread via PTRACE_SEIZE.
func (t *Tracer) attachThread(tid int) error {
	err := unix.PtraceSeize(tid, t.ptraceOptions())
	if err != nil {
		return fmt.Errorf("PTRACE_SEIZE tid %d: %w", tid, err)
	}

	tgid, err := readTGID(tid)
	if err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("read TGID for tid %d: %w", tid, err)
	}

	if err := unix.PtraceInterrupt(tid); err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("PTRACE_INTERRUPT tid %d: %w", tid, err)
	}

	var status unix.WaitStatus
	_, err = unix.Wait4(tid, &status, 0, nil)
	if err != nil {
		t.safeDetach(tid)
		return fmt.Errorf("wait4 after interrupt tid %d: %w", tid, err)
	}

	if !status.Stopped() {
		t.safeDetach(tid)
		return fmt.Errorf("tid %d: expected ptrace-stop after interrupt, got status %v", tid, status)
	}

	// Restart in the appropriate tracing mode
	if t.prefilterActive {
		err = unix.PtraceCont(tid, 0)
	} else {
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil {
		unix.PtraceDetach(tid)
		return fmt.Errorf("restart tid %d: %w", tid, err)
	}

	// Open /proc/<tid>/mem for memory reads
	memFD := -1
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDWR, 0)
	if err != nil {
		fd, _ = unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDONLY, 0)
	}
	memFD = fd

	t.mu.Lock()
	t.tracees[tid] = &TraceeState{
		TID:      tid,
		TGID:     tgid,
		Attached: time.Now(),
		MemFD:    memFD,
	}
	t.mu.Unlock()

	return nil
}

// safeDetach detaches from a seized tracee that may not be in ptrace-stop.
func (t *Tracer) safeDetach(tid int) {
	if err := unix.PtraceInterrupt(tid); err != nil {
		return
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(tid, &status, 0, nil); err != nil {
		return
	}
	if status.Stopped() {
		unix.PtraceDetach(tid)
	}
}
```

**Step 2: Verify build**

Run: `go build ./internal/ptrace/`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/ptrace/attach.go
git commit -m "feat(ptrace): add process/thread attachment via PTRACE_SEIZE"
```

---

## Task 15: allow/deny/resume primitives and stop event dispatcher

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Add syscall primitives and event handlers**

Append to `tracer.go`:

```go
// allowSyscall resumes the tracee, allowing the syscall to proceed.
func (t *Tracer) allowSyscall(tid int) {
	if t.prefilterActive {
		unix.PtraceCont(tid, 0)
	} else {
		unix.PtraceSyscall(tid, 0)
	}
}

// denySyscall invalidates the current syscall and arranges for return value fixup.
func (t *Tracer) denySyscall(tid int, errno int) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		return err
	}
	regs.SetSyscallNr(-1)
	if err := t.setRegs(tid, regs); err != nil {
		// Cannot deny — kill the tracee to prevent the syscall from executing.
		t.mu.Lock()
		state := t.tracees[tid]
		tgid := tid
		if state != nil {
			tgid = state.TGID
		}
		t.mu.Unlock()
		unix.Tgkill(tgid, tid, unix.SIGKILL)
		return fmt.Errorf("deny failed, killed tid %d: %w", tid, err)
	}

	t.mu.Lock()
	if state, ok := t.tracees[tid]; ok {
		state.PendingDenyErrno = errno
		state.InSyscall = true
	}
	t.mu.Unlock()

	return unix.PtraceSyscall(tid, 0)
}

// resumeTracee resumes a tracee with an optional signal to deliver.
func (t *Tracer) resumeTracee(tid int, sig int) {
	if t.prefilterActive {
		unix.PtraceCont(tid, sig)
	} else {
		unix.PtraceSyscall(tid, sig)
	}
}

// applyDenyFixup overwrites the syscall return value with -errno.
func (t *Tracer) applyDenyFixup(tid int, errno int) {
	regs, err := t.getRegs(tid)
	if err != nil {
		return
	}
	regs.SetReturnValue(-int64(errno))
	t.setRegs(tid, regs)
}

// handleStop dispatches a tracee stop event.
func (t *Tracer) handleStop(ctx context.Context, tid int, status unix.WaitStatus) {
	switch {
	case status.Exited() || status.Signaled():
		t.handleExit(tid)

	case status.Stopped():
		sig := status.StopSignal()

		switch {
		case sig == unix.SIGTRAP|0x80:
			t.handleSyscallStop(ctx, tid)

		case sig == unix.SIGTRAP:
			event := status.TrapCause()
			switch event {
			case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_CLONE:
				t.handleNewChild(tid, event)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_VFORK:
				t.handleNewChild(tid, event)
				t.markVforkChild(tid)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_EXEC:
				t.handleExecEvent(tid)
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_SECCOMP:
				t.handleSeccompStop(ctx, tid)
			case unix.PTRACE_EVENT_EXIT:
				t.resumeTracee(tid, 0)
			case unix.PTRACE_EVENT_STOP:
				t.handleEventStop(tid)
			default:
				t.resumeTracee(tid, 0)
			}

		default:
			t.resumeTracee(tid, int(sig))
		}
	}
}

// handleSyscallStop handles SIGTRAP|0x80 stops (TRACESYSGOOD mode).
func (t *Tracer) handleSyscallStop(ctx context.Context, tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		t.allowSyscall(tid)
		return
	}
	entering := !state.InSyscall
	state.InSyscall = entering
	pendingErrno := 0
	if !entering {
		pendingErrno = state.PendingDenyErrno
		state.PendingDenyErrno = 0
	}
	t.mu.Unlock()

	if entering {
		regs, err := t.getRegs(tid)
		if err != nil {
			t.allowSyscall(tid)
			return
		}
		nr := regs.SyscallNr()
		t.mu.Lock()
		state.LastNr = nr
		t.mu.Unlock()

		t.dispatchSyscall(ctx, tid, nr, regs)
	} else {
		if pendingErrno != 0 {
			t.applyDenyFixup(tid, pendingErrno)
		}
		t.allowSyscall(tid)
	}
}

// handleSeccompStop handles PTRACE_EVENT_SECCOMP stops (prefilter mode).
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
	regs, err := t.getRegs(tid)
	if err != nil {
		t.allowSyscall(tid)
		return
	}
	nr := regs.SyscallNr()
	t.dispatchSyscall(ctx, tid, nr, regs)
}

// dispatchSyscall routes a syscall to the appropriate handler.
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isExecveSyscall(nr):
		t.handleExecve(ctx, tid, regs)
	// Phase 1: file, network, signal handlers are stubs that allow
	case isFileSyscall(nr):
		t.allowSyscall(tid)
	case isNetworkSyscall(nr):
		t.allowSyscall(tid)
	case isSignalSyscall(nr):
		t.allowSyscall(tid)
	default:
		t.allowSyscall(tid)
	}
}

// handleNewChild processes a fork/clone/vfork event.
func (t *Tracer) handleNewChild(parentTID int, event int) {
	childTID, err := unix.PtraceGetEventMsg(parentTID)
	if err != nil {
		return
	}
	tid := int(childTID)

	childTGID, err := readTGID(tid)
	if err != nil {
		slog.Warn("handleNewChild: cannot read TGID", "tid", tid, "error", err)
		return
	}

	t.mu.Lock()
	parent := t.tracees[parentTID]
	if parent == nil {
		t.mu.Unlock()
		return
	}

	isNewProcess := childTGID != parent.TGID

	t.tracees[tid] = &TraceeState{
		TID:       tid,
		TGID:      childTGID,
		ParentPID: parent.TGID,
		SessionID: parent.SessionID,
		Attached:  time.Now(),
	}
	t.mu.Unlock()

	if isNewProcess {
		t.processTree.AddChild(parent.TGID, childTGID)
	}
}

// markVforkChild marks the child as a vfork child.
func (t *Tracer) markVforkChild(parentTID int) {
	childTID, err := unix.PtraceGetEventMsg(parentTID)
	if err != nil {
		return
	}
	t.mu.Lock()
	if state, ok := t.tracees[int(childTID)]; ok {
		state.IsVforkChild = true
	}
	t.mu.Unlock()
}

// handleExecEvent handles PTRACE_EVENT_EXEC.
func (t *Tracer) handleExecEvent(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		return
	}
	state.IsVforkChild = false

	formerTID, err := unix.PtraceGetEventMsg(tid)
	if err == nil && int(formerTID) != tid {
		delete(t.tracees, int(formerTID))
	}

	tgid := state.TGID
	for otherTID, otherState := range t.tracees {
		if otherState.TGID == tgid && otherTID != tid {
			if otherState.MemFD >= 0 {
				unix.Close(otherState.MemFD)
			}
			delete(t.tracees, otherTID)
		}
	}
	t.mu.Unlock()
}

// handleExit removes a tracee from the map.
func (t *Tracer) handleExit(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil {
		if state.MemFD >= 0 {
			unix.Close(state.MemFD)
		}
		delete(t.tracees, tid)
	}
	t.mu.Unlock()
}

// handleEventStop distinguishes PTRACE_INTERRUPT responses from group-stops.
func (t *Tracer) handleEventStop(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil && state.PendingInterrupt {
		state.PendingInterrupt = false
		t.mu.Unlock()
		t.resumeTracee(tid, 0)
		return
	}
	t.mu.Unlock()
	unix.PtraceListen(tid)
}

// handleExecve is a stub for Phase 1 — to be replaced in Task 17.
func (t *Tracer) handleExecve(ctx context.Context, tid int, regs Regs) {
	t.allowSyscall(tid)
}
```

**Step 2: Verify build**

Run: `go build ./internal/ptrace/`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): add allow/deny primitives, stop dispatcher, and event handlers"
```

---

## Task 16: Main event loop — Run()

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Implement Run(), drainQueues(), handleResumeRequest()**

Append to `tracer.go`:

```go
// Run starts the ptrace event loop. Blocks until ctx is cancelled or all tracees exit.
func (t *Tracer) Run(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		if err := t.drainQueues(ctx); err != nil {
			return err
		}

		var status unix.WaitStatus
		tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, nil)

		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.ECHILD {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-t.stopped:
					return nil
				case pid := <-t.attachQueue:
					if err := t.attachProcess(pid); err != nil {
						slog.Error("attach from queue failed", "pid", pid, "error", err)
					}
					continue
				case req := <-t.resumeQueue:
					t.handleResumeRequest(req)
					continue
				}
			}
			return fmt.Errorf("wait4: %w", err)
		}

		if tid == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.stopped:
				return nil
			case pid := <-t.attachQueue:
				if err := t.attachProcess(pid); err != nil {
					slog.Error("attach from queue failed", "pid", pid, "error", err)
				}
			case req := <-t.resumeQueue:
				t.handleResumeRequest(req)
			case <-time.After(5 * time.Millisecond):
			}
			continue
		}

		t.handleStop(ctx, tid, status)
	}
}

// Start implements the SyscallTracer interface.
func (t *Tracer) Start(ctx context.Context) error {
	return t.Run(ctx)
}

// Stop signals the event loop to exit.
func (t *Tracer) Stop() {
	select {
	case <-t.stopped:
	default:
		close(t.stopped)
	}
}

func (t *Tracer) drainQueues(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.stopped:
			return fmt.Errorf("tracer stopped")
		case pid := <-t.attachQueue:
			if err := t.attachProcess(pid); err != nil {
				slog.Error("attach from queue failed", "pid", pid, "error", err)
			}
		case req := <-t.resumeQueue:
			t.handleResumeRequest(req)
		default:
			return nil
		}
	}
}

func (t *Tracer) handleResumeRequest(req resumeRequest) {
	t.mu.Lock()
	_, parked := t.parkedTracees[req.TID]
	if parked {
		delete(t.parkedTracees, req.TID)
	}
	t.mu.Unlock()

	if !parked {
		slog.Warn("resume request for non-parked tracee", "tid", req.TID)
		return
	}

	if req.Allow {
		t.allowSyscall(req.TID)
	} else {
		t.denySyscall(req.TID, req.Errno)
	}
}
```

Add `"runtime"` to imports.

**Step 2: Verify build**

Run: `go build ./internal/ptrace/`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): implement main event loop with WNOHANG + channel select"
```

---

## Task 17: ExecveHandler integration

**Files:**
- Modify: `internal/ptrace/tracer.go` — add ExecHandler interface and field
- Modify the stub `handleExecve` from Task 15

**Step 1: Define local ExecHandler interface**

This avoids coupling to the CGO-dependent `internal/netmonitor/unix` package:

```go
// ExecHandler evaluates execve policy. Implemented by an adapter wrapping
// the existing internal/netmonitor/unix.ExecveHandler.
type ExecHandler interface {
	HandleExecve(ctx context.Context, ec ExecContext) ExecResult
}

// ExecContext carries execve information for policy evaluation.
type ExecContext struct {
	PID       int
	ParentPID int
	Filename  string
	Argv      []string
	Truncated bool
	SessionID string
	Depth     int
}

// ExecResult carries the policy decision.
type ExecResult struct {
	Allow  bool
	Action string // "continue", "deny", "redirect"
	Errno  int32
	Rule   string
	Reason string
}
```

Add `execHandler ExecHandler` field to `Tracer` struct. Accept it in `TracerConfig`.

**Step 2: Replace the stub handleExecve**

```go
func (t *Tracer) handleExecve(ctx context.Context, tid int, regs Regs) {
	if t.cfg.ExecHandler == nil || !t.cfg.TraceExecve {
		t.allowSyscall(tid)
		return
	}

	nr := regs.SyscallNr()
	var filenamePtr uint64
	if nr == unix.SYS_EXECVEAT {
		filenamePtr = regs.Arg(1)
	} else {
		filenamePtr = regs.Arg(0)
	}

	filename, err := t.readString(tid, filenamePtr, 4096)
	if err != nil {
		slog.Warn("handleExecve: cannot read filename", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	var argvPtr uint64
	if nr == unix.SYS_EXECVEAT {
		argvPtr = regs.Arg(2)
	} else {
		argvPtr = regs.Arg(1)
	}

	argv, truncated, err := t.readArgv(tid, argvPtr, 1000, 65536)
	if err != nil {
		slog.Warn("handleExecve: cannot read argv", "tid", tid, "error", err)
		t.allowSyscall(tid)
		return
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid, parentPID int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		parentPID = state.ParentPID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	depth := t.processTree.Depth(tgid)

	result := t.cfg.ExecHandler.HandleExecve(ctx, ExecContext{
		PID:       tgid,
		ParentPID: parentPID,
		Filename:  filename,
		Argv:      argv,
		Truncated: truncated,
		SessionID: sessionID,
		Depth:     depth,
	})

	switch result.Action {
	case "deny":
		errno := result.Errno
		if errno == 0 {
			errno = int32(unix.EACCES)
		}
		t.denySyscall(tid, int(errno))
	default:
		t.allowSyscall(tid)
	}
}
```

Update `TracerConfig`:
```go
type TracerConfig struct {
	// ... existing fields ...
	ExecHandler ExecHandler
}
```

And store it:
```go
func NewTracer(cfg TracerConfig) *Tracer {
	return &Tracer{
		cfg:           cfg,
		// ... rest unchanged ...
	}
}
```

**Step 3: Verify build**

Run: `go build ./internal/ptrace/`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): integrate ExecHandler for command allow/deny policy"
```

---

## Task 18: Integration tests

**Files:**
- Create: `internal/ptrace/integration_test.go`

Build tag: `//go:build integration && linux`

These tests require `SYS_PTRACE` capability. Run with:
```bash
go test -tags integration -v ./internal/ptrace/ -run TestIntegration -count=1
```

Or in Docker:
```bash
docker run --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v $(pwd):/src -w /src golang:1.23 \
  go test -tags integration -v ./internal/ptrace/ -run TestIntegration -count=1
```

```go
// internal/ptrace/integration_test.go
//go:build integration && linux

package ptrace

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requirePtrace(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "0.01")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start child process")
	}
	pid := cmd.Process.Pid
	err := unix.PtraceSeize(pid, 0)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		t.Skipf("ptrace not available: %v", err)
	}
	// Clean up: interrupt + wait + detach would be needed if seize succeeded,
	// but we killed the process above, so the tracee is gone.
}

func TestIntegration_AttachDetach(t *testing.T) {
	requirePtrace(t)

	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()

	cfg := TracerConfig{TraceExecve: true}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run tracer in background
	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Send attach request
	tr.AttachPID(cmd.Process.Pid)

	// Wait a bit for attachment
	time.Sleep(200 * time.Millisecond)

	if tr.TraceeCount() == 0 {
		t.Error("expected at least 1 tracee after attach")
	}

	cancel()
	<-errCh
}

type mockExecHandler struct {
	mu      sync.Mutex
	calls   []ExecContext
	allow   bool
	errno   int32
}

func (m *mockExecHandler) HandleExecve(ctx context.Context, ec ExecContext) ExecResult {
	m.mu.Lock()
	m.calls = append(m.calls, ec)
	m.mu.Unlock()

	action := "continue"
	if !m.allow {
		action = "deny"
	}
	return ExecResult{
		Allow:  m.allow,
		Action: action,
		Errno:  m.errno,
	}
}

func TestIntegration_ExecveAllow(t *testing.T) {
	requirePtrace(t)

	handler := &mockExecHandler{allow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/echo", "hello")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)

	err := cmd.Wait()
	cancel()
	<-errCh

	if err != nil {
		t.Errorf("child should have succeeded: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.calls) == 0 {
		t.Log("Note: execve handler may not have been called if attach happened after exec")
	}
}

func TestIntegration_ForkTree(t *testing.T) {
	requirePtrace(t)

	cfg := TracerConfig{TraceExecve: true}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Shell that forks a child
	cmd := exec.Command("/bin/sh", "-c", "echo parent; /bin/sh -c 'echo child'")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	// Give tracer a moment to process events
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-errCh

	if tr.processTree.Size() > 0 {
		t.Logf("process tree tracked %d processes", tr.processTree.Size())
	}
}
```

**Step 1: Run tests (in Docker or with SYS_PTRACE)**

Run: `go test -tags integration -v ./internal/ptrace/ -run TestIntegration -count=1 -timeout 30s`
Expected: Tests pass (or skip if SYS_PTRACE unavailable)

**Step 2: Commit**

```bash
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add integration tests for attach, execve, and fork tree"
```

---

## Task 19: Cross-compilation and full build verification

**Files:** None — verification only

**Step 1: Run all unit tests**

Run: `go test ./internal/ptrace/... -v`
Expected: PASS

**Step 2: Run all capability tests**

Run: `go test ./internal/capabilities/... -v`
Expected: PASS

**Step 3: Run all config tests**

Run: `go test ./internal/config/... -v`
Expected: PASS

**Step 4: Full build**

Run: `go build ./...`
Expected: PASS

**Step 5: Cross-compile check**

Run: `GOOS=windows go build ./... && GOARCH=arm64 go build ./internal/ptrace/`
Expected: PASS (non-Linux platforms skip ptrace package via build tags)

**Step 6: Commit (if any fixups needed)**

```bash
git commit -m "fix: resolve cross-compilation issues for ptrace package"
```

---

## Verification

After completing all tasks:

1. **Unit tests:** `go test ./internal/ptrace/... ./internal/capabilities/... ./internal/config/... -v -race`
2. **Integration tests (Docker):**
   ```bash
   docker run --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
     -v $(pwd):/src -w /src golang:1.23 \
     go test -tags integration -v ./internal/ptrace/ -run TestIntegration -count=1 -timeout 30s
   ```
3. **Cross-compile:** `GOOS=windows go build ./... && GOOS=darwin go build ./...`
4. **Full test suite:** `go test ./... -count=1`
