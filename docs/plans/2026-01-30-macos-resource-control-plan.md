# macOS Resource Control Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement memory and CPU resource limits for macOS sandboxed processes using setrlimit and userspace monitoring.

**Architecture:** Hybrid approach - kernel-enforced memory limits via RLIMIT_AS, plus userspace CPU monitoring with SIGSTOP/SIGCONT throttling at 500ms intervals. Uses proc_pid_rusage() via cgo for CPU stats.

**Tech Stack:** Go, cgo, libproc.h (macOS), syscall package

---

## Task 1: Add proc_pid_rusage cgo wrapper

**Files:**
- Create: `internal/platform/darwin/rusage_darwin.go`
- Create: `internal/platform/darwin/rusage_darwin_test.go`

**Step 1: Write the test file**

Create `internal/platform/darwin/rusage_darwin_test.go`:

```go
//go:build darwin

package darwin

import (
	"os"
	"testing"
)

func TestGetProcRusage(t *testing.T) {
	// Get rusage for current process
	pid := os.Getpid()
	rusage, err := getProcRusage(pid)
	if err != nil {
		t.Fatalf("getProcRusage(%d) failed: %v", pid, err)
	}

	// Verify we got some CPU time (process has been running)
	if rusage.UserTime == 0 && rusage.SystemTime == 0 {
		t.Error("expected non-zero CPU time for current process")
	}

	// Verify resident memory is non-zero
	if rusage.ResidentSize == 0 {
		t.Error("expected non-zero resident memory")
	}
}

func TestGetProcRusageInvalidPID(t *testing.T) {
	// Use an invalid PID
	_, err := getProcRusage(-1)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}
```

**Step 2: Write the cgo implementation**

Create `internal/platform/darwin/rusage_darwin.go`:

```go
//go:build darwin

package darwin

/*
#include <libproc.h>
#include <sys/resource.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ProcRusage contains resource usage information for a process.
type ProcRusage struct {
	UserTime     uint64 // User CPU time in nanoseconds
	SystemTime   uint64 // System CPU time in nanoseconds
	ResidentSize uint64 // Resident memory size in bytes
	VirtualSize  uint64 // Virtual memory size in bytes
}

// getProcRusage retrieves resource usage for a process using proc_pid_rusage.
func getProcRusage(pid int) (*ProcRusage, error) {
	var ri C.struct_rusage_info_v3

	ret := C.proc_pid_rusage(C.int(pid), C.RUSAGE_INFO_V3, (*C.rusage_info_t)(unsafe.Pointer(&ri)))
	if ret != 0 {
		return nil, fmt.Errorf("proc_pid_rusage failed for pid %d: returned %d", pid, ret)
	}

	return &ProcRusage{
		UserTime:     uint64(ri.ri_user_time),
		SystemTime:   uint64(ri.ri_system_time),
		ResidentSize: uint64(ri.ri_resident_size),
		VirtualSize:  uint64(ri.ri_virtual_size),
	}, nil
}
```

**Step 3: Run test to verify it works (on macOS) or compiles (cross-compile check)**

Run: `GOOS=darwin go build ./internal/platform/darwin/...`
Expected: Build succeeds (tests require actual macOS to run)

**Step 4: Commit**

```bash
git add internal/platform/darwin/rusage_darwin.go internal/platform/darwin/rusage_darwin_test.go
git commit -m "feat(darwin): add proc_pid_rusage wrapper for CPU stats"
```

---

## Task 2: Implement CPU monitor

**Files:**
- Create: `internal/platform/darwin/cpu_monitor.go`
- Create: `internal/platform/darwin/cpu_monitor_test.go`

**Step 1: Write the test file**

Create `internal/platform/darwin/cpu_monitor_test.go`:

```go
//go:build darwin

package darwin

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestCPUMonitorCalculatePercent(t *testing.T) {
	m := &cpuMonitor{
		pid:          1, // dummy, won't actually call rusage in this test
		limitPercent: 50,
		interval:     100 * time.Millisecond,
		lastCPUTime:  1000000000, // 1 second of CPU time
		lastSample:   time.Now().Add(-1 * time.Second),
	}

	// Simulate 500ms of CPU time over 1 second = 50%
	currentCPUTime := uint64(1500000000) // 1.5 seconds total
	elapsed := time.Second

	percent := m.calculateCPUPercentFromDelta(currentCPUTime, elapsed)

	// Should be approximately 50%
	if percent < 45 || percent > 55 {
		t.Errorf("expected ~50%%, got %.2f%%", percent)
	}
}

func TestCPUMonitorStartStop(t *testing.T) {
	var stopped atomic.Bool

	m := &cpuMonitor{
		pid:          -1, // invalid PID so rusage fails gracefully
		limitPercent: 50,
		interval:     50 * time.Millisecond,
		stopCh:       make(chan struct{}),
		onStop: func() {
			stopped.Store(true)
		},
	}

	go m.run()

	// Let it run a few cycles
	time.Sleep(150 * time.Millisecond)

	// Stop the monitor
	m.stop()

	// Verify it stopped
	time.Sleep(100 * time.Millisecond)
	if !stopped.Load() {
		t.Error("monitor did not stop")
	}
}
```

**Step 2: Write the CPU monitor implementation**

Create `internal/platform/darwin/cpu_monitor.go`:

```go
//go:build darwin

package darwin

import (
	"log/slog"
	"sync"
	"syscall"
	"time"
)

// cpuMonitor monitors CPU usage of a process and throttles if needed.
type cpuMonitor struct {
	pid            int
	limitPercent   uint32
	interval       time.Duration
	lastCPUTime    uint64
	lastSample     time.Time
	lastCPUPercent float64

	mu       sync.Mutex
	stopCh   chan struct{}
	stopped  bool
	onStop   func() // callback when monitor exits
}

// newCPUMonitor creates a new CPU monitor for a process.
func newCPUMonitor(pid int, limitPercent uint32) *cpuMonitor {
	return &cpuMonitor{
		pid:          pid,
		limitPercent: limitPercent,
		interval:     500 * time.Millisecond,
		stopCh:       make(chan struct{}),
	}
}

// start begins monitoring in a goroutine.
func (m *cpuMonitor) start() {
	// Initialize baseline
	if rusage, err := getProcRusage(m.pid); err == nil {
		m.lastCPUTime = rusage.UserTime + rusage.SystemTime
	}
	m.lastSample = time.Now()

	go m.run()
}

// stop signals the monitor to stop.
func (m *cpuMonitor) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return
	}
	m.stopped = true
	close(m.stopCh)
}

// run is the main monitoring loop.
func (m *cpuMonitor) run() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	defer func() {
		if m.onStop != nil {
			m.onStop()
		}
	}()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if !m.processAlive() {
				return
			}
			m.checkAndThrottle()
		}
	}
}

// processAlive checks if the process still exists.
func (m *cpuMonitor) processAlive() bool {
	// Signal 0 checks if process exists without sending a signal
	err := syscall.Kill(m.pid, 0)
	return err == nil
}

// checkAndThrottle checks CPU usage and throttles if over limit.
func (m *cpuMonitor) checkAndThrottle() {
	rusage, err := getProcRusage(m.pid)
	if err != nil {
		slog.Debug("cpu monitor: failed to get rusage", "pid", m.pid, "error", err)
		return
	}

	currentCPUTime := rusage.UserTime + rusage.SystemTime
	elapsed := time.Since(m.lastSample)

	cpuPercent := m.calculateCPUPercentFromDelta(currentCPUTime, elapsed)
	m.lastCPUPercent = cpuPercent
	m.lastCPUTime = currentCPUTime
	m.lastSample = time.Now()

	if cpuPercent > float64(m.limitPercent) {
		m.throttle(cpuPercent)
	}
}

// calculateCPUPercentFromDelta calculates CPU percentage from time delta.
func (m *cpuMonitor) calculateCPUPercentFromDelta(currentCPUTime uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}

	cpuDelta := currentCPUTime - m.lastCPUTime
	// CPU time is in nanoseconds, elapsed is also in nanoseconds
	percent := (float64(cpuDelta) / float64(elapsed.Nanoseconds())) * 100
	return percent
}

// throttle pauses the process proportionally to how much it exceeded the limit.
func (m *cpuMonitor) throttle(cpuPercent float64) {
	// Calculate how long to pause based on excess
	// If at 100% and limit is 50%, pause for half the interval
	excess := cpuPercent - float64(m.limitPercent)
	if excess <= 0 {
		return
	}

	pauseRatio := excess / cpuPercent
	pauseDuration := time.Duration(float64(m.interval) * pauseRatio)

	// Cap pause duration to interval
	if pauseDuration > m.interval {
		pauseDuration = m.interval
	}

	slog.Debug("cpu monitor: throttling", "pid", m.pid, "cpu", cpuPercent, "limit", m.limitPercent, "pause", pauseDuration)

	// SIGSTOP pauses the process
	if err := syscall.Kill(m.pid, syscall.SIGSTOP); err != nil {
		slog.Debug("cpu monitor: SIGSTOP failed", "pid", m.pid, "error", err)
		return
	}

	time.Sleep(pauseDuration)

	// SIGCONT resumes the process
	if err := syscall.Kill(m.pid, syscall.SIGCONT); err != nil {
		slog.Debug("cpu monitor: SIGCONT failed", "pid", m.pid, "error", err)
	}
}

// getCPUPercent returns the last measured CPU percentage.
func (m *cpuMonitor) getCPUPercent() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCPUPercent
}
```

**Step 3: Run test to verify it compiles**

Run: `GOOS=darwin go build ./internal/platform/darwin/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/darwin/cpu_monitor.go internal/platform/darwin/cpu_monitor_test.go
git commit -m "feat(darwin): add CPU monitor with SIGSTOP/SIGCONT throttling"
```

---

## Task 3: Implement ResourceHandle

**Files:**
- Create: `internal/platform/darwin/resource_handle.go`
- Create: `internal/platform/darwin/resource_handle_test.go`

**Step 1: Write the test file**

Create `internal/platform/darwin/resource_handle_test.go`:

```go
//go:build darwin

package darwin

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestResourceHandleGetRlimits(t *testing.T) {
	h := &ResourceHandle{
		name: "test",
		config: platform.ResourceConfig{
			MaxMemoryMB: 512,
		},
		rlimitAS: 512 * 1024 * 1024,
	}

	rlimits := h.GetRlimits()
	if len(rlimits) != 1 {
		t.Fatalf("expected 1 rlimit, got %d", len(rlimits))
	}

	if rlimits[0].Resource != RlimitAS {
		t.Errorf("expected RLIMIT_AS, got %d", rlimits[0].Resource)
	}

	expected := uint64(512 * 1024 * 1024)
	if rlimits[0].Cur != expected {
		t.Errorf("expected cur=%d, got %d", expected, rlimits[0].Cur)
	}
}

func TestResourceHandleGetRlimitsEmpty(t *testing.T) {
	h := &ResourceHandle{
		name:   "test",
		config: platform.ResourceConfig{},
	}

	rlimits := h.GetRlimits()
	if len(rlimits) != 0 {
		t.Errorf("expected 0 rlimits for no memory limit, got %d", len(rlimits))
	}
}

func TestResourceHandleStats(t *testing.T) {
	h := &ResourceHandle{
		name: "test",
	}

	// Stats should return empty stats when no processes assigned
	stats := h.Stats()
	if stats.MemoryMB != 0 {
		t.Errorf("expected 0 memory, got %d", stats.MemoryMB)
	}
}
```

**Step 2: Write the ResourceHandle implementation**

Create `internal/platform/darwin/resource_handle.go`:

```go
//go:build darwin

package darwin

import (
	"sync"
	"syscall"

	"github.com/agentsh/agentsh/internal/platform"
)

// RlimitAS is the syscall constant for RLIMIT_AS (address space limit).
const RlimitAS = syscall.RLIMIT_AS

// RlimitConfig represents an rlimit to be applied to a process.
type RlimitConfig struct {
	Resource int    // e.g., syscall.RLIMIT_AS
	Cur      uint64 // soft limit
	Max      uint64 // hard limit
}

// ResourceHandle represents applied resource limits on macOS.
type ResourceHandle struct {
	name   string
	config platform.ResourceConfig

	mu sync.Mutex

	// Memory limiting via RLIMIT_AS
	rlimitAS uint64 // 0 means no limit

	// CPU monitoring
	monitors map[int]*cpuMonitor // pid -> monitor
	pids     []int
}

// newResourceHandle creates a new resource handle.
func newResourceHandle(name string, config platform.ResourceConfig) *ResourceHandle {
	h := &ResourceHandle{
		name:     name,
		config:   config,
		monitors: make(map[int]*cpuMonitor),
	}

	if config.MaxMemoryMB > 0 {
		h.rlimitAS = config.MaxMemoryMB * 1024 * 1024
	}

	return h
}

// GetRlimits returns the rlimits to apply in the child process.
func (h *ResourceHandle) GetRlimits() []RlimitConfig {
	var limits []RlimitConfig

	if h.rlimitAS > 0 {
		limits = append(limits, RlimitConfig{
			Resource: RlimitAS,
			Cur:      h.rlimitAS,
			Max:      h.rlimitAS,
		})
	}

	return limits
}

// AssignProcess adds a process to this resource handle.
func (h *ResourceHandle) AssignProcess(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pids = append(h.pids, pid)

	// Start CPU monitoring if CPU limit is configured
	if h.config.MaxCPUPercent > 0 {
		monitor := newCPUMonitor(pid, h.config.MaxCPUPercent)
		h.monitors[pid] = monitor
		monitor.start()
	}

	return nil
}

// Stats returns current resource usage.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := platform.ResourceStats{}

	for _, pid := range h.pids {
		rusage, err := getProcRusage(pid)
		if err != nil {
			continue
		}
		stats.MemoryMB += rusage.ResidentSize / (1024 * 1024)
	}

	// Get CPU percent from first active monitor
	for _, monitor := range h.monitors {
		stats.CPUPercent = monitor.getCPUPercent()
		break
	}

	stats.ProcessCount = len(h.pids)

	return stats
}

// Release stops all monitors and cleans up.
func (h *ResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Stop all CPU monitors
	for pid, monitor := range h.monitors {
		// Send SIGCONT in case process is stopped
		syscall.Kill(pid, syscall.SIGCONT)
		monitor.stop()
	}

	h.monitors = make(map[int]*cpuMonitor)
	h.pids = nil

	return nil
}

// Compile-time interface check
var _ platform.ResourceHandle = (*ResourceHandle)(nil)
```

**Step 3: Run test to verify it compiles**

Run: `GOOS=darwin go build ./internal/platform/darwin/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/darwin/resource_handle.go internal/platform/darwin/resource_handle_test.go
git commit -m "feat(darwin): add ResourceHandle with rlimit and CPU monitor support"
```

---

## Task 4: Update ResourceLimiter implementation

**Files:**
- Modify: `internal/platform/darwin/resources.go`
- Create: `internal/platform/darwin/resources_test.go`

**Step 1: Write the test file**

Create `internal/platform/darwin/resources_test.go`:

```go
//go:build darwin

package darwin

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestResourceLimiterAvailable(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Error("ResourceLimiter should be available on macOS")
	}
}

func TestResourceLimiterSupportedLimits(t *testing.T) {
	r := NewResourceLimiter()
	supported := r.SupportedLimits()

	hasMemory := false
	hasCPU := false
	for _, rt := range supported {
		if rt == platform.ResourceMemory {
			hasMemory = true
		}
		if rt == platform.ResourceCPU {
			hasCPU = true
		}
	}

	if !hasMemory {
		t.Error("expected ResourceMemory to be supported")
	}
	if !hasCPU {
		t.Error("expected ResourceCPU to be supported")
	}
}

func TestResourceLimiterApply(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:          "test-limits",
		MaxMemoryMB:   256,
		MaxCPUPercent: 50,
	}

	handle, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if handle == nil {
		t.Fatal("expected non-nil handle")
	}

	// Cleanup
	handle.Release()
}

func TestResourceLimiterApplyUnsupportedProcessCount(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:         "test-limits",
		MaxProcesses: 10,
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported MaxProcesses")
	}
}

func TestResourceLimiterApplyUnsupportedDiskIO(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:            "test-limits",
		MaxDiskReadMBps: 100,
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported disk I/O limits")
	}
}

func TestResourceLimiterApplyUnsupportedAffinity(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:        "test-limits",
		CPUAffinity: []int{0, 1},
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported CPU affinity")
	}
}
```

**Step 2: Update the ResourceLimiter implementation**

Replace `internal/platform/darwin/resources.go` with:

```go
//go:build darwin

package darwin

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for macOS.
// Uses setrlimit for memory limits and userspace monitoring for CPU limits.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
	mu              sync.Mutex
	handles         map[string]*ResourceHandle
}

// NewResourceLimiter creates a new macOS resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available: true,
		supportedLimits: []platform.ResourceType{
			platform.ResourceMemory,
			platform.ResourceCPU,
		},
		handles: make(map[string]*ResourceHandle),
	}
	return r
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	// Validate: reject unsupported limits
	if config.MaxProcesses > 0 {
		return nil, fmt.Errorf("process count limits not supported on macOS")
	}
	if config.MaxDiskReadMBps > 0 || config.MaxDiskWriteMBps > 0 {
		return nil, fmt.Errorf("disk I/O limits not supported on macOS")
	}
	if len(config.CPUAffinity) > 0 {
		return nil, fmt.Errorf("CPU affinity not supported on macOS")
	}
	if config.MaxNetworkMbps > 0 {
		return nil, fmt.Errorf("network bandwidth limits not supported on macOS")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	if _, exists := r.handles[config.Name]; exists {
		return nil, fmt.Errorf("resource handle %q already exists", config.Name)
	}

	handle := newResourceHandle(config.Name, config)
	r.handles[config.Name] = handle

	return handle, nil
}

// GetHandle returns an existing handle by name.
func (r *ResourceLimiter) GetHandle(name string) (*ResourceHandle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.handles[name]
	return h, ok
}

// Release removes a resource handle.
func (r *ResourceLimiter) Release(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.handles[name]
	if !ok {
		return fmt.Errorf("handle %q not found", name)
	}

	if err := h.Release(); err != nil {
		return err
	}

	delete(r.handles, name)
	return nil
}

// Compile-time interface check
var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
```

**Step 3: Run test to verify it compiles**

Run: `GOOS=darwin go build ./internal/platform/darwin/...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/platform/darwin/resources.go internal/platform/darwin/resources_test.go
git commit -m "feat(darwin): implement ResourceLimiter with memory and CPU support"
```

---

## Task 5: Integrate with Sandbox for rlimit application

**Files:**
- Modify: `internal/platform/darwin/sandbox.go`

**Step 1: Read current sandbox implementation to understand integration point**

The sandbox uses `exec.CommandContext` with `sandbox-exec`. We need to apply rlimits in the child process before exec. Go's `syscall.SysProcAttr` doesn't directly support rlimits, so we need to use a different approach.

**Step 2: Add SandboxConfig field for ResourceHandle**

First, check if `platform.SandboxConfig` already has a field for this. If not, we'll add one to the darwin-specific Sandbox struct.

**Step 3: Update Sandbox struct and Execute method**

Add to `internal/platform/darwin/sandbox.go` after the imports:

```go
// Add this method to Sandbox struct:

// SetResourceHandle associates a resource handle with this sandbox.
func (s *Sandbox) SetResourceHandle(h *ResourceHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resourceHandle = h
}
```

Add `resourceHandle *ResourceHandle` field to Sandbox struct:

```go
// Sandbox represents a sandboxed execution environment on macOS.
type Sandbox struct {
	id             string
	config         platform.SandboxConfig
	profile        string
	resourceHandle *ResourceHandle // Add this field
	mu             sync.Mutex
	closed         bool
}
```

Update the Execute method to apply rlimits and register with resource handle. Since Go's exec doesn't support pre-exec hooks for rlimits easily, we'll set them via the resource handle after the process starts (for CPU monitoring) and document that memory limits require the sandbox to be started with a wrapper that applies rlimits.

For a cleaner approach, we can use `syscall.Setrlimit` in combination with `Cmd.SysProcAttr.Credential` - but actually the cleanest is to have the Execute method:
1. After starting the process, call `resourceHandle.AssignProcess(pid)` for CPU monitoring
2. Memory limits via RLIMIT_AS would need to be applied before exec, which requires either:
   a. A wrapper script that calls `ulimit`
   b. Using `Cmd.SysProcAttr` with a custom fork/exec (complex)

For simplicity in this implementation, we'll:
1. Apply CPU monitoring after process starts
2. Document that RLIMIT_AS should be set via sandbox profile or accept the limitation

Actually, looking more carefully, Go 1.20+ supports `SysProcAttr.Rlimit` on some platforms. Let's check if it's available on darwin, and if not, we'll use the monitoring-only approach for now.

**Step 4: Update Execute to integrate CPU monitoring**

Modify the `Execute` method in `internal/platform/darwin/sandbox.go`:

After `err := execCmd.Run()` section, add PID tracking for the resource handle. Since `exec.Cmd.Run()` waits for completion, we need to use `Start()` instead for long-running processes. However, looking at the current code, it uses `Run()` which blocks.

For background processes, we'd need a different API. For now, let's add the resource handle integration for the `Start()`-based API if it exists, or create one.

Looking at the interface, `Execute` returns `ExecResult` after completion. For CPU monitoring to be useful, we need a streaming/async execution model. Let's check if there's an `ExecuteAsync` or similar.

**Simplified approach:** Since the current `Execute` blocks until completion, CPU monitoring during execution would require changing to `Start()`. Let's add a new method `ExecuteWithResources` that:
1. Uses `Start()` instead of `Run()`
2. Registers with ResourceHandle for CPU monitoring
3. Waits for completion
4. Returns result

Add this to `internal/platform/darwin/sandbox.go`:

```go
// ExecuteWithResources runs a command with resource limiting.
func (s *Sandbox) ExecuteWithResources(ctx context.Context, rh *ResourceHandle, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Build sandbox-exec command with inline profile
	sandboxArgs := []string{"-p", s.profile, cmd}
	sandboxArgs = append(sandboxArgs, args...)

	execCmd := exec.CommandContext(ctx, "sandbox-exec", sandboxArgs...)
	if s.config.WorkspacePath != "" {
		execCmd.Dir = s.config.WorkspacePath
	}

	// Set environment variables if specified
	if len(s.config.Environment) > 0 {
		execCmd.Env = make([]string, 0, len(s.config.Environment))
		for k, v := range s.config.Environment {
			execCmd.Env = append(execCmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	// Start the process (non-blocking)
	if err := execCmd.Start(); err != nil {
		return nil, err
	}

	// Register with resource handle for CPU monitoring
	if rh != nil {
		rh.AssignProcess(execCmd.Process.Pid)
	}

	// Wait for completion
	err := execCmd.Wait()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &platform.ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}, nil
}
```

**Step 5: Add test for ExecuteWithResources**

Add to `internal/platform/darwin/sandbox_test.go` (or create if doesn't exist):

```go
func TestSandboxExecuteWithResources(t *testing.T) {
	// This test verifies the integration compiles and basic flow works
	// Full integration testing requires macOS

	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("sandbox-exec not available")
	}

	sb, err := m.Create(platform.SandboxConfig{
		Name:          "test-resources",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sb.Close()

	// Create resource handle
	rl := NewResourceLimiter()
	rh, err := rl.Apply(platform.ResourceConfig{
		Name:          "test",
		MaxCPUPercent: 80,
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	defer rh.Release()

	// Execute with resources
	result, err := sb.(*Sandbox).ExecuteWithResources(
		context.Background(),
		rh.(*ResourceHandle),
		"echo", "hello",
	)
	if err != nil {
		t.Fatalf("ExecuteWithResources failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}
```

**Step 6: Commit**

```bash
git add internal/platform/darwin/sandbox.go internal/platform/darwin/sandbox_test.go
git commit -m "feat(darwin): integrate resource handle with sandbox execution"
```

---

## Task 6: Add stub for non-cgo builds

**Files:**
- Create: `internal/platform/darwin/rusage_nocgo.go`

**Step 1: Create nocgo stub**

Create `internal/platform/darwin/rusage_nocgo.go`:

```go
//go:build darwin && !cgo

package darwin

import "fmt"

// ProcRusage contains resource usage information for a process.
type ProcRusage struct {
	UserTime     uint64
	SystemTime   uint64
	ResidentSize uint64
	VirtualSize  uint64
}

// getProcRusage is a stub for non-cgo builds.
func getProcRusage(pid int) (*ProcRusage, error) {
	return nil, fmt.Errorf("proc_pid_rusage requires cgo")
}
```

**Step 2: Update rusage_darwin.go build constraint**

Update the build tag in `internal/platform/darwin/rusage_darwin.go`:

```go
//go:build darwin && cgo
```

**Step 3: Commit**

```bash
git add internal/platform/darwin/rusage_nocgo.go internal/platform/darwin/rusage_darwin.go
git commit -m "feat(darwin): add nocgo stub for rusage"
```

---

## Task 7: Final verification and cleanup

**Step 1: Run all tests**

Run: `go test ./...`
Expected: All tests pass

**Step 2: Run go vet**

Run: `go vet ./internal/platform/darwin/...`
Expected: No errors

**Step 3: Run gofmt**

Run: `gofmt -l internal/platform/darwin/`
Expected: No output (already formatted) or fix any issues

**Step 4: Verify cross-compilation**

Run: `GOOS=darwin GOARCH=amd64 go build ./...`
Run: `GOOS=darwin GOARCH=arm64 go build ./...`
Expected: Both succeed

**Step 5: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: cleanup and formatting" || echo "Nothing to commit"
```

**Step 6: Push feature branch**

```bash
git push -u origin feature/macos-resource-control
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | proc_pid_rusage cgo wrapper | rusage_darwin.go, rusage_darwin_test.go |
| 2 | CPU monitor implementation | cpu_monitor.go, cpu_monitor_test.go |
| 3 | ResourceHandle implementation | resource_handle.go, resource_handle_test.go |
| 4 | ResourceLimiter update | resources.go, resources_test.go |
| 5 | Sandbox integration | sandbox.go, sandbox_test.go |
| 6 | Non-cgo stub | rusage_nocgo.go |
| 7 | Final verification | - |
