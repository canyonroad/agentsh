# Ptrace Phase 3: Production Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add max_hold_ms timeout enforcement, ptrace-specific Prometheus metrics, graceful degradation on tracee exit, and overhead benchmarks.

**Architecture:** Extend the existing ptrace tracer with a timeout sweep in the event loop, a `Metrics` interface wired into `PrometheusCollector`, ESRCH-aware error handling, and Go benchmark tests behind integration build tags.

**Tech Stack:** Go, `golang.org/x/sys/unix`, `pkg/observability` (Prometheus text format)

---

### Task 1: Ptrace Metrics Interface

**Files:**
- Create: `internal/ptrace/metrics.go`
- Test: `internal/ptrace/metrics_test.go`

**Step 1: Write the test**

```go
//go:build linux

package ptrace

import (
	"testing"
)

func TestNopMetrics(t *testing.T) {
	// nopMetrics must not panic on any call.
	var m nopMetrics
	m.SetTraceeCount(5)
	m.IncAttachFailure("eperm")
	m.IncTimeout()
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestNopMetrics ./internal/ptrace/`
Expected: FAIL — `nopMetrics` not defined

**Step 3: Write the implementation**

```go
//go:build linux

package ptrace

// Metrics collects ptrace-specific operational metrics.
// Implementations must be safe for concurrent use.
type Metrics interface {
	SetTraceeCount(n int)
	IncAttachFailure(reason string)
	IncTimeout()
}

// nopMetrics is a no-op implementation used when no metrics collector is configured.
type nopMetrics struct{}

func (nopMetrics) SetTraceeCount(int)        {}
func (nopMetrics) IncAttachFailure(string)    {}
func (nopMetrics) IncTimeout()               {}
```

**Step 4: Run test to verify it passes**

Run: `go test -run TestNopMetrics ./internal/ptrace/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/metrics.go internal/ptrace/metrics_test.go
git commit -m "feat(ptrace): add Metrics interface with nop implementation"
```

---

### Task 2: Wire Metrics into Tracer

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Add Metrics field to TracerConfig and Tracer**

In `TracerConfig` (line 107), add:
```go
Metrics Metrics
```

In `NewTracer` (line 163), after setting other fields, add:
```go
metrics := cfg.Metrics
if metrics == nil {
    metrics = nopMetrics{}
}
```

Store it on the `Tracer` struct as field `metrics Metrics`.

**Step 2: Call SetTraceeCount after every tracee map mutation**

Add `t.metrics.SetTraceeCount(len(t.tracees))` at the end of:
- `attachThread` (after `t.tracees[tid] = ...`, line 96) — inside the lock
- `handleNewChild` (after `t.tracees[tid] = ...`, line 417) — inside the lock
- `handleExit` (after `delete(t.tracees, tid)`, line 471) — inside the lock
- `handleExecEvent` (after the cleanup loop, before `t.mu.Unlock()`, line 460) — inside the lock

**Step 3: Call IncAttachFailure on SEIZE errors**

In `attachThread` (line 39), when `PtraceSeize` returns an error:
```go
if err != nil {
    reason := "other"
    if errors.Is(err, unix.ESRCH) {
        reason = "esrch"
    } else if errors.Is(err, unix.EPERM) {
        reason = "eperm"
    }
    t.metrics.IncAttachFailure(reason)
    return fmt.Errorf("PTRACE_SEIZE tid %d: %w", tid, err)
}
```

Add `"errors"` to imports in `attach.go`.

**Step 4: Verify build**

Run: `go build ./internal/ptrace/`
Expected: OK

**Step 5: Run existing tests**

Run: `go test ./internal/ptrace/...`
Expected: PASS — existing tests use nil Metrics which falls back to nopMetrics

**Step 6: Commit**

```bash
git add internal/ptrace/tracer.go internal/ptrace/attach.go
git commit -m "feat(ptrace): wire Metrics interface into tracer and attach"
```

---

### Task 3: Add Ptrace Metrics to PrometheusCollector

**Files:**
- Modify: `pkg/observability/prometheus.go`
- Modify: `pkg/observability/prometheus_test.go`

**Step 1: Write the test**

Add to `prometheus_test.go`:

```go
func TestPrometheusCollector_PtraceMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	c.SetPtraceTraceeCount(5)
	c.IncPtraceAttachFailure("eperm")
	c.IncPtraceAttachFailure("eperm")
	c.IncPtraceAttachFailure("esrch")
	c.IncPtraceTimeout()

	handler := c.Handler(HandlerOptions{})
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	body := w.Body.String()

	expected := []string{
		"agentsh_ptrace_tracees_active 5",
		"agentsh_ptrace_attach_failures_total",
		"agentsh_ptrace_timeouts_total 1",
	}
	for _, m := range expected {
		if !strings.Contains(body, m) {
			t.Errorf("response missing: %s", m)
		}
	}
}

func TestPrometheusCollector_PtraceNilSafety(t *testing.T) {
	var c *PrometheusCollector
	// Must not panic
	c.SetPtraceTraceeCount(1)
	c.IncPtraceAttachFailure("esrch")
	c.IncPtraceTimeout()
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestPrometheusCollector_Ptrace ./pkg/observability/`
Expected: FAIL — methods not defined

**Step 3: Add ptrace fields and methods to PrometheusCollector**

In `prometheus.go`, add fields to `PrometheusCollector`:
```go
// Ptrace metrics
ptraceTracees       atomic.Int64
ptraceAttachFails   sync.Map // key: reason -> *atomic.Uint64
ptraceTimeouts      atomic.Uint64
```

Add methods:
```go
// SetPtraceTraceeCount sets the current ptrace tracee gauge.
func (c *PrometheusCollector) SetPtraceTraceeCount(n int) {
	if c == nil {
		return
	}
	c.ptraceTracees.Store(int64(n))
}

// IncPtraceAttachFailure increments ptrace attach failure counter by reason.
func (c *PrometheusCollector) IncPtraceAttachFailure(reason string) {
	if c == nil {
		return
	}
	ptr, _ := c.ptraceAttachFails.LoadOrStore(reason, &atomic.Uint64{})
	ptr.(*atomic.Uint64).Add(1)
}

// IncPtraceTimeout increments the ptrace max_hold_ms timeout counter.
func (c *PrometheusCollector) IncPtraceTimeout() {
	if c == nil {
		return
	}
	c.ptraceTimeouts.Add(1)
}
```

In the `Handler` method, before the final `}`, add ptrace metrics output:
```go
// Ptrace metrics
fmt.Fprint(w, "# HELP agentsh_ptrace_tracees_active Current number of ptrace-traced threads.\n")
fmt.Fprint(w, "# TYPE agentsh_ptrace_tracees_active gauge\n")
fmt.Fprintf(w, "agentsh_ptrace_tracees_active %d\n\n", c.ptraceTracees.Load())

c.writePtraceAttachFailures(w)

fmt.Fprint(w, "# HELP agentsh_ptrace_timeouts_total Ptrace max_hold_ms timeouts.\n")
fmt.Fprint(w, "# TYPE agentsh_ptrace_timeouts_total counter\n")
fmt.Fprintf(w, "agentsh_ptrace_timeouts_total %d\n\n", c.ptraceTimeouts.Load())
```

Add helper:
```go
func (c *PrometheusCollector) writePtraceAttachFailures(w http.ResponseWriter) {
	keys := snapshotMapKeys(&c.ptraceAttachFails)
	if len(keys) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP agentsh_ptrace_attach_failures_total Ptrace attach failures by reason.\n")
	fmt.Fprint(w, "# TYPE agentsh_ptrace_attach_failures_total counter\n")
	for _, reason := range keys {
		ptr, _ := c.ptraceAttachFails.Load(reason)
		n := ptr.(*atomic.Uint64).Load()
		fmt.Fprintf(w, "agentsh_ptrace_attach_failures_total{reason=%q} %d\n", escapeLabelValue(reason), n)
	}
	fmt.Fprint(w, "\n")
}
```

**Step 4: Run tests**

Run: `go test ./pkg/observability/...`
Expected: PASS (including existing tests)

**Step 5: Commit**

```bash
git add pkg/observability/prometheus.go pkg/observability/prometheus_test.go
git commit -m "feat(observability): add ptrace metrics to PrometheusCollector"
```

---

### Task 4: PrometheusCollector as ptrace.Metrics adapter

**Files:**
- Create: `internal/ptrace/metrics_prometheus.go`
- Test: `internal/ptrace/metrics_prometheus_test.go`

**Step 1: Write the test**

```go
//go:build linux

package ptrace

import (
	"testing"
)

type mockPrometheusCollector struct {
	traceeCount   int
	attachReasons []string
	timeouts      int
}

func (m *mockPrometheusCollector) SetPtraceTraceeCount(n int)      { m.traceeCount = n }
func (m *mockPrometheusCollector) IncPtraceAttachFailure(r string) { m.attachReasons = append(m.attachReasons, r) }
func (m *mockPrometheusCollector) IncPtraceTimeout()               { m.timeouts++ }

func TestPrometheusMetrics(t *testing.T) {
	mock := &mockPrometheusCollector{}
	m := NewPrometheusMetrics(mock)

	m.SetTraceeCount(3)
	if mock.traceeCount != 3 {
		t.Errorf("traceeCount = %d, want 3", mock.traceeCount)
	}

	m.IncAttachFailure("eperm")
	if len(mock.attachReasons) != 1 || mock.attachReasons[0] != "eperm" {
		t.Errorf("attachReasons = %v, want [eperm]", mock.attachReasons)
	}

	m.IncTimeout()
	if mock.timeouts != 1 {
		t.Errorf("timeouts = %d, want 1", mock.timeouts)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -run TestPrometheusMetrics ./internal/ptrace/`
Expected: FAIL

**Step 3: Write the adapter**

```go
//go:build linux

package ptrace

// PtraceMetricsCollector is the interface that PrometheusCollector satisfies.
// Defined here to avoid a dependency from ptrace -> observability.
type PtraceMetricsCollector interface {
	SetPtraceTraceeCount(n int)
	IncPtraceAttachFailure(reason string)
	IncPtraceTimeout()
}

// prometheusMetrics adapts a PtraceMetricsCollector to the ptrace.Metrics interface.
type prometheusMetrics struct {
	c PtraceMetricsCollector
}

// NewPrometheusMetrics creates a Metrics implementation backed by a PtraceMetricsCollector.
func NewPrometheusMetrics(c PtraceMetricsCollector) Metrics {
	return &prometheusMetrics{c: c}
}

func (m *prometheusMetrics) SetTraceeCount(n int)        { m.c.SetPtraceTraceeCount(n) }
func (m *prometheusMetrics) IncAttachFailure(reason string) { m.c.IncPtraceAttachFailure(reason) }
func (m *prometheusMetrics) IncTimeout()                    { m.c.IncPtraceTimeout() }
```

**Step 4: Run tests**

Run: `go test ./internal/ptrace/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ptrace/metrics_prometheus.go internal/ptrace/metrics_prometheus_test.go
git commit -m "feat(ptrace): add PrometheusCollector adapter for ptrace.Metrics"
```

---

### Task 5: max_hold_ms Timeout Enforcement

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Add ParkedAt to TraceeState**

Add to `TraceeState` struct (line 126):
```go
ParkedAt time.Time // set when tracee is parked for async approval
```

**Step 2: Set ParkedAt when parking**

The current code parks tracees by adding to `parkedTracees` map. Search for where tracees get parked — this happens externally via the resume queue pattern. The tracee is left in ptrace-stop without calling `allowSyscall`/`denySyscall`. We need to find where parking happens and record the timestamp.

Looking at the code, parking is not explicitly done in `tracer.go` today — it's an external concern. We need to add a `ParkTracee` method that handlers can call instead of directly leaving the tracee stopped:

```go
// ParkTracee marks a tracee as parked (awaiting async approval).
// The tracee is left in ptrace-stop. Call ResumeQueue to send the decision.
func (t *Tracer) ParkTracee(tid int) {
	t.mu.Lock()
	t.parkedTracees[tid] = struct{}{}
	if state, ok := t.tracees[tid]; ok {
		state.ParkedAt = time.Now()
	}
	t.mu.Unlock()
}
```

**Step 3: Add timeout sweep to event loop**

In `Run()`, replace the `time.After(5 * time.Millisecond)` idle branch (line 609) with a sweep + sleep:

```go
case <-time.After(5 * time.Millisecond):
    t.sweepParkedTimeouts()
```

Add the sweep method:

```go
// sweepParkedTimeouts denies parked tracees that have exceeded max_hold_ms.
func (t *Tracer) sweepParkedTimeouts() {
	if t.cfg.MaxHoldMs <= 0 {
		return
	}
	maxDuration := time.Duration(t.cfg.MaxHoldMs) * time.Millisecond

	t.mu.Lock()
	var expired []int
	for tid := range t.parkedTracees {
		state := t.tracees[tid]
		if state == nil {
			// Tracee already exited — clean up stale parking entry.
			expired = append(expired, tid)
			continue
		}
		if !state.ParkedAt.IsZero() && time.Since(state.ParkedAt) > maxDuration {
			expired = append(expired, tid)
		}
	}
	for _, tid := range expired {
		delete(t.parkedTracees, tid)
	}
	t.mu.Unlock()

	for _, tid := range expired {
		t.mu.Lock()
		state := t.tracees[tid]
		t.mu.Unlock()
		if state == nil {
			continue // already exited
		}
		slog.Warn("ptrace: max_hold_ms timeout, denying syscall",
			"tid", tid,
			"max_hold_ms", t.cfg.MaxHoldMs,
		)
		t.metrics.IncTimeout()
		t.denySyscall(tid, int(unix.EACCES))
	}
}
```

**Step 4: Clear ParkedAt on resume**

In `handleResumeRequest` (line 651), after deleting from parkedTracees, clear `ParkedAt`:
```go
if state, ok := t.tracees[req.TID]; ok {
    state.ParkedAt = time.Time{}
}
```

**Step 5: Verify build**

Run: `go build ./internal/ptrace/`
Expected: OK

**Step 6: Run existing tests**

Run: `go test ./internal/ptrace/...`
Expected: PASS — existing tests don't park tracees, sweep is a no-op

**Step 7: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "feat(ptrace): enforce max_hold_ms timeout on parked tracees"
```

---

### Task 6: Graceful Degradation — Handle Tracee Exit While Parked

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Clean up parked tracees on exit**

In `handleExit` (line 463), add parked tracee cleanup before removing from tracees map:

```go
func (t *Tracer) handleExit(tid int) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state != nil {
		if state.MemFD >= 0 {
			unix.Close(state.MemFD)
		}
		delete(t.tracees, tid)
		if _, parked := t.parkedTracees[tid]; parked {
			delete(t.parkedTracees, tid)
			slog.Warn("ptrace: parked tracee exited before approval", "tid", tid)
		}
		t.metrics.SetTraceeCount(len(t.tracees))
	}
	t.mu.Unlock()
}
```

**Step 2: Guard handleResumeRequest against dead tracees**

Update `handleResumeRequest` (line 651):

```go
func (t *Tracer) handleResumeRequest(req resumeRequest) {
	t.mu.Lock()
	_, parked := t.parkedTracees[req.TID]
	if parked {
		delete(t.parkedTracees, req.TID)
	}
	state := t.tracees[req.TID]
	if state != nil {
		state.ParkedAt = time.Time{}
	}
	t.mu.Unlock()

	if !parked {
		slog.Warn("resume request for non-parked tracee", "tid", req.TID)
		return
	}

	if state == nil {
		slog.Warn("resume request for exited tracee, skipping", "tid", req.TID)
		return
	}

	if req.Allow {
		t.allowSyscall(req.TID)
	} else {
		t.denySyscall(req.TID, req.Errno)
	}
}
```

**Step 3: Verify build and tests**

Run: `go build ./internal/ptrace/ && go test ./internal/ptrace/...`
Expected: OK and PASS

**Step 4: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "fix(ptrace): handle tracee exit while parked and guard resume requests"
```

---

### Task 7: Graceful Degradation — ESRCH Handling in Deny/Allow

**Files:**
- Modify: `internal/ptrace/tracer.go`

**Step 1: Handle ESRCH in allowSyscall**

Update `allowSyscall` (line 224) to handle the case where the tracee has already exited:

```go
func (t *Tracer) allowSyscall(tid int) {
	var err error
	if t.prefilterActive {
		err = unix.PtraceCont(tid, 0)
	} else {
		err = unix.PtraceSyscall(tid, 0)
	}
	if err != nil && errors.Is(err, unix.ESRCH) {
		t.handleExit(tid)
	}
}
```

**Step 2: Handle ESRCH in denySyscall**

In `denySyscall` (line 233), `getRegs` can fail with ESRCH. Update the error path:

```go
func (t *Tracer) denySyscall(tid int, errno int) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.handleExit(tid)
			return nil
		}
		return err
	}
	// ... rest unchanged ...
```

**Step 3: Add `"errors"` import to tracer.go**

Add `"errors"` to the import block.

**Step 4: Verify build and tests**

Run: `go build ./internal/ptrace/ && go test ./internal/ptrace/...`
Expected: OK and PASS

**Step 5: Commit**

```bash
git add internal/ptrace/tracer.go
git commit -m "fix(ptrace): handle ESRCH in allow/deny by cleaning up dead tracee"
```

---

### Task 8: Overhead Benchmarks

**Files:**
- Create: `internal/ptrace/benchmark_test.go`

**Step 1: Write BenchmarkExecOverhead**

```go
//go:build integration && linux

package ptrace

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func BenchmarkExecOverhead(b *testing.B) {
	requirePtraceBench(b)

	handler := &mockExecHandler{defaultAllow: true}
	tr := NewTracer(TracerConfig{
		TraceExecve:      true,
		SeccompPrefilter: false,
		ExecHandler:      handler,
		MaxHoldMs:        5000,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/true")
		cmd.Start()
		tr.AttachPID(cmd.Process.Pid)
		cmd.Wait()
	}
	b.StopTimer()

	cancel()
}

func BenchmarkFileIOOverhead(b *testing.B) {
	requirePtraceBench(b)

	fileHandler := &mockFileHandler{allow: true}
	tr := NewTracer(TracerConfig{
		TraceFile:        true,
		SeccompPrefilter: false,
		FileHandler:      fileHandler,
		MaxHoldMs:        5000,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	// Create a script that does rapid open/close
	dir := b.TempDir()
	script := dir + "/bench.sh"
	writeScript(b, script, `#!/bin/sh
i=0
while [ $i -lt 100 ]; do
    cat /dev/null
    i=$((i+1))
done
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/sh", script)
		cmd.Start()
		tr.AttachPID(cmd.Process.Pid)
		cmd.Wait()
	}
	b.StopTimer()

	cancel()
}

func requirePtraceBench(b *testing.B) {
	b.Helper()
	cmd := exec.Command("/bin/sleep", "0.01")
	if err := cmd.Start(); err != nil {
		b.Skip("cannot start child process")
	}
	pid := cmd.Process.Pid
	err := unix.PtraceSeize(pid)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		b.Skipf("ptrace not available: %v", err)
	}
}

func writeScript(b *testing.B, path, content string) {
	b.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		b.Fatal(err)
	}
}

// mockFileHandler for benchmarks
type mockFileHandler struct {
	allow bool
}

func (m *mockFileHandler) HandleFile(ctx context.Context, fc FileContext) FileResult {
	return FileResult{Allow: m.allow}
}
```

Note: Add needed imports (`"os"`, `"golang.org/x/sys/unix"`).

**Step 2: Verify build**

Run: `go test -c -tags integration -o /dev/null ./internal/ptrace/`
Expected: Compiles OK

**Step 3: Commit**

```bash
git add internal/ptrace/benchmark_test.go
git commit -m "feat(ptrace): add exec and file I/O overhead benchmarks"
```

---

### Task 9: Final Verification

**Step 1: Build all packages**

Run: `go build ./...`
Expected: OK

**Step 2: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: OK (build tags exclude Linux-only files)

**Step 3: Run all unit tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Run ptrace-specific tests**

Run: `go test -v ./internal/ptrace/ ./pkg/observability/`
Expected: PASS, including new metrics tests

**Step 5: Commit any final fixes if needed**
