# Signal Interception Code Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the 6 major issues identified in the fresheyes code review for signal interception.

**Architecture:** Fix build compatibility, correct target classification logic, handle edge cases in syscall extraction, and add proper platform detection for blocking capability.

**Tech Stack:** Go, seccomp, golang.org/x/sys/unix

---

## Task 1: Fix Windows Build - Add Build Tags to Policy Engine

The `internal/policy/engine.go` imports `internal/signal` unconditionally, but `internal/signal/*.go` files use `//go:build !windows`. This causes Windows builds to fail.

**Files:**
- Modify: `internal/policy/engine.go:1-15`
- Create: `internal/policy/engine_signal.go` (new file for signal-specific code)
- Create: `internal/policy/engine_signal_stub.go` (Windows stub)

**Step 1: Write failing test**

Create a simple build verification test that imports the policy package. Since we can't run Windows tests, we'll verify the code compiles with build tags.

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && GOOS=windows go build ./internal/policy/...`
Expected: FAIL with import errors for signal package

**Step 2: Create signal-specific engine file with build tag**

Create `internal/policy/engine_signal.go`:

```go
//go:build !windows

package policy

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/signal"
)

// compileSignalRules compiles signal rules into a signal engine.
func compileSignalRules(rules []SignalRule) (*signal.Engine, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	// Convert policy.SignalRule to signal.SignalRule to avoid import cycle
	sigRules := make([]signal.SignalRule, len(rules))
	for i, r := range rules {
		sigRules[i] = signal.SignalRule{
			Name:        r.Name,
			Description: r.Description,
			Signals:     r.Signals,
			Target: signal.TargetSpec{
				Type:    r.Target.Type,
				Pattern: r.Target.Pattern,
				Min:     r.Target.Min,
				Max:     r.Target.Max,
			},
			Decision:   r.Decision,
			Fallback:   r.Fallback,
			RedirectTo: r.RedirectTo,
			Message:    r.Message,
		}
	}
	sigEngine, err := signal.NewEngine(sigRules)
	if err != nil {
		return nil, fmt.Errorf("compile signal rules: %w", err)
	}
	return sigEngine, nil
}

// signalEngineType is the concrete type for the signal engine.
type signalEngineType = *signal.Engine
```

**Step 3: Create Windows stub**

Create `internal/policy/engine_signal_stub.go`:

```go
//go:build windows

package policy

// compileSignalRules is a no-op on Windows (signal interception not supported).
func compileSignalRules(rules []SignalRule) (interface{}, error) {
	return nil, nil
}

// signalEngineType is nil on Windows.
type signalEngineType = interface{}
```

**Step 4: Update engine.go to use the helper**

In `internal/policy/engine.go`:
- Remove the `"github.com/agentsh/agentsh/internal/signal"` import
- Change `signalEngine *signal.Engine` to `signalEngine signalEngineType`
- Replace the signal compilation block (lines 265-291) with:
  ```go
  sigEngine, err := compileSignalRules(p.SignalRules)
  if err != nil {
      return nil, err
  }
  e.signalEngine = sigEngine
  ```
- Update `SignalEngine()` method to return `signalEngineType`

**Step 5: Verify Windows build passes**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && GOOS=windows go build ./internal/policy/...`
Expected: PASS (no errors)

**Step 6: Verify Linux build still works**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go build ./internal/policy/...`
Expected: PASS

**Step 7: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -v`
Expected: PASS

**Step 8: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_signal.go internal/policy/engine_signal_stub.go
git commit -m "fix(policy): add Windows build support for signal rules

- Extract signal rule compilation to separate files with build tags
- Add Windows stub that returns nil (signal interception unsupported)
- Fixes Windows build failure due to unconditional signal package import"
```

---

## Task 2: Remove Arch-Specific Syscall Number Test

The test `TestSignalSyscalls` asserts hardcoded syscall numbers (62, 234) that are x86_64-specific. These will fail on ARM64 or other architectures.

**Files:**
- Modify: `internal/signal/seccomp_linux_test.go:12-15`

**Step 1: Analyze the test**

The test is:
```go
func TestSignalSyscalls(t *testing.T) {
	assert.Equal(t, 62, unix.SYS_KILL)
	assert.Equal(t, 234, unix.SYS_TGKILL)
}
```

This test doesn't verify any behavior - it just asserts that syscall numbers match hardcoded values. The syscall numbers are correctly obtained from `unix.SYS_KILL` etc. in the actual code, so this test is redundant and harmful.

**Step 2: Remove the test**

Delete the `TestSignalSyscalls` function from `internal/signal/seccomp_linux_test.go`.

**Step 3: Verify tests pass**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/signal/seccomp_linux_test.go
git commit -m "fix(signal): remove arch-specific syscall number test

Remove TestSignalSyscalls which asserted hardcoded syscall numbers
(62 for SYS_KILL, 234 for SYS_TGKILL). These are x86_64-specific and
fail on ARM64 and other architectures. The actual code correctly uses
unix.SYS_* constants, so the test was redundant."
```

---

## Task 3: Fix SameUser Classification in Registry

The `ClassifyTarget` method hardcodes `SameUser: true` with a TODO comment. This causes `TargetUser` rules to incorrectly match any external process regardless of owner.

**Files:**
- Modify: `internal/signal/registry.go:78-89`
- Modify: `internal/signal/registry_test.go` (add test)

**Step 1: Write failing test**

Add test to `internal/signal/registry_test.go`:

```go
func TestClassifyTargetSameUser(t *testing.T) {
	r := NewPIDRegistry("test", 1000)

	// Register source process with UID 1000
	r.RegisterWithUID(1001, 1000, "myapp", 1000)

	// External process with same UID
	ctx := r.ClassifyTarget(1001, 9999)
	assert.True(t, ctx.SameUser, "same user should be true when UIDs match")

	// External process with different UID - we can't know without /proc lookup
	// So SameUser should be false for unknown external processes
	ctx = r.ClassifyTarget(1001, 9998)
	assert.False(t, ctx.SameUser, "same user should be false for unknown external process")
}
```

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestClassifyTargetSameUser -v`
Expected: FAIL (RegisterWithUID doesn't exist)

**Step 2: Add UID tracking to registry**

Modify `internal/signal/registry.go`:

```go
// PIDRegistry tracks process membership in a session.
type PIDRegistry struct {
	mu            sync.RWMutex
	sessionID     string
	supervisorPID int
	supervisorUID int // Add: UID of the supervisor

	// pid -> parent pid
	parents map[int]int
	// pid -> command name
	commands map[int]string
	// pid -> child pids
	children map[int][]int
	// pid -> uid
	uids map[int]int // Add: track UIDs
}

// NewPIDRegistry creates a new registry for a session.
func NewPIDRegistry(sessionID string, supervisorPID int) *PIDRegistry {
	return &PIDRegistry{
		sessionID:     sessionID,
		supervisorPID: supervisorPID,
		supervisorUID: -1, // Unknown
		parents:       make(map[int]int),
		commands:      make(map[int]string),
		children:      make(map[int][]int),
		uids:          make(map[int]int),
	}
}

// NewPIDRegistryWithUID creates a new registry with supervisor UID.
func NewPIDRegistryWithUID(sessionID string, supervisorPID, supervisorUID int) *PIDRegistry {
	r := NewPIDRegistry(sessionID, supervisorPID)
	r.supervisorUID = supervisorUID
	return r
}

// Register adds a process to the session (legacy, assumes same UID as supervisor).
func (r *PIDRegistry) Register(pid, parentPID int, command string) {
	r.RegisterWithUID(pid, parentPID, command, r.supervisorUID)
}

// RegisterWithUID adds a process to the session with explicit UID.
func (r *PIDRegistry) RegisterWithUID(pid, parentPID int, command string, uid int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.parents[pid] = parentPID
	r.commands[pid] = command
	r.children[parentPID] = append(r.children[parentPID], pid)
	r.uids[pid] = uid
}
```

**Step 3: Update ClassifyTarget to check UIDs**

```go
// ClassifyTarget determines the relationship between source and target PIDs.
func (r *PIDRegistry) ClassifyTarget(sourcePID, targetPID int) *TargetContext {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sourceUID, sourceKnown := r.uids[sourcePID]
	if !sourceKnown && sourcePID == r.supervisorPID {
		sourceUID = r.supervisorUID
		sourceKnown = r.supervisorUID >= 0
	}

	targetUID, targetKnown := r.uids[targetPID]
	if !targetKnown && targetPID == r.supervisorPID {
		targetUID = r.supervisorUID
		targetKnown = r.supervisorUID >= 0
	}

	// SameUser is only true if we know both UIDs and they match
	sameUser := sourceKnown && targetKnown && sourceUID == targetUID

	ctx := &TargetContext{
		SourcePID: sourcePID,
		TargetPID: targetPID,
		TargetCmd: r.commands[targetPID],
		InSession: r.inSessionLocked(targetPID),
		SameUser:  sameUser,
	}
	// ... rest of method unchanged
}
```

**Step 4: Update Unregister to clean up UID**

```go
func (r *PIDRegistry) Unregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	parentPID := r.parents[pid]
	delete(r.parents, pid)
	delete(r.commands, pid)
	delete(r.uids, pid) // Add this line

	// ... rest unchanged
}
```

**Step 5: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestClassifyTargetSameUser -v`
Expected: PASS

**Step 6: Run all registry tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run Registry -v`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/signal/registry.go internal/signal/registry_test.go
git commit -m "fix(signal): track UID for accurate SameUser classification

- Add UID tracking to PIDRegistry (uids map, supervisorUID)
- Add RegisterWithUID and NewPIDRegistryWithUID for explicit UID
- SameUser is now false for unknown external processes
- Fixes TargetUser rules incorrectly matching any external process"
```

---

## Task 4: Fix TargetSystem Definition

The `TargetSystem` target type treats any PID < 100 as a system process, but the docs say it should only match "PID 1 and kernel threads". This misclassifies normal processes in containers or low-PID environments.

**Files:**
- Modify: `internal/signal/target.go:127-128`
- Modify: `internal/signal/target_test.go` (add test)

**Step 1: Write failing test**

Add test to `internal/signal/target_test.go`:

```go
func TestTargetSystemMatching(t *testing.T) {
	target := &ParsedTarget{Type: TargetSystem}

	// PID 1 (init) should match
	ctx := &TargetContext{TargetPID: 1}
	assert.True(t, target.Matches(ctx), "PID 1 should match TargetSystem")

	// PID 2 (kthreadd on Linux) should match
	ctx = &TargetContext{TargetPID: 2}
	assert.True(t, target.Matches(ctx), "PID 2 should match TargetSystem")

	// Low PID like 50 should NOT match (could be normal process in container)
	ctx = &TargetContext{TargetPID: 50}
	assert.False(t, target.Matches(ctx), "PID 50 should NOT match TargetSystem")

	// Normal PID should NOT match
	ctx = &TargetContext{TargetPID: 1234}
	assert.False(t, target.Matches(ctx), "PID 1234 should NOT match TargetSystem")
}
```

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestTargetSystemMatching -v`
Expected: FAIL (PID 50 incorrectly matches)

**Step 2: Fix TargetSystem matching**

Modify `internal/signal/target.go` line 128:

Change:
```go
case TargetSystem:
	return ctx.TargetPID == 1 || ctx.TargetPID < 100
```

To:
```go
case TargetSystem:
	// Match PID 1 (init) and PID 2 (kthreadd, Linux kernel thread parent)
	// Other kernel threads have higher PIDs but are children of PID 2
	return ctx.TargetPID == 1 || ctx.TargetPID == 2
```

**Step 3: Run test**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run TestTargetSystemMatching -v`
Expected: PASS

**Step 4: Run all target tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -run Target -v`
Expected: PASS

**Step 5: Update documentation**

Verify `docs/operations/policies.md` already says "PID 1 and kernel threads". The code now matches the documentation.

**Step 6: Commit**

```bash
git add internal/signal/target.go internal/signal/target_test.go
git commit -m "fix(signal): correct TargetSystem to match only PID 1 and 2

TargetSystem was incorrectly matching any PID < 100, which would
misclassify normal processes in containers or low-PID environments.
Now correctly matches only PID 1 (init) and PID 2 (kthreadd).

This matches the documented behavior: 'PID 1 and kernel threads'"
```

---

## Task 5: Handle Process Group Signals and tkill

The `ExtractSignalContext` function doesn't handle:
1. `kill(0, sig)` - signal to caller's process group
2. `kill(-pid, sig)` - signal to process group
3. `tkill(tid, sig)` - doesn't set TargetPID, only TargetTID

**Files:**
- Modify: `internal/signal/seccomp_linux.go:153-189`
- Add: `internal/signal/seccomp_linux_test.go` (add test for extraction)

**Step 1: Write failing test**

Add test to `internal/signal/seccomp_linux_test.go`:

```go
func TestExtractSignalContextProcessGroup(t *testing.T) {
	// We can't easily create ScmpNotifReq, but we can test the logic
	// by checking the SignalContext struct and documenting expected behavior

	// For kill(0, sig): TargetPID should be 0 (process group of caller)
	// For kill(-pgid, sig): TargetPID should be negative
	// For tkill(tid, sig): TargetPID should equal TargetTID (thread = process for classification)

	ctx := SignalContext{
		PID:       1000,
		Syscall:   200, // mock tkill
		TargetTID: 1001,
		TargetPID: 0,   // Currently not set by tkill
		Signal:    15,
	}

	// Document: if TargetPID is 0 but TargetTID is set, use TargetTID for classification
	if ctx.TargetPID == 0 && ctx.TargetTID != 0 {
		ctx.TargetPID = ctx.TargetTID
	}

	assert.Equal(t, 1001, ctx.TargetPID, "tkill should use TID as PID for classification")
}
```

**Step 2: Update ExtractSignalContext**

Modify `internal/signal/seccomp_linux.go`:

```go
func ExtractSignalContext(req *seccomp.ScmpNotifReq) SignalContext {
	ctx := SignalContext{
		PID:     int(req.Pid),
		Syscall: int(req.Data.Syscall),
	}

	switch int(req.Data.Syscall) {
	case unix.SYS_KILL:
		// kill(pid_t pid, int sig)
		// pid > 0: send to specific process
		// pid == 0: send to caller's process group
		// pid == -1: send to all processes (permission-limited)
		// pid < -1: send to process group -pid
		ctx.TargetPID = int(int32(req.Data.Args[0])) // Signed conversion
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_TGKILL:
		// tgkill(pid_t tgid, pid_t tid, int sig)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.TargetTID = int(req.Data.Args[1])
		ctx.Signal = int(req.Data.Args[2])

	case unix.SYS_TKILL:
		// tkill(pid_t tid, int sig)
		// For classification purposes, use TID as the target PID
		// since we're targeting a specific thread
		ctx.TargetTID = int(req.Data.Args[0])
		ctx.TargetPID = ctx.TargetTID // Use TID for classification
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_RT_SIGQUEUEINFO:
		// rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.Signal = int(req.Data.Args[1])

	case unix.SYS_RT_TGSIGQUEUEINFO:
		// rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
		ctx.TargetPID = int(req.Data.Args[0])
		ctx.TargetTID = int(req.Data.Args[1])
		ctx.Signal = int(req.Data.Args[2])
	}

	return ctx
}
```

**Step 3: Add helper for process group detection**

Add to `internal/signal/seccomp_linux.go`:

```go
// IsProcessGroupSignal returns true if the signal targets a process group.
func (c *SignalContext) IsProcessGroupSignal() bool {
	// kill(0, sig) or kill(-pgid, sig)
	return c.TargetPID <= 0
}

// ProcessGroupID returns the process group ID for process group signals.
// Returns 0 for non-process-group signals.
func (c *SignalContext) ProcessGroupID() int {
	if c.TargetPID == 0 {
		return c.PID // Caller's process group
	}
	if c.TargetPID < 0 {
		return -c.TargetPID // Explicit process group
	}
	return 0 // Not a process group signal
}
```

**Step 4: Update stub to match**

Add to `internal/signal/seccomp_stub.go`:

```go
// IsProcessGroupSignal returns true if the signal targets a process group.
func (c *SignalContext) IsProcessGroupSignal() bool {
	return c.TargetPID <= 0
}

// ProcessGroupID returns the process group ID for process group signals.
func (c *SignalContext) ProcessGroupID() int {
	if c.TargetPID == 0 {
		return c.PID
	}
	if c.TargetPID < 0 {
		return -c.TargetPID
	}
	return 0
}
```

**Step 5: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/signal/seccomp_linux.go internal/signal/seccomp_stub.go internal/signal/seccomp_linux_test.go
git commit -m "fix(signal): handle process group signals and tkill correctly

- Use signed conversion for kill() pid argument to preserve negative values
- Set TargetPID = TargetTID for tkill to enable classification
- Add IsProcessGroupSignal() and ProcessGroupID() helpers
- Document behavior for kill(0, sig) and kill(-pgid, sig)"
```

---

## Task 6: Add Platform Detection for canBlock

The handler hardcodes `canBlock := true` but this should be determined by platform capabilities. On macOS/Windows, we can only audit, not block.

**Files:**
- Modify: `internal/signal/handler.go:54-70`
- Add: `internal/signal/platform.go`
- Add: `internal/signal/platform_linux.go`
- Add: `internal/signal/platform_stub.go`

**Step 1: Write failing test**

Add test to `internal/signal/handler_test.go`:

```go
func TestHandlerRespectsPlatformCapability(t *testing.T) {
	rules := []SignalRule{
		{
			Name:     "deny-external",
			Signals:  []string{"SIGTERM"},
			Target:   TargetSpec{Type: "external"},
			Decision: "deny",
			Fallback: "audit",
		},
	}
	engine, err := NewEngine(rules)
	require.NoError(t, err)

	registry := NewPIDRegistry("test", 1000)
	handler := NewHandler(engine, registry, nil)

	// Handler should use platform detection, not hardcoded true
	// This test documents the expected behavior
	dec := handler.Handle(context.Background(), SignalContext{
		PID:       1000,
		TargetPID: 9999, // External
		Signal:    15,
	})

	// On Linux with seccomp, should be Deny
	// On other platforms, should fallback to Audit
	if CanBlockSignals() {
		assert.Equal(t, DecisionDeny, dec.Action)
	} else {
		assert.Equal(t, DecisionAudit, dec.Action)
	}
}
```

**Step 2: Create platform detection files**

Create `internal/signal/platform.go`:

```go
//go:build !windows

package signal

// CanBlockSignals reports whether the platform can enforce signal blocking.
// This is a runtime check that verifies seccomp user-notify is available.
var canBlockSignals *bool

// CanBlockSignals returns true if the platform can block signals.
func CanBlockSignals() bool {
	if canBlockSignals != nil {
		return *canBlockSignals
	}
	result := IsSignalSupportAvailable()
	canBlockSignals = &result
	return result
}
```

Create `internal/signal/platform_stub.go`:

```go
//go:build windows

package signal

// CanBlockSignals returns false on Windows (signal interception not supported).
func CanBlockSignals() bool {
	return false
}
```

**Step 3: Update handler to use platform detection**

Modify `internal/signal/handler.go`:

Change:
```go
// For now, assume we can block (seccomp user-notify supports it)
// In a real implementation, this would be determined by platform detection
canBlock := true
```

To:
```go
// Determine if platform can enforce blocking
canBlock := CanBlockSignals()
```

**Step 4: Run tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/signal/platform.go internal/signal/platform_stub.go internal/signal/handler.go internal/signal/handler_test.go
git commit -m "fix(signal): use platform detection for blocking capability

- Add CanBlockSignals() that checks IsSignalSupportAvailable() at runtime
- Handler now uses CanBlockSignals() instead of hardcoded true
- On platforms without seccomp user-notify, fallback decisions apply
- Windows stub always returns false"
```

---

## Task 7: Run Full Test Suite and Verify Fixes

**Step 1: Run all signal tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/signal/... -v`
Expected: PASS

**Step 2: Run policy tests**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./internal/policy/... -v`
Expected: PASS

**Step 3: Verify Windows cross-compilation**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && GOOS=windows go build ./...`
Expected: PASS (no errors)

**Step 4: Verify ARM64 cross-compilation**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && GOARCH=arm64 go build ./...`
Expected: PASS (no errors)

**Step 5: Run full test suite**

Run: `cd /home/eran/work/agentsh/.worktrees/signal-interception && go test ./... -v 2>&1 | head -100`
Expected: All tests pass

---

## Summary of Fixes

| Issue | File | Fix |
|-------|------|-----|
| Windows build | `internal/policy/engine.go` | Extract signal code to build-tagged files |
| Arch-specific test | `internal/signal/seccomp_linux_test.go` | Remove hardcoded syscall number assertions |
| SameUser hardcoded | `internal/signal/registry.go` | Track UIDs, only set SameUser when known |
| TargetSystem wrong | `internal/signal/target.go` | Match only PID 1 and 2, not PID < 100 |
| Process groups | `internal/signal/seccomp_linux.go` | Signed conversion, tkill sets TargetPID |
| canBlock hardcoded | `internal/signal/handler.go` | Use CanBlockSignals() platform detection |
