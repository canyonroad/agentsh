# Yama-Aware PR_SET_PTRACER with ProcessVMReadv Self-Test — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix #218 — make the PR_SET_PTRACER call Yama-aware and add a ProcessVMReadv self-test so file_monitor works on kernels without Yama LSM.

**Architecture:** Two new files (`yama_linux.go` for Yama detection, `pvr_probe_linux.go` for the memory-access self-test) plus edits to three existing files (`main.go`, `notify_linux.go`, `wrap_linux.go`). The wrapper skips PR_SET_PTRACER when Yama isn't loaded. The server probes ProcessVMReadv against the wrapper PID during the notify handshake, failing fast if both memory-access methods are broken and file_monitor or execve interception is enabled.

**Tech Stack:** Go, `golang.org/x/sys/unix`, Linux seccomp-notify

**Spec:** `docs/superpowers/specs/2026-04-12-yama-aware-ptracer-design.md`

---

### Task 1: Yama Detection — Test + Implementation

**Files:**
- Create: `cmd/agentsh-unixwrap/yama_linux.go`
- Create: `cmd/agentsh-unixwrap/yama_linux_test.go`

- [ ] **Step 1: Write the failing tests**

Create `cmd/agentsh-unixwrap/yama_linux_test.go`:

```go
//go:build linux && cgo

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsYamaActive_WhenPresent(t *testing.T) {
	// Create a temp file that simulates /proc/sys/kernel/yama/ptrace_scope
	dir := t.TempDir()
	fakePath := filepath.Join(dir, "ptrace_scope")
	require.NoError(t, os.WriteFile(fakePath, []byte("1\n"), 0644))

	orig := yamaPtraceScopePath
	yamaPtraceScopePath = fakePath
	defer func() { yamaPtraceScopePath = orig }()

	assert.True(t, isYamaActive(), "should report Yama active when ptrace_scope file exists")
}

func TestIsYamaActive_WhenAbsent(t *testing.T) {
	orig := yamaPtraceScopePath
	yamaPtraceScopePath = "/nonexistent/path/ptrace_scope"
	defer func() { yamaPtraceScopePath = orig }()

	assert.False(t, isYamaActive(), "should report Yama inactive when ptrace_scope file is missing")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./cmd/agentsh-unixwrap/ -run TestIsYamaActive -v`

Expected: compilation error — `yamaPtraceScopePath` and `isYamaActive` are not defined.

- [ ] **Step 3: Write minimal implementation**

Create `cmd/agentsh-unixwrap/yama_linux.go`:

```go
//go:build linux && cgo

package main

import "os"

// yamaPtraceScopePath is the sysctl that exists when Yama LSM is loaded.
// Package-level var for testability.
var yamaPtraceScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// isYamaActive returns true if the Yama LSM is loaded and active.
// When Yama is not loaded, PR_SET_PTRACER is meaningless (returns EINVAL)
// and ProcessVMReadv permissions fall back to standard Unix DAC.
func isYamaActive() bool {
	_, err := os.Stat(yamaPtraceScopePath)
	return err == nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/eran/work/agentsh && go test ./cmd/agentsh-unixwrap/ -run TestIsYamaActive -v`

Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/agentsh-unixwrap/yama_linux.go cmd/agentsh-unixwrap/yama_linux_test.go
git commit -m "feat(seccomp): add Yama LSM detection for PR_SET_PTRACER (#218)"
```

---

### Task 2: Yama-Aware PR_SET_PTRACER in Wrapper

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go:45-54`

- [ ] **Step 1: Replace the unconditional PR_SET_PTRACER call**

In `cmd/agentsh-unixwrap/main.go`, replace lines 45-54 (the comment block and the `if cfg.ServerPID > 0` block):

Old code:
```go
	// Authorize the server process to read our memory via ProcessVMReadv.
	// Under Yama ptrace_scope=1 (Ubuntu/Debian default), only ancestor
	// processes can use ProcessVMReadv. In the wrap path the server is NOT
	// our ancestor, so this prctl authorizes it specifically.
	// Must run before any seccomp notifications can be processed.
	if cfg.ServerPID > 0 {
		if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(cfg.ServerPID), 0, 0, 0); err != nil {
			log.Printf("PR_SET_PTRACER(%d): %v (ProcessVMReadv may fail under Yama)", cfg.ServerPID, err)
		}
	}
```

New code:
```go
	// Authorize the server process to read our memory via ProcessVMReadv.
	// Under Yama ptrace_scope=1 (Ubuntu/Debian default), only ancestor
	// processes can use ProcessVMReadv. In the wrap path the server is NOT
	// our ancestor, so this prctl authorizes it specifically.
	// On kernels without Yama, PR_SET_PTRACER returns EINVAL — but it's
	// also unnecessary because standard Unix DAC governs ptrace.
	if cfg.ServerPID > 0 {
		if isYamaActive() {
			if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(cfg.ServerPID), 0, 0, 0); err != nil {
				log.Printf("PR_SET_PTRACER(%d): %v (Yama active, ProcessVMReadv may fail)", cfg.ServerPID, err)
			}
		} else {
			log.Printf("yama: not active, skipping PR_SET_PTRACER (standard DAC governs ptrace)")
		}
	}
```

- [ ] **Step 2: Verify build and existing tests pass**

Run: `cd /home/eran/work/agentsh && go build ./cmd/agentsh-unixwrap/ && go test ./cmd/agentsh-unixwrap/ -v`

Expected: build succeeds, all existing tests pass.

- [ ] **Step 3: Verify cross-compilation**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`

Expected: build succeeds (the new file has `_linux.go` suffix, excluded from Windows builds).

- [ ] **Step 4: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go
git commit -m "fix(seccomp): skip PR_SET_PTRACER when Yama LSM not loaded (#218)"
```

---

### Task 3: ProcessVMReadv Probe Functions — Test + Implementation

**Files:**
- Create: `internal/api/pvr_probe_linux.go`
- Create: `internal/api/pvr_probe_linux_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/api/pvr_probe_linux_test.go`:

```go
//go:build linux && cgo

package api

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindReadableAddr_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err, "should find a readable mapping in own process")
	assert.NotZero(t, addr, "address should be non-zero")
}

func TestProbeProcessVMReadvAt_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err)

	err = probeProcessVMReadvAt(os.Getpid(), addr)
	assert.NoError(t, err, "ProcessVMReadv against own PID should succeed")
}

func TestProbeProcMemAt_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err)

	err = probeProcMemAt(os.Getpid(), addr)
	assert.NoError(t, err, "/proc/self/mem read should succeed")
}

func TestProbeMemoryAccess_Self(t *testing.T) {
	pvrErr, memErr := probeMemoryAccess(os.Getpid())
	assert.NoError(t, pvrErr, "ProcessVMReadv should succeed against self")
	assert.NoError(t, memErr, "memErr should be nil when ProcessVMReadv succeeds")
}

func TestProbeMemoryAccess_InvalidPID(t *testing.T) {
	// PID that almost certainly doesn't exist
	pvrErr, memErr := probeMemoryAccess(999999999)
	assert.Error(t, pvrErr, "should fail for nonexistent PID")
	assert.Error(t, memErr, "fallback should also fail for nonexistent PID")
}

func TestFindReadableAddr_InvalidPID(t *testing.T) {
	_, err := findReadableAddr(999999999)
	assert.Error(t, err, "should fail for nonexistent PID")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestFindReadableAddr|TestProbeProcessVMReadvAt|TestProbeProcMemAt|TestProbeMemoryAccess" -v`

Expected: compilation error — functions not defined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/api/pvr_probe_linux.go`:

```go
//go:build linux && cgo

package api

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// probeMemoryAccess tests that the server can read from the given PID's address
// space using ProcessVMReadv and the /proc/<pid>/mem fallback. Returns
// (nil, nil) if ProcessVMReadv works, (pvrErr, nil) if only /proc/mem works,
// or (pvrErr, memErr) if both fail.
func probeMemoryAccess(pid int) (pvrErr, memErr error) {
	addr, err := findReadableAddr(pid)
	if err != nil {
		return fmt.Errorf("find readable addr: %w", err), fmt.Errorf("find readable addr: %w", err)
	}
	pvrErr = probeProcessVMReadvAt(pid, addr)
	if pvrErr != nil {
		memErr = probeProcMemAt(pid, addr)
	}
	return pvrErr, memErr
}

// probeProcessVMReadvAt reads 8 bytes from the given address in the target
// process via ProcessVMReadv. Returns nil on success.
func probeProcessVMReadvAt(pid int, addr uint64) error {
	buf := make([]byte, 8)
	liov := unix.Iovec{Base: &buf[0], Len: 8}
	riov := unix.RemoteIovec{Base: uintptr(addr), Len: 8}
	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	return err
}

// probeProcMemAt reads 8 bytes from the given address via /proc/<pid>/mem.
// Returns nil on success.
func probeProcMemAt(pid int, addr uint64) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 8)
	_, err = f.ReadAt(buf, int64(addr))
	return err
}

// findReadableAddr parses /proc/<pid>/maps to find the start address of the
// first readable mapping. Scans at most 20 lines.
func findReadableAddr(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/maps: %w", pid, err)
	}
	lines := strings.Split(string(data), "\n")
	limit := 20
	if len(lines) < limit {
		limit = len(lines)
	}
	for _, line := range lines[:limit] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// permissions field: rwxp — check first char is 'r'
		if len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue
		}
		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) < 2 {
			continue
		}
		addr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		return addr, nil
	}
	return 0, fmt.Errorf("no readable mapping found in /proc/%d/maps (scanned %d lines)", pid, limit)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run "TestFindReadableAddr|TestProbeProcessVMReadvAt|TestProbeProcMemAt|TestProbeMemoryAccess" -v`

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/pvr_probe_linux.go internal/api/pvr_probe_linux_test.go
git commit -m "feat(seccomp): add ProcessVMReadv/proc-mem memory access probe (#218)"
```

---

### Task 4: Self-Test Integration in Exec Path

**Files:**
- Modify: `internal/api/notify_linux.go:297-299`

- [ ] **Step 1: Add the self-test between handler setup and ACK**

In `internal/api/notify_linux.go`, find the code between the execve handler setup closing brace (line 297) and the ACK comment (line 299). Insert the probe block between them.

Old code (lines 297-302):
```go
		}
		// Send ACK to wrapper so it knows the notify handler is ready before exec.
		if _, err := parentSock.Write([]byte{1}); err != nil {
			slog.Debug("notify: ACK write to wrapper failed", "error", err, "session_id", sessID)
		}
```

New code:
```go
		}

		// Probe: verify ProcessVMReadv (or /proc/mem fallback) works against
		// the wrapper before starting. Catches Yama, missing CAP_SYS_PTRACE,
		// or other LSM restrictions at startup instead of on first notification.
		if wrapperPID > 0 {
			pvrErr, memErr := probeMemoryAccess(wrapperPID)
			if pvrErr != nil && memErr != nil {
				if fileHandler != nil || h != nil {
					slog.Error("seccomp notify: ProcessVMReadv and /proc/mem both failed — "+
						"handler cannot read tracee memory for path resolution",
						"wrapper_pid", wrapperPID,
						"pvr_error", pvrErr, "mem_error", memErr,
						"session_id", sessID,
						"hint", "check kernel.yama.ptrace_scope, ensure CAP_SYS_PTRACE, "+
							"or set sandbox.seccomp.file_monitor.enabled: false")
					return // Don't send ACK — wrapper fails with clear handshake error
				}
				slog.Warn("ProcessVMReadv probe failed, socket monitoring may be degraded",
					"wrapper_pid", wrapperPID, "pvr_error", pvrErr, "mem_error", memErr)
			} else if pvrErr != nil {
				slog.Debug("ProcessVMReadv failed but /proc/mem fallback works",
					"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
			}
		}

		// Send ACK to wrapper so it knows the notify handler is ready before exec.
		if _, err := parentSock.Write([]byte{1}); err != nil {
			slog.Debug("notify: ACK write to wrapper failed", "error", err, "session_id", sessID)
		}
```

- [ ] **Step 2: Verify build succeeds**

Run: `cd /home/eran/work/agentsh && go build ./internal/api/`

Expected: build succeeds with no errors.

- [ ] **Step 3: Run existing tests to check for regressions**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -v -count=1 2>&1 | tail -20`

Expected: all existing tests pass. The probe runs against self PID in test contexts and should succeed.

- [ ] **Step 4: Commit**

```bash
git add internal/api/notify_linux.go
git commit -m "fix(seccomp): add ProcessVMReadv self-test in exec notify handshake (#218)"
```

---

### Task 5: Self-Test Integration in Wrap Path

**Files:**
- Modify: `internal/api/wrap_linux.go:113-115`

- [ ] **Step 1: Add the self-test between fileHandler creation and the handler goroutine**

In `internal/api/wrap_linux.go`, find lines 113-115 (fileHandler creation through goroutine start). Insert the probe between them.

Old code (lines 112-115):
```go
	// Create file handler if configured
	fileHandler := createFileHandler(a.cfg.Sandbox.Seccomp.FileMonitor, sessionPolicy, emitter, a.cfg.Landlock.Enabled)

	go func() {
```

New code:
```go
	// Create file handler if configured
	fileHandler := createFileHandler(a.cfg.Sandbox.Seccomp.FileMonitor, sessionPolicy, emitter, a.cfg.Landlock.Enabled)

	// Probe: verify ProcessVMReadv (or /proc/mem fallback) works against
	// the wrapper before starting. Same logic as the exec path probe in
	// notify_linux.go — catches broken memory access at startup.
	if wrapperPID > 0 {
		pvrErr, memErr := probeMemoryAccess(wrapperPID)
		if pvrErr != nil && memErr != nil {
			if fileHandler != nil || execveHandler != nil {
				slog.Error("wrap: ProcessVMReadv and /proc/mem both failed — "+
					"handler cannot read tracee memory for path resolution",
					"wrapper_pid", wrapperPID,
					"pvr_error", pvrErr, "mem_error", memErr,
					"session_id", sessionID,
					"hint", "check kernel.yama.ptrace_scope, ensure CAP_SYS_PTRACE, "+
						"or set sandbox.seccomp.file_monitor.enabled: false")
				// Clean up resources that would normally be handled by the goroutine.
				notifyFD.Close()
				if cleanupSymlink != nil {
					cleanupSymlink()
				}
				return
			}
			slog.Warn("wrap: ProcessVMReadv probe failed, socket monitoring may be degraded",
				"wrapper_pid", wrapperPID, "pvr_error", pvrErr, "mem_error", memErr)
		} else if pvrErr != nil {
			slog.Debug("wrap: ProcessVMReadv failed but /proc/mem fallback works",
				"wrapper_pid", wrapperPID, "pvr_error", pvrErr)
		}
	}

	go func() {
```

- [ ] **Step 2: Verify build succeeds**

Run: `cd /home/eran/work/agentsh && go build ./internal/api/`

Expected: build succeeds with no errors.

- [ ] **Step 3: Run existing tests**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -v -count=1 2>&1 | tail -20`

Expected: all existing tests pass.

- [ ] **Step 4: Verify cross-compilation**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`

Expected: build succeeds. `pvr_probe_linux.go` and the modified `wrap_linux.go` are excluded from Windows builds by filename suffix.

- [ ] **Step 5: Commit**

```bash
git add internal/api/wrap_linux.go
git commit -m "fix(seccomp): add ProcessVMReadv self-test in wrap notify handler (#218)"
```

---

### Task 6: Cross-Process Integration Test

**Files:**
- Modify: `internal/api/pvr_probe_linux_test.go`

- [ ] **Step 1: Add a cross-process probe test**

Append to `internal/api/pvr_probe_linux_test.go`:

```go
func TestProbeMemoryAccess_CrossProcess(t *testing.T) {
	// Fork a child process (sleep), probe it from parent, then kill it.
	// This validates the actual access pattern: server reading from wrapper.
	cmd := exec.Command("sleep", "10")
	require.NoError(t, cmd.Start(), "failed to start child process")
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Give the child a moment to be fully mapped.
	time.Sleep(50 * time.Millisecond)

	pvrErr, memErr := probeMemoryAccess(cmd.Process.Pid)
	assert.NoError(t, pvrErr, "ProcessVMReadv should succeed against child process")
	assert.NoError(t, memErr, "memErr should be nil when ProcessVMReadv succeeds")
}
```

Also add the needed imports at the top of the file. The full import block becomes:

```go
import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

- [ ] **Step 2: Run the test**

Run: `cd /home/eran/work/agentsh && go test ./internal/api/ -run TestProbeMemoryAccess_CrossProcess -v`

Expected: PASS. Parent can read from child process (same UID, standard ptrace access).

- [ ] **Step 3: Commit**

```bash
git add internal/api/pvr_probe_linux_test.go
git commit -m "test(seccomp): add cross-process ProcessVMReadv integration test (#218)"
```

---

### Task 7: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cd /home/eran/work/agentsh && go test ./... 2>&1 | tail -30`

Expected: all tests pass.

- [ ] **Step 2: Verify Windows cross-compilation**

Run: `cd /home/eran/work/agentsh && GOOS=windows go build ./...`

Expected: build succeeds. All new files have `_linux` suffix.

- [ ] **Step 3: Verify Linux build**

Run: `cd /home/eran/work/agentsh && go build ./...`

Expected: build succeeds.
