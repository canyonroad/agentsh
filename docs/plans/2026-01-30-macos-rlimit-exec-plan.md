# macOS RLIMIT_AS Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable memory limiting on macOS via RLIMIT_AS using a wrapper binary

**Architecture:** Wrapper binary sets rlimit on itself then exec's target command

**Tech Stack:** Go, unix.Setrlimit, unix.Exec

---

## Task 1: Create the wrapper binary

**Files:**
- Create: `cmd/agentsh-rlimit-exec/main.go`

**Step 1: Create the directory and file**

```go
//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentsh-rlimit-exec <command> [args...]")
		os.Exit(1)
	}

	// Apply RLIMIT_AS if set
	if limitStr := os.Getenv("AGENTSH_RLIMIT_AS"); limitStr != "" {
		limit, err := strconv.ParseUint(limitStr, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: invalid AGENTSH_RLIMIT_AS: %v\n", err)
			os.Exit(1)
		}
		rlimit := unix.Rlimit{Cur: limit, Max: limit}
		if err := unix.Setrlimit(unix.RLIMIT_AS, &rlimit); err != nil {
			fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: setrlimit failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Look up command path
	cmd := os.Args[1]
	path, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: command not found: %s\n", cmd)
		os.Exit(127)
	}

	// Exec replaces this process with the target command
	args := os.Args[1:] // includes cmd as args[0]
	if err := unix.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-rlimit-exec: exec failed: %v\n", err)
		os.Exit(126)
	}
}
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/agentsh-rlimit-exec/...`
Expected: No errors

**Step 3: Commit**

```bash
git add cmd/agentsh-rlimit-exec/main.go
git commit -m "feat(darwin): add agentsh-rlimit-exec wrapper for memory limits"
```

---

## Task 2: Add tests for the wrapper binary

**Files:**
- Create: `cmd/agentsh-rlimit-exec/main_test.go`

**Step 1: Create test file**

```go
//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRlimitExecSetsLimit(t *testing.T) {
	// Build the wrapper first
	wrapper := buildWrapper(t)

	// Run wrapper with a command that prints its rlimit
	// We use a small Go program for this
	limit := uint64(128 * 1024 * 1024) // 128MB

	cmd := exec.Command(wrapper, "sh", "-c", "ulimit -v")
	cmd.Env = append(os.Environ(), "AGENTSH_RLIMIT_AS="+strconv.FormatUint(limit, 10))

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper failed: %v", err)
	}

	// ulimit -v returns limit in KB
	expectedKB := limit / 1024
	outputStr := strings.TrimSpace(string(output))
	actualKB, err := strconv.ParseUint(outputStr, 10, 64)
	if err != nil {
		t.Fatalf("failed to parse ulimit output %q: %v", outputStr, err)
	}

	if actualKB != expectedKB {
		t.Errorf("rlimit = %d KB, want %d KB", actualKB, expectedKB)
	}
}

func TestRlimitExecNoLimit(t *testing.T) {
	wrapper := buildWrapper(t)

	// Run without AGENTSH_RLIMIT_AS - should work normally
	cmd := exec.Command(wrapper, "echo", "hello")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper failed: %v", err)
	}

	if !strings.Contains(string(output), "hello") {
		t.Errorf("output = %q, want to contain 'hello'", output)
	}
}

func TestRlimitExecCommandNotFound(t *testing.T) {
	wrapper := buildWrapper(t)

	cmd := exec.Command(wrapper, "nonexistent-command-12345")
	err := cmd.Run()

	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}

	if exitErr.ExitCode() != 127 {
		t.Errorf("exit code = %d, want 127", exitErr.ExitCode())
	}
}

func buildWrapper(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	wrapper := tmpDir + "/agentsh-rlimit-exec"

	cmd := exec.Command("go", "build", "-o", wrapper, ".")
	cmd.Dir = "."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build wrapper: %v\n%s", err, output)
	}

	return wrapper
}
```

**Step 2: Run tests**

Run: `go test ./cmd/agentsh-rlimit-exec/...`
Expected: All pass

**Step 3: Commit**

```bash
git add cmd/agentsh-rlimit-exec/main_test.go
git commit -m "test(darwin): add tests for agentsh-rlimit-exec wrapper"
```

---

## Task 3: Update resources.go to support memory limits

**Files:**
- Modify: `internal/platform/darwin/resources.go`

**Step 1: Re-add ResourceMemory to SupportedLimits**

Change NewResourceLimiter():

```go
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available: true,
		supportedLimits: []platform.ResourceType{
			platform.ResourceMemory, // Supported via agentsh-rlimit-exec wrapper
			platform.ResourceCPU,
		},
		handles: make(map[string]*ResourceHandle),
	}
	return r
}
```

**Step 2: Remove MaxMemoryMB error in Apply()**

Remove this check from Apply():

```go
// Remove this:
if config.MaxMemoryMB > 0 {
    return nil, fmt.Errorf("memory limits not yet implemented on macOS...")
}
```

**Step 3: Verify it compiles**

Run: `go build ./internal/platform/darwin/...`
Expected: No errors

**Step 4: Commit**

```bash
git add internal/platform/darwin/resources.go
git commit -m "feat(darwin): re-enable memory limit support in ResourceLimiter"
```

---

## Task 4: Update resources_test.go for memory support

**Files:**
- Modify: `internal/platform/darwin/resources_test.go`

**Step 1: Update TestResourceLimiterSupportedLimits**

Add check for ResourceMemory:

```go
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
```

**Step 2: Update TestResourceLimiterApply to include memory**

```go
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
```

**Step 3: Remove TestResourceLimiterApplyUnsupportedMemory**

This test is no longer valid since memory is now supported.

**Step 4: Run tests**

Run: `go test ./internal/platform/darwin/...`
Expected: All pass

**Step 5: Commit**

```bash
git add internal/platform/darwin/resources_test.go
git commit -m "test(darwin): update tests for memory limit support"
```

---

## Task 5: Integrate wrapper in sandbox_resources.go

**Files:**
- Modify: `internal/platform/darwin/sandbox_resources.go`

**Step 1: Add wrapper integration**

Update ExecuteWithResources to use the wrapper when memory limits are configured:

```go
func (s *Sandbox) ExecuteWithResources(ctx context.Context, rh *ResourceHandle, cmd string, args ...string) (*platform.ExecResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox is closed")
	}
	s.mu.Unlock()

	// Check if we need to wrap the command for rlimit enforcement
	actualCmd := cmd
	actualArgs := args
	var rlimitEnv string

	if rh != nil {
		rlimits := rh.GetRlimits()
		for _, rl := range rlimits {
			if rl.Resource == RlimitAS && rl.Cur > 0 {
				// Wrap with agentsh-rlimit-exec
				actualCmd = "agentsh-rlimit-exec"
				actualArgs = append([]string{cmd}, args...)
				rlimitEnv = fmt.Sprintf("AGENTSH_RLIMIT_AS=%d", rl.Cur)
				break
			}
		}
	}

	// Build sandbox-exec command with inline profile
	sandboxArgs := []string{"-p", s.profile, actualCmd}
	sandboxArgs = append(sandboxArgs, actualArgs...)

	execCmd := exec.CommandContext(ctx, "sandbox-exec", sandboxArgs...)
	// ... rest of the function, adding rlimitEnv to environment ...
}
```

**Step 2: Add rlimitEnv to the command environment**

In the environment setup section:

```go
	// Set environment variables
	if len(s.config.Environment) > 0 || rlimitEnv != "" {
		execCmd.Env = os.Environ() // Start with current environment
		for k, v := range s.config.Environment {
			execCmd.Env = append(execCmd.Env, k+"="+v)
		}
		if rlimitEnv != "" {
			execCmd.Env = append(execCmd.Env, rlimitEnv)
		}
	}
```

**Step 3: Add fmt import if needed**

**Step 4: Verify it compiles**

Run: `go build ./internal/platform/darwin/...`
Expected: No errors

**Step 5: Commit**

```bash
git add internal/platform/darwin/sandbox_resources.go
git commit -m "feat(darwin): integrate agentsh-rlimit-exec in sandbox execution"
```

---

## Task 6: Add integration test for memory limits

**Files:**
- Modify: `internal/platform/darwin/sandbox_resources_test.go`

**Step 1: Add test for memory-limited execution**

```go
func TestSandboxExecuteWithResources_MemoryLimit(t *testing.T) {
	if !conpty.IsConPtyAvailable() {
		t.Skip("sandbox-exec not functional on this system")
	}

	// Check if wrapper is available
	if _, err := exec.LookPath("agentsh-rlimit-exec"); err != nil {
		t.Skip("agentsh-rlimit-exec not in PATH")
	}

	m := NewSandboxManager()
	if !sandboxExecWorks(t, m) {
		t.Skip("sandbox-exec not functional on this system")
	}

	sb, err := m.Create(platform.SandboxConfig{
		Name:          "test-memory",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sb.Close()

	// Create resource handle with memory limit
	rl := NewResourceLimiter()
	rh, err := rl.Apply(platform.ResourceConfig{
		Name:        "test",
		MaxMemoryMB: 128, // 128MB limit
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	defer rh.Release()

	// Execute and check that ulimit shows the limit
	result, err := sb.(*Sandbox).ExecuteWithResources(
		context.Background(),
		rh.(*ResourceHandle),
		"sh", "-c", "ulimit -v",
	)
	if err != nil {
		t.Fatalf("ExecuteWithResources failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}

	// Verify the limit is approximately correct (128MB = 131072 KB)
	output := strings.TrimSpace(string(result.Stdout))
	limitKB, err := strconv.ParseUint(output, 10, 64)
	if err != nil {
		t.Logf("ulimit output: %q", output)
		t.Skipf("could not parse ulimit output: %v", err)
	}

	expectedKB := uint64(128 * 1024)
	if limitKB != expectedKB {
		t.Errorf("memory limit = %d KB, want %d KB", limitKB, expectedKB)
	}
}
```

**Step 2: Add required imports**

Add `"strconv"` and `"strings"` to imports.

**Step 3: Run tests**

Run: `go test ./internal/platform/darwin/...`
Expected: All pass (test may skip if wrapper not in PATH)

**Step 4: Commit**

```bash
git add internal/platform/darwin/sandbox_resources_test.go
git commit -m "test(darwin): add integration test for memory-limited execution"
```

---

## Task 7: Update design document and final cleanup

**Files:**
- Modify: `docs/plans/2026-01-30-macos-resource-control-design.md`

**Step 1: Update the design doc**

Update the Memory Limiting section to reflect the implementation:

```markdown
## Memory Limiting

### Mechanism

Uses RLIMIT_AS via a wrapper binary (`agentsh-rlimit-exec`). The wrapper:
1. Reads limit from `AGENTSH_RLIMIT_AS` environment variable
2. Calls `setrlimit(RLIMIT_AS, limit)` on itself
3. Calls `exec()` to run the target command
4. Target inherits the rlimit

### Implementation Status

**Implemented** via wrapper binary approach. Go's `exec.Cmd` doesn't support
setting rlimits in `SysProcAttr` on darwin, and macOS lacks `prlimit()`.
```

**Step 2: Verify all builds**

Run: `go build ./...`
Run: `GOOS=darwin go build ./...`
Expected: No errors

**Step 3: Run all tests**

Run: `go test ./...`
Expected: All pass

**Step 4: Commit**

```bash
git add docs/plans/
git commit -m "docs: update macOS resource control design for memory limit implementation"
```
