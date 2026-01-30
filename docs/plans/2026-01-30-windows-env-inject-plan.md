# Windows env_inject Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable `env_inject` on Windows by passing custom environment blocks to `CreateProcessW` instead of inheriting parent environment.

**Architecture:** Add `env` parameter to `RunInAppContainer`, build UTF-16 environment blocks from parent env + injections, pass to `CreateProcessW` with `CREATE_UNICODE_ENVIRONMENT` flag. Works for both AppContainer and non-AppContainer code paths.

**Tech Stack:** Go, Windows API (CreateProcessW), syscall package for UTF-16 conversion

**Design Document:** `docs/plans/2026-01-30-windows-env-inject-design.md`

---

## Task 1: Add Helper Functions for Environment Block Building

**Files:**
- Modify: `internal/platform/windows/appcontainer.go`
- Test: `internal/platform/windows/appcontainer_test.go`

**Step 1: Write the failing test for mergeWithParentEnv**

Add to `internal/platform/windows/appcontainer_test.go`:

```go
func TestMergeWithParentEnv(t *testing.T) {
	// Save and restore environment
	origEnv := os.Environ()
	os.Clearenv()
	os.Setenv("EXISTING_VAR", "original")
	os.Setenv("PATH", "/usr/bin")
	defer func() {
		os.Clearenv()
		for _, e := range origEnv {
			if k, v, ok := strings.Cut(e, "="); ok {
				os.Setenv(k, v)
			}
		}
	}()

	tests := []struct {
		name     string
		inject   map[string]string
		wantKey  string
		wantVal  string
	}{
		{
			name:    "empty inject returns parent env",
			inject:  map[string]string{},
			wantKey: "EXISTING_VAR",
			wantVal: "original",
		},
		{
			name:    "inject adds new variable",
			inject:  map[string]string{"NEW_VAR": "new_value"},
			wantKey: "NEW_VAR",
			wantVal: "new_value",
		},
		{
			name:    "inject overrides existing variable",
			inject:  map[string]string{"EXISTING_VAR": "overridden"},
			wantKey: "EXISTING_VAR",
			wantVal: "overridden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeWithParentEnv(tt.inject)
			if result[tt.wantKey] != tt.wantVal {
				t.Errorf("mergeWithParentEnv() got %q = %q, want %q", tt.wantKey, result[tt.wantKey], tt.wantVal)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v -run TestMergeWithParentEnv ./internal/platform/windows/...`
Expected: FAIL with "undefined: mergeWithParentEnv"

**Step 3: Write minimal implementation**

Add to `internal/platform/windows/appcontainer.go` (after imports):

```go
// mergeWithParentEnv combines os.Environ() with injected variables.
// Injected values override parent values for the same key.
func mergeWithParentEnv(inject map[string]string) map[string]string {
	result := make(map[string]string)

	// Start with parent environment
	for _, e := range os.Environ() {
		if k, v, ok := strings.Cut(e, "="); ok {
			result[k] = v
		}
	}

	// Layer injections on top
	for k, v := range inject {
		result[k] = v
	}

	return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v -run TestMergeWithParentEnv ./internal/platform/windows/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/windows/appcontainer.go internal/platform/windows/appcontainer_test.go
git commit -m "feat(windows): add mergeWithParentEnv helper for env_inject"
```

---

## Task 2: Add buildEnvironmentBlock Helper

**Files:**
- Modify: `internal/platform/windows/appcontainer.go`
- Test: `internal/platform/windows/appcontainer_test.go`

**Step 1: Write the failing test for buildEnvironmentBlock**

Add to `internal/platform/windows/appcontainer_test.go`:

```go
func TestBuildEnvironmentBlock(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantNil  bool
		contains []string
	}{
		{
			name:    "empty env returns nil",
			env:     map[string]string{},
			wantNil: true,
		},
		{
			name:     "single var creates block",
			env:      map[string]string{"FOO": "bar"},
			wantNil:  false,
			contains: []string{"FOO=bar"},
		},
		{
			name:     "multiple vars creates block",
			env:      map[string]string{"FOO": "bar", "BAZ": "qux"},
			wantNil:  false,
			contains: []string{"FOO=bar", "BAZ=qux"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEnvironmentBlock(tt.env)
			if tt.wantNil {
				if result != nil {
					t.Errorf("buildEnvironmentBlock() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Errorf("buildEnvironmentBlock() = nil, want non-nil")
				return
			}
			// Decode UTF-16 block back to string for verification
			block := decodeEnvironmentBlock(result)
			for _, want := range tt.contains {
				found := false
				for _, got := range block {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("buildEnvironmentBlock() missing %q in %v", want, block)
				}
			}
		})
	}
}

// decodeEnvironmentBlock converts a UTF-16 environment block back to strings for testing
func decodeEnvironmentBlock(block *uint16) []string {
	if block == nil {
		return nil
	}
	var result []string
	ptr := unsafe.Pointer(block)
	for {
		s := windows.UTF16PtrToString((*uint16)(ptr))
		if s == "" {
			break
		}
		result = append(result, s)
		// Move pointer past this string + null terminator
		ptr = unsafe.Pointer(uintptr(ptr) + uintptr((len(s)+1)*2))
	}
	return result
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v -run TestBuildEnvironmentBlock ./internal/platform/windows/...`
Expected: FAIL with "undefined: buildEnvironmentBlock"

**Step 3: Write minimal implementation**

Add to `internal/platform/windows/appcontainer.go`:

```go
import (
	"sort"
	"strings"
	"syscall"
)

// buildEnvironmentBlock creates a Windows environment block from a map.
// Returns nil if env is empty (signals inheritance to CreateProcessW).
// The block is UTF-16 encoded, null-separated, double-null terminated.
func buildEnvironmentBlock(env map[string]string) *uint16 {
	if len(env) == 0 {
		return nil
	}

	// Build "KEY=VALUE" strings
	var entries []string
	for k, v := range env {
		entries = append(entries, k+"="+v)
	}
	sort.Strings(entries) // Windows convention: sorted

	// Join with nulls, add double-null terminator
	joined := strings.Join(entries, "\x00") + "\x00\x00"

	// Convert to UTF-16
	utf16Block, _ := syscall.UTF16FromString(joined)
	return &utf16Block[0]
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v -run TestBuildEnvironmentBlock ./internal/platform/windows/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/platform/windows/appcontainer.go internal/platform/windows/appcontainer_test.go
git commit -m "feat(windows): add buildEnvironmentBlock helper for env_inject"
```

---

## Task 3: Update RunInAppContainer Signature

**Files:**
- Modify: `internal/platform/windows/appcontainer.go`
- Test: `internal/platform/windows/appcontainer_test.go`

**Step 1: Update function signature and CreateProcessW call**

Modify `RunInAppContainer` in `internal/platform/windows/appcontainer.go`:

1. Change signature from:
```go
func (ac *AppContainer) RunInAppContainer(cmdLine, workDir string, captureOutput bool) (*AppContainerProcess, error)
```
To:
```go
func (ac *AppContainer) RunInAppContainer(cmdLine, workDir string, captureOutput bool, env map[string]string) (*AppContainerProcess, error)
```

2. Before the `CreateProcessW` call, add environment block building:
```go
	// Build environment block if env provided
	var envBlock *uint16
	if len(env) > 0 {
		merged := mergeWithParentEnv(env)
		envBlock = buildEnvironmentBlock(merged)
	}

	// CreateProcess flags - add CREATE_UNICODE_ENVIRONMENT when using custom env
	flags := extendedStartupInfoPresent
	if envBlock != nil {
		flags |= 0x00000400 // CREATE_UNICODE_ENVIRONMENT
	}
```

3. Update the `CreateProcessW` call to use `flags` and `envBlock`:
```go
	r1, _, err = procCreateProcessW.Call(
		0, // lpApplicationName
		uintptr(unsafe.Pointer(cmdLinePtr)),
		0, 0, // security attributes
		inheritHandles,
		flags,                                  // was: extendedStartupInfoPresent
		uintptr(unsafe.Pointer(envBlock)),     // was: 0
		uintptr(unsafe.Pointer(workDirPtr)),
		uintptr(unsafe.Pointer(&siEx)),
		uintptr(unsafe.Pointer(&pi)),
	)
```

**Step 2: Update existing test calls**

In `internal/platform/windows/appcontainer_test.go`, update all calls to `RunInAppContainer` to pass `nil` as the fourth parameter:

```go
// Find all occurrences like:
proc, err := ac.RunInAppContainer(cmdLine, workDir, true)
// Change to:
proc, err := ac.RunInAppContainer(cmdLine, workDir, true, nil)
```

**Step 3: Run tests to verify existing behavior preserved**

Run: `go test -v ./internal/platform/windows/...`
Expected: PASS (existing tests still work with nil env)

**Step 4: Commit**

```bash
git add internal/platform/windows/appcontainer.go internal/platform/windows/appcontainer_test.go
git commit -m "feat(windows): add env parameter to RunInAppContainer"
```

---

## Task 4: Add Integration Test for env_inject

**Files:**
- Test: `internal/platform/windows/appcontainer_test.go`

**Step 1: Write the integration test**

Add to `internal/platform/windows/appcontainer_test.go`:

```go
func TestRunInAppContainerWithEnv(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	ac, err := NewAppContainer("test-env-inject")
	if err != nil {
		t.Fatalf("NewAppContainer failed: %v", err)
	}
	defer ac.Delete()

	env := map[string]string{
		"AGENTSH_TEST_VAR": "injected_value_12345",
	}

	// cmd.exe /c echo %AGENTSH_TEST_VAR%
	proc, err := ac.RunInAppContainer(
		`cmd.exe /c echo %AGENTSH_TEST_VAR%`,
		"",
		true,
		env,
	)
	if err != nil {
		t.Fatalf("RunInAppContainer failed: %v", err)
	}

	_, err = proc.Process.Wait()
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	output, err := io.ReadAll(proc.Stdout())
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "injected_value_12345") {
		t.Errorf("Output %q does not contain injected value", string(output))
	}
}

func TestRunInAppContainerEnvOverridesParent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	// Set a parent env var
	os.Setenv("AGENTSH_PARENT_VAR", "parent_value")
	defer os.Unsetenv("AGENTSH_PARENT_VAR")

	ac, err := NewAppContainer("test-env-override")
	if err != nil {
		t.Fatalf("NewAppContainer failed: %v", err)
	}
	defer ac.Delete()

	env := map[string]string{
		"AGENTSH_PARENT_VAR": "overridden_value",
	}

	proc, err := ac.RunInAppContainer(
		`cmd.exe /c echo %AGENTSH_PARENT_VAR%`,
		"",
		true,
		env,
	)
	if err != nil {
		t.Fatalf("RunInAppContainer failed: %v", err)
	}

	_, err = proc.Process.Wait()
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	output, err := io.ReadAll(proc.Stdout())
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !strings.Contains(string(output), "overridden_value") {
		t.Errorf("Output %q does not contain overridden value", string(output))
	}
	if strings.Contains(string(output), "parent_value") {
		t.Errorf("Output %q still contains parent value", string(output))
	}
}
```

**Step 2: Run test (will skip on non-Windows)**

Run: `go test -v -run TestRunInAppContainerWithEnv ./internal/platform/windows/...`
Expected: SKIP with "Windows-only test" (on Linux) or PASS (on Windows)

**Step 3: Commit**

```bash
git add internal/platform/windows/appcontainer_test.go
git commit -m "test(windows): add env_inject integration tests"
```

---

## Task 5: Update Caller to Pass env_inject

**Files:**
- Explore: Find where `RunInAppContainer` is called from exec path
- Modify: The caller file to pass `extra.envInject`

**Step 1: Find the caller**

Run: `grep -r "RunInAppContainer" --include="*.go" | grep -v "_test.go" | grep -v "appcontainer.go"`

This will show where `RunInAppContainer` is called. The exec path on Windows should pass `extra.envInject`.

**Step 2: Update the caller**

If found in a file like `internal/api/exec_windows.go` or similar, update the call from:
```go
proc, err := ac.RunInAppContainer(cmdLine, workDir, captureOutput)
```
To:
```go
proc, err := ac.RunInAppContainer(cmdLine, workDir, captureOutput, extra.envInject)
```

If `extra` might be nil, add a nil check:
```go
var envInject map[string]string
if extra != nil {
    envInject = extra.envInject
}
proc, err := ac.RunInAppContainer(cmdLine, workDir, captureOutput, envInject)
```

**Step 3: Run tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add <caller-file>
git commit -m "feat(windows): wire env_inject through exec path"
```

---

## Task 6: Final Verification and Cleanup

**Step 1: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 2: Run gofmt**

Run: `gofmt -w internal/platform/windows/`
Expected: No output (files already formatted) or files reformatted

**Step 3: Run go vet**

Run: `go vet ./internal/platform/windows/...`
Expected: No errors

**Step 4: Final commit if any formatting changes**

```bash
git add -A
git commit -m "style: format windows env_inject code" || echo "Nothing to commit"
```

**Step 5: Push feature branch**

```bash
git push -u origin feature/windows-env-inject
```

---

## Summary

| Task | Description | Est. Time |
|------|-------------|-----------|
| 1 | Add mergeWithParentEnv helper | 5 min |
| 2 | Add buildEnvironmentBlock helper | 5 min |
| 3 | Update RunInAppContainer signature | 10 min |
| 4 | Add integration tests | 5 min |
| 5 | Update caller to pass env_inject | 5 min |
| 6 | Final verification | 5 min |

**Total: ~35 minutes**

After completion, create a PR with title: "feat(windows): add env_inject support"
