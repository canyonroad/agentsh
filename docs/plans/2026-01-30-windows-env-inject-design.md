# Windows env_inject Support Design

**Date:** 2026-01-30
**Status:** Approved
**Goal:** Enable `env_inject` on Windows for parity with Linux/macOS, allowing operators to inject environment variables into sandboxed processes.

## Overview

The existing `env_inject` feature works on Linux/macOS via Go's standard `cmd.Env`. On Windows, processes launched via `CreateProcessW` in `appcontainer.go` currently inherit the parent environment (passing `0` for the environment parameter). This design adds support for passing a custom environment block to Windows processes.

## Function Signature Change

```go
// Before
func (ac *AppContainer) RunInAppContainer(cmdLine, workDir string, captureOutput bool) (*AppContainerProcess, error)

// After
func (ac *AppContainer) RunInAppContainer(cmdLine, workDir string, captureOutput bool, env map[string]string) (*AppContainerProcess, error)
```

**Behavior:**
- If `env` is nil or empty → pass `0` to CreateProcessW (inherit, current behavior)
- If `env` has values → build environment block with parent env + injections, pass to CreateProcessW
- Works for both AppContainer and non-AppContainer code paths

## Environment Block Building

Windows environment block format for CreateProcessW:
- UTF-16 encoded strings
- Each `KEY=VALUE` pair is null-terminated
- Block ends with an extra null (double-null termination)
- Example: `VAR1=val1\0VAR2=val2\0\0`

### Helper Functions

```go
// buildEnvironmentBlock creates a Windows environment block from a map.
// Returns nil if env is empty (signals inheritance to CreateProcessW).
func buildEnvironmentBlock(env map[string]string) *uint16 {
    if len(env) == 0 {
        return nil
    }

    // Build "KEY=VALUE\0" strings
    var block []string
    for k, v := range env {
        block = append(block, k+"="+v)
    }
    sort.Strings(block) // Windows expects sorted (conventional)

    // Join with nulls, add double-null terminator
    joined := strings.Join(block, "\x00") + "\x00\x00"

    // Convert to UTF-16
    utf16Block, _ := syscall.UTF16FromString(joined)
    return &utf16Block[0]
}

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

## CreateProcessW Integration

Current code passes `0` for environment (inherit). Updated code:

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

r1, _, err = procCreateProcessW.Call(
    0,
    uintptr(unsafe.Pointer(cmdLinePtr)),
    0, 0,
    inheritHandles,
    flags,
    uintptr(unsafe.Pointer(envBlock)), // environment block or nil
    uintptr(unsafe.Pointer(workDirPtr)),
    uintptr(unsafe.Pointer(&siEx)),
    uintptr(unsafe.Pointer(&pi)),
)
```

**Key points:**
- `CREATE_UNICODE_ENVIRONMENT` flag (0x400) tells Windows the block is UTF-16
- Passing `nil` (when envBlock is nil) means inherit - preserves current behavior
- Merged environment includes parent env so child doesn't lose PATH, etc.

## Caller Integration

The Windows exec path passes `extra.envInject` to the updated function:

```go
// Before
proc, err := ac.RunInAppContainer(cmdLine, workDir, true)

// After
proc, err := ac.RunInAppContainer(cmdLine, workDir, true, extra.envInject)
```

Existing callers and tests pass `nil` to preserve current behavior.

## Testing

### Unit Tests

1. **buildEnvironmentBlock:**
   - Empty map returns nil
   - Single var produces correct UTF-16 block
   - Multiple vars are null-separated with double-null terminator

2. **mergeWithParentEnv:**
   - Empty inject returns parent env unchanged
   - Inject adds new variables
   - Inject overrides existing parent variables

3. **RunInAppContainer with env:**
   - Process receives injected variable
   - Injected var overrides parent var
   - Nil env preserves inheritance

### Example Test

```go
func TestRunInAppContainerWithEnv(t *testing.T) {
    if !isAdmin() {
        t.Skip("requires admin privileges")
    }

    ac, err := NewAppContainer("test-env")
    require.NoError(t, err)
    defer ac.Delete()

    env := map[string]string{
        "AGENTSH_TEST_VAR": "injected_value",
    }

    proc, err := ac.RunInAppContainer(
        `cmd.exe /c echo %AGENTSH_TEST_VAR%`,
        "",
        true,
        env,
    )
    require.NoError(t, err)

    _, _ = proc.Process.Wait()
    output, _ := io.ReadAll(proc.Stdout())

    assert.Contains(t, string(output), "injected_value")
}
```

## Edge Cases

1. **Empty env_inject** - Pass `nil` → inherits parent env (no change)
2. **Large environment** - Windows ~32KB limit applies; CreateProcessW returns error if exceeded
3. **Special characters** - UTF-16 conversion handles Unicode; values with `=` are fine
4. **PATH and system variables** - Always preserved (merge with parent first)

## Files to Modify

| File | Changes |
|------|---------|
| `internal/platform/windows/appcontainer.go` | Add `env` param, `buildEnvironmentBlock`, `mergeWithParentEnv`, update CreateProcessW call |
| `internal/platform/windows/appcontainer_test.go` | Add env tests, update existing test calls with `nil` |
| Caller file (Windows exec path) | Pass `extra.envInject` to RunInAppContainer |
