# Ptrace Soft-Delete Wiring

**Date:** 2026-03-22
**Status:** Implemented
**Scope:** Linux only (ptrace enforcement)

## Background

The ptrace tracer has a complete, tested `softDeleteFile()` implementation that intercepts `unlinkat`/`unlink` syscalls and moves files to a trash directory via injected `mkdirat` + `renameat2` syscalls. An integration test (`TestIntegration_SoftDelete`) confirms the mechanism works end-to-end.

However, the ptrace handler in `internal/api/ptrace_handlers.go` explicitly denies `DecisionSoftDelete` instead of returning the soft-delete action:

```go
case types.DecisionSoftDelete:
    // Soft-delete requires a trash directory which is not available in the
    // ptrace handler context. Deny with audit visibility.
    return ptrace.FileResult{
        Allow:  false,
        Action: "deny",
        Errno:  int32(syscall.EACCES),
    }
```

The fix is to pass the trash directory into the handler context and return the soft-delete action.

## What Changes

### 1. Add trashDir to ptrace handler router

**File:** `internal/api/ptrace_handlers.go`

Add a `trashDir string` field to the `ptraceHandlerRouter` struct (or equivalent handler struct that contains the `DecisionSoftDelete` case).

### 2. Wire trash path from config

**File:** Where `ptraceHandlerRouter` is constructed (likely `internal/api/app_ptrace_linux.go` or the ptrace setup code)

Pass `a.cfg.Sandbox.FUSE.Audit.TrashPath` as the `trashDir` value. This reuses the existing FUSE audit config — no new config fields needed.

### 3. Return soft-delete action when trash dir is available

**File:** `internal/api/ptrace_handlers.go`

Replace the deny fallback:

```go
case types.DecisionSoftDelete:
    if h.trashDir == "" {
        // No trash directory configured — deny (current behavior)
        return ptrace.FileResult{
            Allow:  false,
            Action: "deny",
            Errno:  int32(syscall.EACCES),
        }
    }
    return ptrace.FileResult{
        Action:   "soft-delete",
        TrashDir: h.trashDir,
    }
```

The tracer's existing `softDeleteFile()` handles the rest: generates a unique trash filename, injects `mkdirat` to create the trash directory, injects `renameat2` to move the file, and makes the tracee think `unlink` succeeded.

## Testing

1. Existing `TestIntegration_SoftDelete` already covers the tracer-level mechanism.
2. Add a unit test in `ptrace_handlers_test.go` verifying that `DecisionSoftDelete` with a non-empty `trashDir` returns `Action: "soft-delete"` and `TrashDir` populated.
3. Add a unit test verifying that `DecisionSoftDelete` with empty `trashDir` returns `Action: "deny"`.

## Out of Scope

- File hashing before soft-delete (FUSE does this; ptrace can add later)
- Restore tokens
- `file_soft_delete` event emission from ptrace path
- New config fields — reuses existing `sandbox.fuse.audit.trash_path`
