# Fix file_monitor Write Denials in Wrap Path

## Goal

Make `seccomp.file_monitor.enabled: true` correctly allow writes to workspace, `/tmp`, and other policy-allowed paths in the `agentsh wrap` execution path. Current score: 63/73. Target: 73/73.

## Root Causes

Two independent bugs cause all writes to be denied when file_monitor is enabled in the wrap path:

### 1. ProcessVMReadv fails under Yama ptrace_scope=1

In the wrap path, the CLI spawns the sandboxed child independently of the server. The server is NOT an ancestor of the child. On Ubuntu/Debian with `kernel.yama.ptrace_scope=1` (the default), `ProcessVMReadv` requires the caller to be an ancestor of the target — so it fails with EPERM.

`resolvePathAt` calls `readString` → `ProcessVMReadv` → EPERM → error. In `handleFileNotificationEmulated`, when path resolution fails for a non-read-only open, the handler responds with EACCES. This blocks ALL writes before policy is even consulted — including writes to `/tmp` (literal path, no variable expansion needed).

PR #168 fixed the read case by checking `isReadOnlyOpen(flags)` and returning CONTINUE. Writes remain blocked.

### 2. Wrap path uses unexpanded policy engine

`startNotifyHandlerForWrap` (wrap_linux.go:109) creates the file handler with `a.policy` — the app-level engine created via `NewEngine()` with NO variable expansion. Policy rules using `${PROJECT_ROOT}/**` contain the literal string `${PROJECT_ROOT}` as a glob pattern, which never matches real paths like `/home/user/project/file.txt`.

The exec path correctly uses a session-specific engine created via `NewEngineWithVariables()` with `PROJECT_ROOT`, `GIT_ROOT`, and `HOME` expanded. The wrap path has the session object available (it's passed through `acceptNotifyFD`) but never uses its policy engine.

## Design

### Fix 1: PR_SET_PTRACER_ANY in the wrapper

Add `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` in `cmd/agentsh-unixwrap/main.go` before exec.

This authorizes any process (including the server) to call `ProcessVMReadv` on the sandboxed child, bypassing the Yama ancestor check. The call goes after all handshakes complete and before `syscall.Exec`, alongside the existing pre-exec setup (landlock, ptrace sync).

**Security consideration:** The child is already sandboxed via seccomp BPF. Allowing non-ancestor processes to read its memory is a minor relaxation — the sandbox itself is the security boundary, not Yama's ptrace restriction. The server needs this access to enforce file policy.

**Scope:** The prctl fixes ALL `ProcessVMReadv`/`ProcessVMWritev` callsites simultaneously — not just `readString` but also `readPointer`, `writeString`, `ReadSockaddr`, `readOpenHow`, and `readOpenHowResolve`. No per-function changes needed.

**Exec survival:** `PR_SET_PTRACER` is stored per-task in the Yama LSM, separate from credentials. It is NOT cleared by `yama_task_free` on exec — only on task exit. It should survive exec for non-setuid binaries. If it doesn't (needs verification), add a `/proc/PID/mem` pread fallback to ALL ProcessVMReadv callsites in the seccomp handler path (`execve_reader.go` and `file_syscalls.go`), matching the pattern in `internal/ptrace/memory.go:35-46`.

**Files:**
- Modify: `cmd/agentsh-unixwrap/main.go` — add prctl call before exec
- Contingent: `internal/netmonitor/unix/execve_reader.go` and `file_syscalls.go` — add `/proc/PID/mem` fallback (only if prctl doesn't survive exec)

### Fix 2: Use session-specific policy engine in wrap path

Thread the session's policy engine through to the notify handler.

**Changes:**
- `acceptNotifyFD` (wrap.go:293): already receives `s *session.Session` — pass it to `startNotifyHandlerForWrap`
- `startNotifyHandlerForWrap` (wrap_linux.go:61): add `s *session.Session` parameter; prefer `s.PolicyEngine()` over `a.policy` with fallback (same pattern as exec path in core.go:167-174)
- Three callsites use `a.policy` at lines 68, 109, 117 — all three should use the session engine

**Pattern (from exec path):**
```go
sessionPolicy := a.policy
if s != nil {
    if sp := s.PolicyEngine(); sp != nil {
        sessionPolicy = sp
    }
}
```

**Files:**
- Modify: `internal/api/wrap.go` — pass session to `startNotifyHandlerForWrap`
- Modify: `internal/api/wrap_linux.go` — accept session, use session policy engine
- Modify: `internal/api/wrap_windows.go` — update `startNotifyHandlerForWrap` signature (stub)
- Modify: `internal/api/wrap_other.go` — update `startNotifyHandlerForWrap` signature (stub)

**Out of scope:** `startSignalHandlerForWrap` also uses `a.policy`, but signal rules don't use path variables — they match on signal names/numbers. No change needed there.

## Testing

### Unit tests
- Verify `PR_SET_PTRACER` survives exec: fork, child calls prctl + exec, parent tries ProcessVMReadv on grandchild
- Existing `TestFilePolicyEngineWrapper_CheckFile` already validates the policy engine path

### Integration tests
- Extend `internal/integration/file_monitor_test.go`:
  - Add write-allowed test: `echo test > /workspace/test.txt` should succeed
  - Add `/tmp` write test: `echo test > /tmp/test.txt` should succeed
  - Add write-denied test: `echo test > /etc/test.txt` should be denied
  - Test with `${PROJECT_ROOT}` variable expansion active

## Affected paths

Only the wrap path is affected. The exec path already:
1. Has the server as ancestor of the child (ProcessVMReadv works)
2. Uses session-specific policy engine (variables expanded)
