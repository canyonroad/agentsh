# Runtime Safety Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix approval hangs, ensure timed-out commands terminate whole process groups, and prevent host environment leakage into agent sessions.

**Architecture:** Keep current agentsh API; tighten behaviors inside approvals manager and exec paths. Add deterministic tests for approvals and process-group cleanup; introduce explicit environment allow/deny logic before spawning commands.

**Tech Stack:** Go 1.25+, stdlib os/exec/syscall/context, httptest, existing test helpers.

### Task 1: Make local approval prompts respect context/timeout

**Files:**
- Modify: `internal/approvals/manager.go`
- Test: `internal/approvals/manager_test.go` (new)

**Step 1: Write failing test**

```go
func TestRequestApproval_ContextCancelUnblocksPrompt(t *testing.T) {
    // Use a fake tty reader that never replies; cancel ctx and expect resolution within timeout.
}
```

**Step 2: Run test to see it fail**

Run: `go test ./internal/approvals -run TestRequestApproval_ContextCancelUnblocksPrompt -count=1`
Expected: FAIL due to hang or missing behavior.

**Step 3: Implement prompt handling**

```go
// spawn prompt in goroutine, select on ctx.Done()/timer/result
// ensure pending is removed and emitEvent called once
```

Ensure `promptTTY` takes a context and returns on cancellation; guard against leaked goroutines.

**Step 4: Add timeout test**

```go
func TestRequestApproval_TimesOut(t *testing.T) { /* expect Resolution Approved=false, Reason contains "timeout" */ }
```

**Step 5: Run package tests**

Run: `go test ./internal/approvals -count=1`
Expected: PASS.

### Task 2: Kill whole process group on command timeout/failure

**Files:**
- Modify: `internal/api/exec.go`
- Modify: `internal/api/exec_stream.go`
- Test: `internal/api/exec_timeout_test.go` (extend)

**Step 1: Write failing tests**

```go
func TestExecTimeout_KillsChildProcesses(t *testing.T) {
    // Spawn shell that forks child sleeping; ensure both die and exit code 124.
}
```

Add similar coverage for streaming endpoint if needed.

**Step 2: Run targeted tests to see failure**

Run: `go test ./internal/api -run Timeout_Kills -count=1`
Expected: FAIL because children survive.

**Step 3: Implement process-group cleanup**

```go
// after ctx deadline or non-exit errors, send SIGKILL to -pgid; ensure no double-kill panic
```

Apply to both exec paths; keep current SIGTERM+SIGKILL in /kill endpoint unchanged.

**Step 4: Re-run api tests**

Run: `go test ./internal/api -count=1`
Expected: PASS.

### Task 3: Sanitize environment passed to exec

**Files:**
- Modify: `internal/api/exec.go`
- Test: `internal/api/exec_env_test.go` (extend)

**Step 1: Write failing test**

```go
func TestMergeEnv_StripsHostSecrets(t *testing.T) {
    os.Setenv("AWS_SECRET_ACCESS_KEY", "hostsecret")
    got := mergeEnv(baseEnv, session, nil)
    // assert sensitive keys not present; allowlist PATH, LANG, TERM, AGENTSH_*, proxy vars
}
```

**Step 2: Run failing test**

Run: `go test ./internal/api -run MergeEnv_StripsHostSecrets -count=1`
Expected: FAIL (host vars still present).

**Step 3: Implement env policy**

```go
// start from minimal base (PATH + locale + TERM + HOME?), add session env, overrides, proxy vars, AGENTSH_* telemetry
// drop known secret prefixes (AWS_, GCP_, AZURE_, SSH_AUTH_SOCK, DOCKER_*, GOOGLE_APPLICATION_CREDENTIALS, etc.)
```

Document rationale in code comments.

**Step 4: Re-run api tests**

Run: `go test ./internal/api -count=1`
Expected: PASS.

### Task 4: Full verification

**Files:** none (run tests)

**Step 1: Run full test suite**

Run: `go test ./...`
Expected: PASS.

**Step 2: Quick smoke**

Optionally run `go test ./cmd/...` (already covered) and `go vet ./...` if time permits.

