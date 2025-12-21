# Unix Socket Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce and monitor AF_UNIX socket operations (connect/bind/listen/sendto) via seccomp user-notify with policy-based allow/deny, emitting events and guidance.

**Architecture:** Commands run through a wrapper that installs a seccomp user-notify filter, sends the notify fd to the agentsh server via socketpair (SCM_RIGHTS), and execs the real command. The server listens on the notify fd, uses `CheckUnixSocket` policy to allow/deny, and emits `unix_socket_op` events. Privileged integration tests verify allow/deny/abstract behavior and skip gracefully when user-notify is unavailable.

**Tech Stack:** Go 1.25; seccomp/libseccomp-golang; testcontainers; Linux-only enforcement; socketpair fd passing; SCM_RIGHTS.

---

### Task 1: Add wrapper binary to install filter and hand off notify fd

**Files:**
- Create: `cmd/agentsh-unixwrap/main.go`
- Modify: `go.mod`, `go.sum` (already include seccomp dep)

**Steps:**
1) Write `main` that:
   - Creates a socketpair.
   - Installs seccomp user-notify filter via `unix.InstallOrWarn` (exit 0 with message if unsupported).
   - Gets notify fd, sends it to the server via socketpair using `unix.Sendmsg` with SCM_RIGHTS.
   - Closes socketpair fds and `execve` the target command (args after `--`).
   - Passes original env through.
2) Build stub to exit non-zero on errors with clear logs to stderr.
3) `go test ./...` (should pass; wrapper has no tests yet).

### Task 2: Server receive path for notify fd

**Files:**
- Modify: `internal/api/core.go` (exec path)
- Modify: `internal/api/pty_core.go` (PTY path)
- Create: `internal/netmonitor/unix/fdpass.go`

**Steps:**
1) Add helper to receive an fd over a socketpair (SCM_RIGHTS) and return `*os.File` or int.
2) In exec/pty paths, create socketpair, set child env `AGENTSH_NOTIFY_SOCK_FD=<n>`, pass one end via `ExtraFiles` to wrapper.
3) After `cmd.Start`, close child end; receive notify fd via helper and start handler loop (reuse existing handler) with session policy and emitter.
4) Ensure handler cleanup on command completion; guard if notify fd not received.
5) `go test ./internal/api -run TestPlaceholder` (no new tests yet) then full `go test ./...` to ensure build.

### Task 3: Use wrapper when unix-socket enforcement enabled

**Files:**
- Modify: `internal/api/core.go`, `internal/api/pty_core.go`
- Modify: `internal/config/config.go` (add toggle? optional)

**Steps:**
1) Add config flag `sandbox.unix_sockets.enabled` (bool) default false.
2) When enabled, change command invocation to `/usr/local/bin/agentsh-unixwrap -- <cmd> ...` (binary path configurable via env `AGENTSH_UNIXWRAP_BIN`, default `agentsh-unixwrap` on PATH).
3) If wrapper not found or user-notify unsupported, set guidance note but allow command (monitor-only) or fail based on config; choose monitor-only default.
4) Run `go test ./internal/api/...` and `go test ./...`.

### Task 4: Event/guidance wiring for unix sockets

**Files:**
- Modify: `internal/netmonitor/unix/handler.go`
- Modify: `internal/api/guidance` helpers if needed

**Steps:**
1) Ensure handler emits `unix_socket_op` events with `Abstract`, `Operation`, policy info; append to `BlockedOperations` when denied.
2) Map denied decisions to HTTP 403 with guidance (similar to network/file blocked guidance).
3) `go test ./...`.

### Task 5: Privileged integration test

**Files:**
- Add: `internal/integration/agentsh_unix_socket_test.go`
- Modify: `.github/workflows/ci.yml` if needed (already privileged for FUSE; ensure linux job runs this test)

**Test steps (in code):**
- Build agentsh + agentsh-unixwrap.
- Start testcontainer (privileged, SYS_ADMIN) with policy: allow `/workspace/ok.sock`, deny `/workspace/no.sock`, deny abstract `@bad`.
- In session, start a Unix listener on allowed path and connect (should succeed), attempt connect to denied path (expect 403 blocked), attempt abstract socket (expect block or skip if unsupported).
- Skip test if `DetectSupport` returns unsupported.

### Task 6: Docs update

**Files:**
- Modify: `README.md` or `docs/spec.md` to document `unix_socket_rules` and the enforcement requirement (Linux + seccomp user-notify + wrapper).

**Steps:**
1) Add brief section with example policy and note about privileged requirement.
2) `go test ./...` (no doc tests) and spellcheck if available.

### Task 7: Clean up and commit

**Files:**
- All modified/created files.

**Steps:**
1) `go test ./...` and `go test -tags=integration ./internal/integration/...` locally.
2) Commit with message "Add unix socket policy enforcement via seccomp notify".
3) Push branch.

## Current Status (Dec 2025)
- Seccomp user-notify wrapper (`agentsh-unixwrap`) is in place and ships the notify fd back to the server.
- Runtime handling is audit-only for now; parent notify fd is closed and no enforcement occurs yet.
- Policy model includes unix socket rules; enforcement wiring to ServeNotify remains TODO.
