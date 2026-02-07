# macOS Endpoint Security AUTH_EXEC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the existing ESF client's `AUTH_EXEC` handler into the full agentsh exec pipeline, adding recursion prevention (`es_mute_process`), the deny-then-respawn stub pattern for redirect/approve decisions, and macOS-specific `agentsh wrap` support.

**Architecture:** The ESF Swift infrastructure already exists (`macos/SysExt/ESFClient.swift`). We extend the Go-side XPC protocol to support full exec pipeline decisions (not just allow/deny), add a `wrap_darwin.go` to connect `agentsh wrap` to the ES system on macOS, modify the XPC protocol to carry exec pipeline responses (decision + action), and add `es_mute_process()` calls for recursion prevention. The stub binary (`cmd/agentsh-stub/`) is already platform-agnostic and reusable.

**Tech Stack:** Go (XPC server, wrap CLI, stub), Swift (ESF client, System Extension), Unix domain sockets (XPC transport), existing stub wire protocol

---

## Context for Implementers

### What Already Exists

1. **`macos/SysExt/ESFClient.swift`** — Complete ESF client subscribing to `AUTH_EXEC`, `AUTH_OPEN`, etc. The `handleAuthExec` method currently does simple allow/deny via XPC `checkCommand` call. **Needs extending** for full pipeline routing.

2. **`macos/SysExt/ProcessHierarchy.swift`** — Parent-child process tracking via fork/exit events with sysctl fallback. Already used for session scoping.

3. **`macos/Shared/XPCProtocol.swift`** — Swift XPC protocol with `checkCommand(executable:args:pid:sessionID:reply:)`. Reply is `(Bool, String?)` — just allow/deny. **Needs extending** to return decision + action.

4. **`internal/platform/darwin/xpc/`** — Go-side XPC socket server. Handles `RequestTypeCommand` with simple allow/deny. **Needs extending** for exec pipeline decisions.

5. **`internal/stub/`** — Complete stub wire protocol and server. Platform-agnostic. **Reusable as-is.**

6. **`cmd/agentsh-stub/`** — Stub binary. Reads `AGENTSH_STUB_FD` env var for socket fd. **Reusable as-is.**

7. **`internal/cli/wrap.go`** — Platform-independent wrap orchestration. Calls `platformSetupWrap()`. **Needs darwin variant.**

8. **`internal/cli/wrap_other.go`** — `//go:build !linux` stub returning "not supported". **Needs build tag change** to `!linux && !darwin`.

### Key Design Decisions

- **Deny-then-respawn**: ES `AUTH_EXEC` cannot rewrite exec targets. For redirect/approve, we deny the original exec and spawn `agentsh-stub` as a new child.
- **Recursion guard**: `es_mute_process()` on server-spawned processes prevents re-interception.
- **XPC protocol extension**: The `checkCommand` reply changes from `(Bool, String?)` to `(String, String?, String?)` — `(decision, rule, action)` where action is "continue", "redirect", or "deny".
- **Session scoping**: AUTH_EXEC events are filtered by session PID ancestry via `ProcessHierarchy.isDescendant()`.

---

## Task 1: Extend XPC Protocol for Exec Pipeline Decisions

Extend the Go-side XPC server to return full exec pipeline decisions (not just allow/deny) for command checks.

**Files:**
- Modify: `internal/platform/darwin/xpc/protocol.go`
- Modify: `internal/platform/darwin/xpc/server.go`
- Modify: `internal/platform/darwin/xpc/handler.go`
- Test: `internal/platform/darwin/xpc/server_test.go`
- Test: `internal/platform/darwin/xpc/handler_test.go`

### What to Do

The current `RequestTypeCommand` handler returns `PolicyResponse{Allow: bool, Rule: string}`. We need it to also return the exec pipeline decision and action.

**Step 1:** Add new fields to `PolicyResponse` in `protocol.go`:

```go
// In PolicyResponse struct, add:
Action      string `json:"action,omitempty"`      // "continue", "redirect", "deny" (exec pipeline action)
ExecDecision string `json:"exec_decision,omitempty"` // "allow", "deny", "approve", "redirect", "audit"
```

**Step 2:** Add a new `RequestType` constant for exec-specific command checks:

```go
RequestTypeExecCheck RequestType = "exec_check"
```

**Step 3:** Add `ExecCheckRequest` and handler interfaces. In `server.go`, add an `ExecHandler` interface:

```go
// ExecHandler handles exec pipeline checks from the ESF client.
type ExecHandler interface {
    CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string) ExecCheckResult
}

type ExecCheckResult struct {
    Decision string // "allow", "deny", "approve", "redirect", "audit"
    Action   string // "continue", "redirect", "deny"
    Rule     string
    Message  string
}
```

**Step 4:** Add `SetExecHandler()` to `Server` and wire it into `handleRequest()`.

**Step 5:** Update `PolicyAdapter` in `handler.go` to implement `ExecHandler` by delegating to the policy engine's `CheckCommand`, mapping the decision to an action:
- `allow` / `audit` → `Action: "continue"`
- `deny` → `Action: "deny"`
- `approve` / `redirect` → `Action: "redirect"`

**Step 6:** Write tests in `server_test.go`:
- Test `exec_check` request returns correct decision/action for allow/deny/approve policies
- Test missing exec handler returns allow (fail-open)

**Step 7:** Run tests:
```bash
go test ./internal/platform/darwin/xpc/ -v -count=1
```

**Step 8:** Commit:
```bash
git add internal/platform/darwin/xpc/
git commit -m "feat(xpc): add exec_check request type for ES exec pipeline"
```

---

## Task 2: Extend Swift XPC Protocol and ESFClient for Full Pipeline

Extend the Swift-side XPC protocol and ESFClient to handle exec pipeline decisions (not just allow/deny).

**Files:**
- Modify: `macos/Shared/XPCProtocol.swift`
- Modify: `macos/SysExt/ESFClient.swift`

### What to Do

**Step 1:** Add a new method to `AgentshXPCProtocol` for exec pipeline checks:

```swift
/// Check command execution through the full exec pipeline.
/// Returns: (decision, action, rule) where:
///   - decision: "allow", "deny", "approve", "redirect", "audit"
///   - action: "continue" (allow in-place), "redirect" (deny + spawn stub), "deny" (block)
///   - rule: The matched policy rule name
func checkExecPipeline(
    executable: String,
    args: [String],
    pid: pid_t,
    parentPID: pid_t,
    sessionID: String?,
    reply: @escaping (String, String, String?) -> Void  // (decision, action, rule)
)
```

**Step 2:** Replace the `handleAuthExec` implementation in `ESFClient.swift` to use the new pipeline check:

```swift
private func handleAuthExec(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }

    guard let messageCopy = es_copy_message(event) else {
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    let execEvent = event.pointee.event.exec
    let execPath = String(cString: execEvent.target.pointee.executable.pointee.path.data)

    // Extract argv
    let argc = es_exec_arg_count(&event.pointee.event.exec)
    var args: [String] = []
    for i in 0..<argc {
        let arg = es_exec_arg(&event.pointee.event.exec, i)
        args.append(String(cString: arg.data))
    }

    let parentPID = event.pointee.process.pointee.ppid

    xpcProxy?.checkExecPipeline(
        executable: execPath,
        args: args,
        pid: pid,
        parentPID: parentPID,
        sessionID: nil
    ) { [weak self] decision, action, rule in
        guard let client = self?.getClient() else {
            es_free_message(messageCopy)
            return
        }

        switch action {
        case "continue":
            // Allow exec in-place (common case, zero overhead)
            es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_ALLOW, false)

        case "deny":
            // Block the exec
            es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_DENY, false)

        case "redirect":
            // Deny the exec, then spawn stub
            es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_DENY, false)
            // Stub spawning is handled server-side via the Go exec pipeline

        default:
            // Unknown action, fail-open
            es_respond_auth_result(client, messageCopy, ES_AUTH_RESULT_ALLOW, false)
        }

        es_free_message(messageCopy)
    }
}
```

**Step 3:** No automated tests for Swift code (would require Xcode project setup). Manual verification:
- Build with `xcodebuild` if Xcode project exists
- If not, verify syntax correctness by code review

**Step 4:** Commit:
```bash
git add macos/Shared/XPCProtocol.swift macos/SysExt/ESFClient.swift
git commit -m "feat(esf): extend AUTH_EXEC handler for full exec pipeline routing"
```

---

## Task 3: Add es_mute_process() Recursion Guard

Add `es_mute_process()` calls to prevent re-interception of agentsh-spawned processes.

**Files:**
- Modify: `macos/SysExt/ESFClient.swift`

### What to Do

When the agentsh server spawns commands (via `stub.ServeStubConnection`), those child processes must NOT be re-intercepted by the ES client. The ES framework provides `es_mute_process()` for this — muted processes and all descendants are invisible.

**Step 1:** Add a mute method to `ESFClient`:

```swift
/// Mute a process and all its descendants so ES events are not delivered for them.
/// Used for recursion prevention — agentsh-spawned commands must not be re-intercepted.
func muteProcess(auditToken: audit_token_t) {
    guard let client = getClient() else { return }
    let result = es_mute_process(client, &auditToken, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
    if result != ES_RETURN_SUCCESS {
        NSLog("Failed to mute process: \(result.rawValue)")
    }
}

/// Mute a process by PID. Looks up the audit_token via the ES message cache.
/// This is called from the Go side via XPC when the server spawns a command.
func muteProcessByPID(_ pid: pid_t) {
    // es_mute_process requires an audit_token_t, not a PID.
    // We track audit tokens from NOTIFY_FORK events.
    guard let token = auditTokenCache[pid] else {
        NSLog("Cannot mute PID \(pid): no cached audit token")
        return
    }
    muteProcess(auditToken: token)
}
```

**Step 2:** Add an audit token cache to `ESFClient`:

```swift
/// Cache of PID -> audit_token_t for muting
private var auditTokenCache: [pid_t: audit_token_t] = [:]
private let cacheQueue = DispatchQueue(label: "com.agentsh.audittokencache")
```

**Step 3:** Update `handleNotifyFork` to cache the child's audit token:

```swift
private func handleNotifyFork(_ message: es_message_t, pid: pid_t) {
    let childToken = message.event.fork.child.pointee.audit_token
    let childPid = audit_token_to_pid(childToken)

    // Cache audit token for muting
    cacheQueue.sync {
        auditTokenCache[childPid] = childToken
    }

    ProcessHierarchy.shared.recordFork(parentPID: pid, childPID: childPid)
    NSLog("Fork: \(pid) -> \(childPid)")
}
```

**Step 4:** Update `handleNotifyExit` to clean up the cache:

```swift
private func handleNotifyExit(_ message: es_message_t, pid: pid_t) {
    cacheQueue.sync {
        auditTokenCache.removeValue(forKey: pid)
    }
    ProcessHierarchy.shared.recordExit(pid: pid)
    ProcessIdentifier.invalidate(pid: pid)
    NSLog("Exit: \(pid)")
}
```

**Step 5:** Add XPC method for muting (in `XPCProtocol.swift`):

```swift
/// Mute a process to prevent ES event delivery (recursion guard).
func muteProcess(pid: pid_t, reply: @escaping (Bool) -> Void)
```

**Step 6:** Commit:
```bash
git add macos/SysExt/ESFClient.swift macos/Shared/XPCProtocol.swift
git commit -m "feat(esf): add es_mute_process recursion guard with audit token cache"
```

---

## Task 4: Add wrap_darwin.go for macOS Wrap Support

Create the macOS-specific `platformSetupWrap` implementation and update build tags.

**Files:**
- Create: `internal/cli/wrap_darwin.go`
- Modify: `internal/cli/wrap_other.go` (build tag change)
- Test: `internal/cli/wrap_test.go`

### What to Do

On macOS with ES tier, `agentsh wrap` needs to:
1. Tell the server to register this session for ES interception
2. Pass the agent PID as the taint root
3. The ESF client (System Extension) handles interception independently

Unlike Linux where seccomp is set up per-process, macOS ES is system-wide — the System Extension is already running. The wrap command just needs to register the session.

**Step 1:** Change build tag in `wrap_other.go` from `!linux` to `!linux && !darwin`:

```go
//go:build !linux && !darwin
```

**Step 2:** Create `wrap_darwin.go`:

```go
//go:build darwin

package cli

import (
    "context"
    "fmt"
    "os"
    "syscall"

    "github.com/agentsh/agentsh/pkg/types"
)

// platformSetupWrap on macOS sets up ES-based interception.
// Unlike Linux (seccomp per-process), macOS ES is system-wide via the System Extension.
// The wrap command registers the session with the server, which configures the ESF client
// to intercept execs from this session's process tree.
func platformSetupWrap(ctx context.Context, wrapResp types.WrapInitResponse, sessID string, agentPath string, agentArgs []string, cfg *clientConfig) (*wrapLaunchConfig, error) {
    if wrapResp.WrapperBinary == "" {
        // No wrapper needed on macOS — ES interception is handled by System Extension.
        // The agent runs directly, and the ESF client intercepts its execs.
        env := os.Environ()
        env = append(env,
            fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
            fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
        )

        return &wrapLaunchConfig{
            command: agentPath,
            args:    agentArgs,
            env:     env,
            sysProcAttr: &syscall.SysProcAttr{
                Setpgid: true,
            },
        }, nil
    }

    // If the server returns a wrapper binary (e.g., agentsh-macwrap for sandboxing),
    // use it as the launch command.
    env := os.Environ()
    env = append(env,
        fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessID),
        fmt.Sprintf("AGENTSH_SERVER=%s", cfg.serverAddr),
    )
    for k, v := range wrapResp.WrapperEnv {
        env = append(env, fmt.Sprintf("%s=%s", k, v))
    }

    wrapperArgs := append([]string{"--", agentPath}, agentArgs...)

    return &wrapLaunchConfig{
        command: wrapResp.WrapperBinary,
        args:    wrapperArgs,
        env:     env,
        sysProcAttr: &syscall.SysProcAttr{
            Setpgid: true,
        },
    }, nil
}
```

**Step 3:** Update the `runWrap` function in `wrap.go` to also try macOS setup:

The current code in `wrap.go` only tries setup on Linux:
```go
if runtime.GOOS == "linux" {
    wrapCfg, err = setupWrapInterception(...)
```

Change to:
```go
if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
    wrapCfg, err = setupWrapInterception(...)
```

**Step 4:** Update the success log message in `wrap.go` to be platform-appropriate:
```go
if runtime.GOOS == "linux" {
    fmt.Fprintf(os.Stderr, "agentsh: agent %s started with seccomp interception (pid: %d)\n", ...)
} else if runtime.GOOS == "darwin" {
    fmt.Fprintf(os.Stderr, "agentsh: agent %s started with ES interception (pid: %d)\n", ...)
}
```

**Step 5:** Run tests:
```bash
go test ./internal/cli/ -v -count=1
```

**Step 6:** Cross-compile to verify:
```bash
GOOS=darwin go build ./...
GOOS=linux go build ./...
GOOS=windows go build ./...
```

**Step 7:** Commit:
```bash
git add internal/cli/wrap_darwin.go internal/cli/wrap_other.go internal/cli/wrap.go
git commit -m "feat(wrap): add macOS darwin platformSetupWrap for ES interception"
```

---

## Task 5: Add Server-Side Exec Pipeline for macOS ES

Add server-side handling for exec pipeline routing from the ESF client, including stub spawning for redirect/approve decisions.

**Files:**
- Create: `internal/platform/darwin/es_exec.go`
- Test: `internal/platform/darwin/es_exec_test.go`

### What to Do

When the ESF client sends an `exec_check` request via XPC, the Go server needs to:
1. Evaluate the command against policy
2. For allow/audit: return `action: "continue"` (ES allows in-place)
3. For deny: return `action: "deny"` (ES denies with EPERM)
4. For redirect/approve: return `action: "redirect"`, then spawn `agentsh-stub` server-side and run the original command through the full pipeline

**Step 1:** Create `es_exec.go` implementing the `ExecHandler` interface:

```go
//go:build darwin

package darwin

import (
    "context"
    "log/slog"
    "net"
    "os"

    "github.com/agentsh/agentsh/internal/platform/darwin/xpc"
    "github.com/agentsh/agentsh/internal/stub"
)

// ESExecHandler handles exec pipeline checks from the ESF client.
type ESExecHandler struct {
    policyChecker ExecPolicyChecker
    stubBinary    string // Path to agentsh-stub
}

// ExecPolicyChecker interface for policy evaluation.
type ExecPolicyChecker interface {
    CheckCommand(cmd string, args []string) ExecPolicyResult
}

// ExecPolicyResult represents a policy check result.
type ExecPolicyResult struct {
    Decision          string // allow, deny, approve, audit, redirect
    EffectiveDecision string // What actually happens (respects shadow mode)
    Rule              string
    Message           string
}

// NewESExecHandler creates a new ES exec handler.
func NewESExecHandler(checker ExecPolicyChecker, stubBinary string) *ESExecHandler {
    return &ESExecHandler{
        policyChecker: checker,
        stubBinary:    stubBinary,
    }
}

// CheckExec evaluates an exec request and returns the pipeline decision.
func (h *ESExecHandler) CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string) xpc.ExecCheckResult {
    if h.policyChecker == nil {
        return xpc.ExecCheckResult{
            Decision: "allow",
            Action:   "continue",
            Rule:     "no_policy",
        }
    }

    result := h.policyChecker.CheckCommand(executable, args)

    effectiveDecision := result.EffectiveDecision
    if effectiveDecision == "" {
        effectiveDecision = result.Decision
    }

    switch effectiveDecision {
    case "allow", "audit":
        return xpc.ExecCheckResult{
            Decision: result.Decision,
            Action:   "continue",
            Rule:     result.Rule,
            Message:  result.Message,
        }

    case "deny":
        return xpc.ExecCheckResult{
            Decision: result.Decision,
            Action:   "deny",
            Rule:     result.Rule,
            Message:  result.Message,
        }

    case "approve", "redirect":
        // For redirect/approve: deny the original exec, spawn stub server-side
        go h.spawnStubServer(executable, args, pid, parentPID, sessionID)
        return xpc.ExecCheckResult{
            Decision: result.Decision,
            Action:   "redirect",
            Rule:     result.Rule,
            Message:  result.Message,
        }

    default:
        // Unknown decision — fail-secure
        return xpc.ExecCheckResult{
            Decision: result.Decision,
            Action:   "deny",
            Rule:     "unknown",
            Message:  "unknown effective decision",
        }
    }
}

// spawnStubServer spawns the original command via the stub protocol.
// On macOS, we can't rewrite the exec target, so we deny the original exec
// and run the command server-side, with I/O proxied through the stub.
func (h *ESExecHandler) spawnStubServer(executable string, args []string, pid int32, parentPID int32, sessionID string) {
    // Create a Unix socket pair for stub <-> server communication
    srvConn, stubConn, err := createUnixSocketPair()
    if err != nil {
        slog.Error("es_exec: failed to create socket pair", "error", err, "pid", pid)
        return
    }

    // Start serving the stub connection with the original command
    go func() {
        defer srvConn.Close()
        sErr := stub.ServeStubConnection(context.Background(), srvConn, stub.ServeConfig{
            Command: executable,
            Args:    args,
        })
        if sErr != nil {
            slog.Error("es_exec: stub serve error", "pid", pid, "cmd", executable, "error", sErr)
        }
    }()

    // The stubConn needs to be passed to the stub binary.
    // On macOS, we spawn the stub as a new child process.
    go h.launchStub(stubConn, executable, pid)
}

// launchStub spawns agentsh-stub with the socket fd.
func (h *ESExecHandler) launchStub(conn net.Conn, originalCmd string, originalPID int32) {
    defer conn.Close()

    // Extract raw fd from connection
    file, err := connToFile(conn)
    if err != nil {
        slog.Error("es_exec: failed to get fd from conn", "error", err)
        return
    }
    defer file.Close()

    // Spawn agentsh-stub with the socket as fd 3
    // TODO: Use posix_spawn with the original process's context for proper parent relationship
    cmd := exec.CommandContext(context.Background(), h.stubBinary)
    cmd.Env = append(os.Environ(),
        "AGENTSH_STUB_FD=3",
    )
    cmd.ExtraFiles = []*os.File{file}

    if err := cmd.Start(); err != nil {
        slog.Error("es_exec: failed to start stub", "error", err, "stub", h.stubBinary)
        return
    }

    // TODO: Request es_mute_process for the stub via XPC
    // This prevents the ESF client from re-intercepting the stub's exec

    if err := cmd.Wait(); err != nil {
        slog.Debug("es_exec: stub exited", "error", err, "pid", originalPID)
    }
}

// createUnixSocketPair creates a pair of connected Unix domain sockets.
func createUnixSocketPair() (net.Conn, net.Conn, error) {
    // Use net.Pipe for in-process socket pair
    return net.Pipe(), nil  // PLACEHOLDER — see actual implementation below
}
```

Note: The `createUnixSocketPair` and `connToFile` helpers need proper implementation using `unix.Socketpair` (similar to the Linux `createStubSocketPair` in `redirect_linux.go`). Follow the same pattern.

**Step 2:** Write tests in `es_exec_test.go`:
- Test allow decision returns action=continue
- Test deny decision returns action=deny
- Test approve decision returns action=redirect
- Test nil policy checker returns allow

**Step 3:** Run tests:
```bash
go test ./internal/platform/darwin/ -v -count=1 -run TestESExec
```

**Step 4:** Commit:
```bash
git add internal/platform/darwin/es_exec.go internal/platform/darwin/es_exec_test.go
git commit -m "feat(darwin): add ES exec pipeline handler with stub spawning"
```

---

## Task 6: Wire XPC Server to ES Exec Handler

Connect the XPC server's `exec_check` request type to the new `ESExecHandler`.

**Files:**
- Modify: `internal/platform/darwin/xpc/server.go`
- Modify: `internal/platform/darwin/platform.go` (or wherever platform init happens)
- Test: `internal/platform/darwin/xpc/server_test.go`

### What to Do

**Step 1:** Add `SetExecHandler` method to `Server` in `server.go`:

```go
func (s *Server) SetExecHandler(h ExecHandler) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.execHandler = h
}
```

Add the field to `Server`:
```go
execHandler ExecHandler
```

**Step 2:** Add the request handler in `handleRequest`:

```go
case RequestTypeExecCheck:
    return s.handleExecCheck(req)
```

With:
```go
func (s *Server) handleExecCheck(req *PolicyRequest) PolicyResponse {
    s.mu.Lock()
    h := s.execHandler
    s.mu.Unlock()

    if h == nil {
        // No exec handler — fall back to simple allow/deny via policy handler
        allow, rule := s.handler.CheckCommand(req.Path, req.Args)
        action := "continue"
        if !allow {
            action = "deny"
        }
        return PolicyResponse{Allow: allow, Rule: rule, Action: action}
    }

    result := h.CheckExec(req.Path, req.Args, req.PID, req.ParentPID, req.SessionID)
    return PolicyResponse{
        Allow:        result.Action == "continue",
        Rule:         result.Rule,
        Action:       result.Action,
        ExecDecision: result.Decision,
        Message:      result.Message,
    }
}
```

**Step 3:** Update the protocol to add `ParentPID` to `PolicyRequest` if not already present (it's already there as `parent_pid`).

**Step 4:** Write integration test:
```go
func TestExecCheckHandler(t *testing.T) {
    // Create mock exec handler
    // Send exec_check request
    // Verify response contains correct action and decision
}
```

**Step 5:** Run tests:
```bash
go test ./internal/platform/darwin/xpc/ -v -count=1
```

**Step 6:** Commit:
```bash
git add internal/platform/darwin/xpc/server.go internal/platform/darwin/xpc/server_test.go
git commit -m "feat(xpc): wire exec_check requests to ES exec handler"
```

---

## Task 7: Add XPC Bridge for exec_check in Swift PolicyBridge

Update the Swift XPC bridge (`PolicyBridge.swift`) to handle the new `checkExecPipeline` method by sending `exec_check` JSON requests to the Go Unix socket server.

**Files:**
- Modify: `macos/XPCService/PolicyBridge.swift`

### What to Do

The `PolicyBridge.swift` bridges Swift XPC calls to the Go Unix socket. It already handles `checkCommand` by sending `{"type":"command",...}`. We need to add handling for the new `checkExecPipeline` method.

**Step 1:** Add `checkExecPipeline` implementation:

```swift
func checkExecPipeline(
    executable: String,
    args: [String],
    pid: pid_t,
    parentPID: pid_t,
    sessionID: String?,
    reply: @escaping (String, String, String?) -> Void
) {
    let request: [String: Any] = [
        "type": "exec_check",
        "path": executable,
        "args": args,
        "pid": pid,
        "parent_pid": parentPID,
        "session_id": sessionID ?? ""
    ]

    sendRequest(request) { response in
        let decision = response["exec_decision"] as? String ?? "allow"
        let action = response["action"] as? String ?? "continue"
        let rule = response["rule"] as? String
        reply(decision, action, rule)
    }
}
```

**Step 2:** Add `muteProcess` implementation that sends a mute request to the ESF client:

```swift
func muteProcess(pid: pid_t, reply: @escaping (Bool) -> Void) {
    // This is called from Go when the server spawns a command.
    // Forward to the ESFClient via local notification or shared state.
    NotificationCenter.default.post(
        name: .muteProcessRequest,
        object: nil,
        userInfo: ["pid": pid]
    )
    reply(true)
}
```

**Step 3:** Commit:
```bash
git add macos/XPCService/PolicyBridge.swift
git commit -m "feat(xpc-bridge): add checkExecPipeline and muteProcess support"
```

---

## Task 8: Integration Tests for Exec Pipeline

Write Go integration tests that exercise the full exec pipeline path through the XPC server.

**Files:**
- Create: `internal/platform/darwin/es_exec_test.go` (extend from Task 5)
- Modify: `internal/platform/darwin/xpc/integration_test.go`

### What to Do

**Step 1:** Write mock-based integration tests:

```go
func TestExecPipeline_AllowContinue(t *testing.T) {
    // Create XPC server with mock exec handler that returns allow
    // Send exec_check request
    // Verify response: action=continue, allow=true
}

func TestExecPipeline_DenyBlock(t *testing.T) {
    // Create XPC server with mock exec handler that returns deny
    // Send exec_check request
    // Verify response: action=deny, allow=false
}

func TestExecPipeline_RedirectSpawnStub(t *testing.T) {
    // Create XPC server with mock exec handler that returns redirect
    // Send exec_check request
    // Verify response: action=redirect, allow=false
    // Verify stub server was started (via mock/channel)
}
```

**Step 2:** Test the ESExecHandler policy mapping:

```go
func TestESExecHandler_PolicyMapping(t *testing.T) {
    tests := []struct {
        name       string
        decision   string
        wantAction string
    }{
        {"allow", "allow", "continue"},
        {"audit", "audit", "continue"},
        {"deny", "deny", "deny"},
        {"approve", "approve", "redirect"},
        {"redirect", "redirect", "redirect"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            handler := NewESExecHandler(&mockPolicyChecker{decision: tt.decision}, "")
            result := handler.CheckExec("/usr/bin/test", nil, 1234, 1233, "sess-1")
            assert.Equal(t, tt.wantAction, result.Action)
        })
    }
}
```

**Step 3:** Run all darwin tests:
```bash
go test ./internal/platform/darwin/... -v -count=1
```

**Step 4:** Commit:
```bash
git add internal/platform/darwin/
git commit -m "test(darwin): add integration tests for ES exec pipeline"
```

---

## Task 9: Cross-Platform Build Verification and CI

Verify the changes build correctly on all platforms and update CI configuration.

**Files:**
- Modify: `internal/cli/wrap_other.go` (already done in Task 4, verify)
- Verify: all new files have correct build tags

### What to Do

**Step 1:** Verify cross-compilation:

```bash
# Build for all platforms
go build ./...
GOOS=darwin go build ./...
GOOS=linux go build ./...
GOOS=windows go build ./...
```

**Step 2:** Verify build tags are correct:
- `wrap_darwin.go`: `//go:build darwin`
- `wrap_linux.go`: `//go:build linux`
- `wrap_other.go`: `//go:build !linux && !darwin`
- `es_exec.go`: `//go:build darwin`

**Step 3:** Run full test suite:
```bash
go test ./... -count=1
```

**Step 4:** Commit any fixes:
```bash
git add -A
git commit -m "fix: ensure cross-platform build correctness for macOS ES support"
```

---

## Task 10: Session Scoping for ES Events

Add session-based filtering so the ESF client only intercepts execs from the wrapped agent's process tree, not all processes on the system.

**Files:**
- Modify: `macos/SysExt/ESFClient.swift`
- Modify: `macos/SysExt/ProcessHierarchy.swift`
- Modify: `internal/platform/darwin/xpc/protocol.go`
- Modify: `internal/platform/darwin/xpc/server.go`

### What to Do

The ESF client currently receives AUTH_EXEC for ALL processes. We need to filter to only the wrapped agent's process tree.

**Step 1:** Add a `SessionRegistry` to track active wrap sessions and their root PIDs:

In `ESFClient.swift`:
```swift
/// Active wrap sessions: maps session root PID to session ID
private var activeSessions: [pid_t: String] = [:]
private let sessionQueue = DispatchQueue(label: "com.agentsh.sessions")

/// Register a wrap session — called when agentsh wrap starts
func registerSession(rootPID: pid_t, sessionID: String) {
    sessionQueue.sync {
        activeSessions[rootPID] = sessionID
    }
}

/// Unregister a wrap session — called when the agent exits
func unregisterSession(rootPID: pid_t) {
    sessionQueue.sync {
        activeSessions.removeValue(forKey: rootPID)
    }
}
```

**Step 2:** Update `handleAuthExec` to check if the process is in an active session tree:

```swift
private func handleAuthExec(_ event: UnsafePointer<es_message_t>, pid: pid_t) {
    guard let client = getClient() else { return }

    // Fast path: check if this process is in any active session tree
    let sessionInfo = findSession(forPID: pid)
    if sessionInfo == nil {
        // Not in any active session — allow immediately
        es_respond_auth_result(client, event, ES_AUTH_RESULT_ALLOW, false)
        return
    }

    // ... proceed with pipeline check using sessionInfo.sessionID
}

private func findSession(forPID pid: pid_t) -> (rootPID: pid_t, sessionID: String)? {
    return sessionQueue.sync {
        // Check if pid is directly a session root
        if let sid = activeSessions[pid] {
            return (pid, sid)
        }
        // Walk ancestors to find session root
        let ancestors = ProcessHierarchy.shared.getAncestors(pid: pid)
        for ancestor in ancestors {
            if let sid = activeSessions[ancestor] {
                return (ancestor, sid)
            }
        }
        return nil
    }
}
```

**Step 3:** Add XPC request type for session registration:

In `protocol.go`:
```go
RequestTypeRegisterSession   RequestType = "register_session"
RequestTypeUnregisterSession RequestType = "unregister_session"
```

In `server.go`, handle these in `handleRequest`:
```go
case RequestTypeRegisterSession:
    // Forward to ESF client via the session registry
    return PolicyResponse{Allow: true, Success: true}
case RequestTypeUnregisterSession:
    return PolicyResponse{Allow: true, Success: true}
```

**Step 4:** Wire session registration into `wrap_darwin.go` `postStart` callback.

**Step 5:** Run tests:
```bash
go test ./internal/platform/darwin/... -v -count=1
```

**Step 6:** Commit:
```bash
git add macos/SysExt/ESFClient.swift macos/SysExt/ProcessHierarchy.swift internal/platform/darwin/xpc/
git commit -m "feat(esf): add session scoping to filter AUTH_EXEC to agent process tree"
```

---

## Summary

| Task | Component | Priority |
|------|-----------|----------|
| 1 | Extend XPC protocol for exec pipeline | HIGH — foundation |
| 2 | Extend Swift ESFClient and XPC protocol | HIGH — foundation |
| 3 | Add es_mute_process recursion guard | HIGH — safety |
| 4 | Add wrap_darwin.go | HIGH — user-facing |
| 5 | Add server-side exec pipeline handler | HIGH — core logic |
| 6 | Wire XPC server to exec handler | HIGH — integration |
| 7 | Add Swift PolicyBridge exec support | HIGH — integration |
| 8 | Integration tests | MEDIUM — quality |
| 9 | Cross-platform build verification | HIGH — correctness |
| 10 | Session scoping for ES events | HIGH — correctness |

**Dependencies:**
- Task 1 → Tasks 2, 5, 6 (protocol must exist first)
- Task 3 is independent (Swift-only)
- Task 4 is independent (Go-only)
- Task 5 depends on Task 1
- Task 6 depends on Tasks 1, 5
- Task 7 depends on Tasks 1, 2
- Task 8 depends on Tasks 5, 6
- Task 9 depends on all
- Task 10 depends on Tasks 2, 4
