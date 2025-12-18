# Shell Shim + Interactive PTY Exec Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace `/bin/sh` and `/bin/bash` with a tiny shim that routes all shell execution through `agentsh`, including full interactive PTY support over both gRPC and HTTP.

**Architecture:** Add a generic shim (`agentsh-shell-shim`) installed at `/bin/sh` and `/bin/bash` that delegates to `agentsh exec` (Option A). Enhance `agentsh` to support `--argv0` and `--pty` with a shared PTY engine. Provide PTY streaming via a new generated-proto gRPC service and an HTTP WebSocket endpoint per session.

**Tech Stack:** Go, chi (HTTP routing), gRPC, WebSocket, PTY via `golang.org/x/sys/unix`, terminal raw mode via `golang.org/x/term` (or direct termios if preferred).

---

## Task 1: Add `argv0` to exec request types

**Files:**
- Modify: `pkg/types/exec.go:1`
- Test: `internal/api/exec_argv0_test.go` (new)

**Step 1: Write the failing test**
- Create `internal/api/exec_argv0_test.go` with a unit test for a new helper that builds `*exec.Cmd` from an exec request:
  - Expected: when `Argv0` is set, the spawned `cmd.Args[0]` equals `Argv0`.

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/api -run TestBuildExecCmd_Argv0 -v`
- Expected: FAIL (helper doesn’t exist / request lacks field).

**Step 3: Write minimal implementation**
- Add `Argv0 string \`json:"argv0,omitempty"\`` to `pkg/types/exec.go`.
- In server execution path, introduce a helper (e.g. `buildExecCmd(...)`) that sets `cmd.Args[0]` when `req.Argv0` is non-empty.

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/api -run TestBuildExecCmd_Argv0 -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add pkg/types/exec.go internal/api/exec_argv0_test.go`
- Run: `git commit -m "feat: support argv0 for exec"`

---

## Task 2: Inject recursion-guard env (`AGENTSH_IN_SESSION`)

**Files:**
- Modify: `internal/api/exec.go:223` (mergeEnv)
- Test: `internal/api/exec_env_test.go` (new)

**Step 1: Write the failing test**
- Create `internal/api/exec_env_test.go` to test `mergeEnv(...)` behavior:
  - Expected: output env includes `AGENTSH_IN_SESSION=1`
  - Optional: also include `AGENTSH_SESSION_ID=<id>` if the call site has session context (if not, skip).

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/api -run TestMergeEnv_InSession -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- In `internal/api/exec.go` `mergeEnv(...)` (around `internal/api/exec.go:223`), set:
  - `envMap["AGENTSH_IN_SESSION"] = "1"`
- If you also want to inject session id, thread it through (either via `overrides` or by changing `mergeEnv` signature).

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/api -run TestMergeEnv_InSession -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add internal/api/exec.go internal/api/exec_env_test.go`
- Run: `git commit -m "feat: mark processes as running inside agentsh"`

---

## Task 3: Add `--argv0` flag to `agentsh exec`

**Files:**
- Modify: `internal/cli/exec.go:21`
- Modify: `internal/cli/exec_parse.go:1`
- Test: `internal/cli/exec_parse_test.go` (extend)

**Step 1: Write the failing test**
- Extend `internal/cli/exec_parse_test.go` with a test that parses a new `--argv0` flag (or parsed input) into `types.ExecRequest.Argv0`.

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/cli -run TestParseExecInput_Argv0 -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- Add `--argv0` flag in `internal/cli/exec.go` near existing flags (`internal/cli/exec.go:129`).
- Update parse path to populate `req.Argv0`.

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/cli -run TestParseExecInput_Argv0 -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add internal/cli/exec.go internal/cli/exec_parse.go internal/cli/exec_parse_test.go`
- Run: `git commit -m "feat: add --argv0 to agentsh exec"`

---

## Task 4: Add generated-proto gRPC PTY service

**Files:**
- Create: `proto/agentsh/v1/pty.proto`
- Create: `pkg/ptygrpc/*` (generated output directory; choose a stable location)
- Modify: `internal/api/grpc.go:41` (register the new service in addition to the existing Struct-based service)
- Create: `internal/api/pty_grpc.go`

**Step 1: Write the failing test**
- Add a small compile-level test or a server registration test:
  - Start a gRPC server and assert the PTY service is registered (or call it and get “unimplemented” before implementation).

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/api -run TestGRPC_PTYRegistered -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- Define `pty.proto` with:
  - Service `AgentshPTY` (package `agentsh.v1`) with `rpc ExecPTY(stream ExecPTYClientMsg) returns (stream ExecPTYServerMsg);`
  - Messages: `Start`, `Stdin`, `Resize`, `Signal`, `Output`, `Exit`, `Error` using `bytes` for data.
- Add protobuf generation workflow:
  - Document required tools (`protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`)
  - Add a `Makefile` target (e.g. `make proto`) to generate code into `pkg/ptygrpc`.
- Implement an `ExecPTY` stub in `internal/api/pty_grpc.go` returning `Unimplemented` until PTY engine exists.
- Register the generated service in `internal/api/grpc.go` (alongside existing manual registration).

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/api -run TestGRPC_PTYRegistered -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add proto pkg internal/api Makefile`
- Run: `git commit -m "feat: add gRPC PTY service scaffolding"`

---

## Task 5: Implement shared PTY engine (server-side)

**Files:**
- Create: `internal/pty/engine.go`
- Create: `internal/pty/engine_test.go`
- Modify: `internal/api/pty_grpc.go` (wire to engine)

**Step 1: Write the failing test**
- `internal/pty/engine_test.go`: spawn a short-lived PTY command (e.g. `sh -lc 'printf hi'`) via the engine and assert output contains `hi` and exit code is 0.

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/pty -run TestEngine_RunPTY -v`
- Expected: FAIL (engine missing).

**Step 3: Write minimal implementation**
- Implement:
  - PTY allocation (`openpty`)
  - Child spawn with controlling TTY, process group, and env merge
  - Goroutines to pump PTY master ↔ client streams
  - Resize handler (`TIOCSWINSZ`)
  - Signal forwarding to process group
  - Clean shutdown on client disconnect

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/pty -run TestEngine_RunPTY -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add internal/pty internal/api/pty_grpc.go`
- Run: `git commit -m "feat: implement PTY engine"`

---

## Task 6: Add HTTP WebSocket PTY endpoint per session

**Files:**
- Modify: `internal/api/app.go:64` (add route `/sessions/{id}/pty`)
- Create: `internal/api/pty_ws.go`
- Test: `internal/api/pty_ws_test.go` (new)

**Step 1: Write the failing test**
- Use `httptest` to call `/api/v1/sessions/{id}/pty` without WS upgrade and assert it returns a clear error (or 400).
- Optional: with a WS client library, test a basic start+exit flow.

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/api -run TestPTYWebSocket -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- Add `r.Get("/sessions/{id}/pty", a.execInSessionPTYWS)` near `internal/api/app.go:71`.
- Implement WS handler:
  - Auth already handled by middleware; preserve API key behavior.
  - First message must be JSON “start” (command, args, argv0, env, working_dir).
  - Subsequent binary frames become stdin bytes; text frames handle resize/signal.
  - Stream PTY output as binary frames; send final `exit` JSON and close.
- Wire handler to shared PTY engine.

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/api -run TestPTYWebSocket -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add internal/api/app.go internal/api/pty_ws.go internal/api/pty_ws_test.go`
- Run: `git commit -m "feat: add HTTP WebSocket PTY endpoint"`

---

## Task 7: Add `agentsh exec --pty` CLI path

**Files:**
- Modify: `internal/cli/exec.go:21`
- Create: `internal/cli/exec_pty.go`
- Test: `internal/cli/exec_pty_test.go`

**Step 1: Write the failing test**
- Unit test that `--pty` chooses the PTY transport and that terminal raw-mode hooks are invoked only when stdin/stdout are TTY.

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/cli -run TestExecPTYFlag -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- Add `--pty` flag to `agentsh exec`.
- When `--pty` is set:
  - If transport is `grpc`, use the generated PTY service.
  - If transport is `http`, connect to the WebSocket endpoint.
- Set terminal raw mode, handle SIGWINCH resize events, forward SIGINT/SIGTERM.

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/cli -run TestExecPTYFlag -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add internal/cli`
- Run: `git commit -m "feat: add agentsh exec --pty"`

---

## Task 8: Add the shell shim binary

**Files:**
- Create: `cmd/agentsh-shell-shim/main.go`
- Create: `internal/shim/*` (session id resolution helpers + tests)
- Test: `internal/shim/session_id_test.go`

**Step 1: Write the failing test**
- Unit tests for session id resolution priority order:
  - env `AGENTSH_SESSION_ID`
  - env `AGENTSH_SESSION_FILE`
  - file-backed fallback (creates + reuses)

**Step 2: Run test to verify it fails**
- Run: `go test ./internal/shim -run TestResolveSessionID -v`
- Expected: FAIL.

**Step 3: Write minimal implementation**
- Implement:
  - `AGENTSH_BIN` resolution (`exec.LookPath`)
  - `.real` target selection based on invocation basename
  - recursion guard via `AGENTSH_IN_SESSION=1`
  - TTY detection and command construction:
    - `agentsh exec [--pty] --argv0 <os.Args[0]> <sid> -- <realShell> <args...>`
  - session id resolution algorithm with `flock` and stable file placement (`/run/agentsh`, `/tmp/agentsh`, `.agentsh`).

**Step 4: Run test to verify it passes**
- Run: `go test ./internal/shim -run TestResolveSessionID -v`
- Expected: PASS.

**Step 5: Commit**
- Run: `git add cmd/agentsh-shell-shim internal/shim`
- Run: `git commit -m "feat: add /bin/sh and /bin/bash shim binary"`

---

## Task 9: Dockerfile / packaging changes

**Files:**
- Modify: `Dockerfile:1`
- Modify: `Makefile:1`
- Modify: `README.md:1` (document the feature + env vars)

**Steps:**
1) Build shim as a separate output (e.g. `./bin/agentsh-shell-shim`).
2) In container image, move `/bin/sh` and `/bin/bash` to `.real` and install shim at both paths.
3) Document:
   - `AGENTSH_BIN`
   - `AGENTSH_SESSION_ID`, `AGENTSH_SESSION_FILE`
   - `AGENTSH_IN_SESSION` (reserved/internal)
   - PTY endpoints and `agentsh exec --pty`
4) Add a minimal smoke test section.

**Commit**
- Run: `git add Dockerfile Makefile README.md`
- Run: `git commit -m "docs: package sh/bash shim and PTY exec"`

---

## Task 10: End-to-end smoke test (manual)

**Steps (local):**
1) Build: `make build` (and `make proto` if applicable)
2) Start server: `./bin/agentsh server --config config.yml`
3) Create session: `./bin/agentsh session create --workspace .`
4) Non-interactive: `./bin/agentsh exec <sid> -- sh -lc 'echo hi'`
5) Interactive: `./bin/agentsh exec --pty <sid> -- sh`
6) In a container image using the shim:
   - `docker run -it ... /bin/sh` should route through agentsh and remain interactive.

