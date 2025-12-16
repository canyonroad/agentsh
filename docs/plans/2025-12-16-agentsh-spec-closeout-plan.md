# agentsh Spec Closeout Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the remaining gaps between the current codebase and `docs/spec.md` + `docs/plans/2025-12-16-agentsh-implementation-plan.md`, while keeping changes Linux-first and test-verified.

**Architecture:** Reuse the existing REST router + session manager + policy engine. Add transport support (TLS + Unix socket), round out CLI UX (attach, exec `--json/--stream`, policy/config trees), then incrementally add cgroups v2 enforcement and (optionally) gRPC.

**Tech Stack:** Go, Chi, Cobra, SQLite, YAML, (optional) cgroups v2, (optional) gRPC/protobuf.

---

## Phase 0 — Make verification reliable

### Task 0.1: Stop `go test ./...` from choking on local FUSE leftovers

**Why:** In this repo it’s easy to end up with a broken mount under `data/sessions/.../workspace-mnt` which makes `go test ./...` fail during package discovery.

**Action (local dev hygiene):**
- If you hit `transport endpoint is not connected`, clean your local `data/sessions` tree (and unmount if necessary).

**Verify (example):**
- Run: `env GOCACHE=$PWD/.gocache GOMODCACHE=$PWD/.gomodcache go test ./cmd/... ./internal/... ./pkg/...`
- Expected: `ok` for packages with tests, and `[no test files]` for others.

---

## Phase 1 — Bring config + server transports up to spec

### Task 1.1: Add config structs for TLS + unix socket + HTTP timeouts + request size

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (create if missing)

**Step 1: Write failing test**
- Add a `Load()` test that parses a YAML snippet including:
  - `server.http.read_timeout`, `server.http.write_timeout`, `server.http.max_request_size`
  - `server.unix_socket.enabled/path/permissions`
  - `server.tls.enabled/cert_file/key_file`
- Assert these fields are populated in the returned `config.Config`.

**Step 2: Run test to verify it fails**
- Run: `env GOCACHE=$PWD/.gocache GOMODCACHE=$PWD/.gomodcache go test ./internal/config -run TestLoad_ParsesServerTransportFields`
- Expected: FAIL (fields missing / zero values).

**Step 3: Implement minimal config structs**
- Extend config types:
  - `ServerHTTPConfig` → add `ReadTimeout`, `WriteTimeout`, `MaxRequestSize`
  - Add `ServerUnixSocketConfig` under `ServerConfig`
  - Add `ServerTLSConfig` under `ServerConfig` (or under `ServerHTTPConfig`, but keep it consistent with `config.yml`)
- Add parsing helpers:
  - duration parsing already exists elsewhere; for request size support a small parser for `10MB` / `10MiB` / `1048576`.

**Step 4: Run test to verify it passes**
- Same `go test` command; expected PASS.

### Task 1.2: Add environment variable overrides required by `docs/spec.md`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Step 1: Write failing test**
- Set env vars like `AGENTSH_HTTP_ADDR`, `AGENTSH_GRPC_ADDR` and ensure they override YAML values.

**Step 2: Verify red**
- Run: `go test ./internal/config -run TestLoad_EnvOverrides`
- Expected: FAIL.

**Step 3: Implement**
- In `Load()`, after YAML unmarshal + defaults, apply overrides:
  - `AGENTSH_HTTP_ADDR` → `cfg.Server.HTTP.Addr`
  - `AGENTSH_GRPC_ADDR` → `cfg.Server.GRPC.Addr`
  - (Optional) `AGENTSH_DATA_DIR` to derive defaults for `sessions.base_dir` and `audit.storage.sqlite_path`.

**Step 4: Verify green**
- Expected PASS.

---

## Phase 2 — Server: enforce HTTP timeouts/limits + unix socket + TLS

### Task 2.1: Enforce `max_request_size` at the HTTP layer

**Files:**
- Modify: `internal/server/server.go`
- Test: `internal/server/server_test.go` (add a focused test)

**Step 1: Write failing test**
- Start server handler (can use `api.NewApp` + router like existing tests).
- Make a request with body > `max_request_size` and assert `413` (or your chosen status) with a clear error.

**Step 2: Verify red**
- Run: `go test ./internal/server -run TestHTTP_MaxRequestSize`
- Expected: FAIL (currently no limit).

**Step 3: Implement**
- Wrap the router with a handler that uses `http.MaxBytesReader` for all requests.
- Make sure error response is JSON (consistent with API errors).

**Step 4: Verify green**
- Expected PASS.

### Task 2.2: Wire `read_timeout` and `write_timeout` into `http.Server`

**Files:**
- Modify: `internal/server/server.go`
- Test: (optional) `internal/server/server_test.go`

**Step 1: Implement**
- Set `ReadTimeout` and `WriteTimeout` on `http.Server` using config duration values.

**Step 2: Verify**
- At least compile/test: `go test ./internal/server -run TestServer_`

### Task 2.3: Add Unix socket listener support

**Files:**
- Modify: `internal/server/server.go`
- Add: `internal/server/unix_listener_test.go` (or extend existing test file)

**Step 1: Write failing test**
- Configure server with unix socket enabled, path under `t.TempDir()`, permissions `0660`.
- Start the server (or just start the listener + `Serve` in a goroutine).
- Create an HTTP client that dials unix socket and call `/health`, expect `200`.

**Step 2: Verify red**
- Run: `go test ./internal/server -run TestUnixSocket_Health`
- Expected: FAIL (no unix socket support).

**Step 3: Implement**
- Add unix listener creation:
  - Remove existing socket file if present.
  - `net.Listen("unix", path)`, `os.Chmod(path, perms)`
- Serve the existing handler on that listener.
- Ensure shutdown closes the unix listener and removes the socket file.

**Step 4: Verify green**
- Expected PASS.

### Task 2.4: Add TLS support for the TCP HTTP listener

**Files:**
- Modify: `internal/server/server.go`
- Test: `internal/server/tls_test.go`

**Step 1: Write failing test**
- Generate a self-signed cert/key in the test (PEM) into temp files.
- Configure TLS enabled and start server on `127.0.0.1:0`.
- Use an `http.Client` with `InsecureSkipVerify: true` to call `/health`, expect `200`.

**Step 2: Verify red**
- Run: `go test ./internal/server -run TestTLS_Health`
- Expected: FAIL.

**Step 3: Implement**
- If TLS enabled: use `ListenAndServeTLS(certFile, keyFile)` (or `ServeTLS` on an explicit listener).
- Keep non-TLS behavior unchanged.

**Step 4: Verify green**
- Expected PASS.

---

## Phase 3 — Client: add `unix://` transport support

### Task 3.1: Support `--server unix:///path/to.sock`

**Files:**
- Modify: `internal/client/client.go`
- Test: `internal/client/client_unix_test.go`

**Step 1: Write failing test**
- Start an `httptest.Server`-equivalent over a unix socket (use `net.Listen("unix", ...)` + `http.Serve`).
- Create client with baseURL `unix:///tmp/...sock`, call health (add a tiny helper method or call `doJSON` with GET `/health`).

**Step 2: Verify red**
- Run: `go test ./internal/client -run TestClient_UnixSocket`
- Expected: FAIL.

**Step 3: Implement**
- If baseURL scheme is `unix`, set a custom `http.Transport.DialContext` that dials the unix path.
- Use a dummy host in `baseURL` like `http://unix` for request URLs; the dialer routes to the socket.

**Step 4: Verify green**
- Expected PASS.

---

## Phase 4 — CLI parity (attach, exec flags, streaming)

### Task 4.1: Implement `agentsh session attach SESSION_ID`

**Files:**
- Modify: `internal/cli/session.go`
- Add: `internal/cli/attach.go`

**Step 1: Write failing test**
- Add a small test around the command wiring: ensure `session attach` exists and errors without args.

**Step 2: Verify red**
- Run: `go test ./internal/cli -run TestSessionAttach_Wired`
- Expected: FAIL.

**Step 3: Implement**
- Add Cobra subcommand `session attach`:
  - REPL loop: print prompt `agentsh:<session>:<cwd>$ ` (fetch cwd via `GET /sessions/{id}`).
  - Parse input into command + args (use a small shlex-like splitter; keep it minimal).
  - Call `Exec` and print JSON response (or pretty summaries if `--stream` is later enabled).

**Step 4: Verify green**
- Expected PASS.

### Task 4.2: Add `agentsh exec --json '...'`

**Files:**
- Modify: `internal/cli/exec.go`

**Step 1: Write failing test**
- Parse args `exec <id> --json '{"command":"pwd"}'` and ensure it sends `ExecRequest.Command == "pwd"`.

**Step 2: Verify red**
- Run: `go test ./internal/cli -run TestExec_JSONFlag`
- Expected: FAIL.

**Step 3: Implement**
- Add `--json` flag that unmarshals into `types.ExecRequest`.
- Keep existing `--timeout` behavior (timeout in JSON may be overridden or validated; pick one and document it).

**Step 4: Verify green**
- Expected PASS.

### Task 4.3: Add true streaming exec (`agentsh exec --stream`)

**Files:**
- Modify: `internal/api/app.go` (new handler)
- Add: `internal/api/exec_stream.go`
- Modify: `internal/cli/exec.go`
- Add: `internal/client/stream_exec.go` (or extend client)
- Add types: `pkg/types/exec_stream.go`

**Step 1: Write failing API test**
- Add `POST /api/v1/sessions/{id}/exec/stream` test:
  - Run a command that prints multiple lines with delays (e.g. `sh -c 'echo a; sleep 0.1; echo b'`).
  - Assert the response is `text/event-stream` and includes at least two `stdout` chunk events in order.

**Step 2: Verify red**
- Run: `go test ./internal/api -run TestExecStream_StreamsStdout`
- Expected: FAIL (endpoint missing).

**Step 3: Implement minimal streaming**
- Server:
  - Execute command with `StdoutPipe/StderrPipe`.
  - Read pipes line-by-line or chunk-by-chunk.
  - Emit SSE frames:
    - `event: stdout` / `data: <chunk>`
    - `event: stderr` / `data: <chunk>`
    - `event: done` / `data: {"exit_code":..., "command_id":...}`
  - Still save full output to the store for `output` pagination.
- Client/CLI:
  - When `--stream` is set, call the streaming endpoint and print:
    - `[stdout] ...`
    - `[stderr] ...`
    - (Optionally) interleave policy/file/net events if you also tail session SSE in parallel.

**Step 4: Verify green**
- API test passes.
- CLI unit test ensures flag wiring.

---

## Phase 5 — Add `policy` and `config` CLI trees

### Task 5.1: `agentsh policy list/show/validate`

**Files:**
- Add: `internal/cli/policy.go`
- Modify: `internal/cli/root.go`
- (Optional) Add: `internal/policy/validate.go` if needed

**Step 1: Write failing CLI test**
- Verify `agentsh policy` subcommands exist.

**Step 2: Verify red**
- Run: `go test ./internal/cli -run TestPolicyCmd_Wired`
- Expected: FAIL.

**Step 3: Implement**
- `policy list`: list policy files under `policies.dir` (from config) or a `--dir` flag.
- `policy show <name|path>`: print parsed YAML as JSON.
- `policy validate <path>`: load + validate (return non-zero on errors).

**Step 4: Verify green**
- Expected PASS.

### Task 5.2: `agentsh config show/validate`

**Files:**
- Add: `internal/cli/config.go`
- Modify: `internal/cli/root.go`

**Step 1: Write failing CLI test**
- Verify `agentsh config show` exists.

**Step 2: Verify red**
- Run: `go test ./internal/cli -run TestConfigCmd_Wired`
- Expected: FAIL.

**Step 3: Implement**
- `config show`: load YAML + apply env overrides + print JSON.
- `config validate`: parse config and exit non-zero on error.

**Step 4: Verify green**
- Expected PASS.

---

## Phase 6 — Resource limits (cgroups v2) (Linux-only, optional but in spec)

### Task 6.1: Implement cgroups v2 enforcement for memory/cpu/pids

**Files:**
- Add: `internal/limits/cgroupv2_linux.go`
- Modify: `internal/api/exec.go` (apply cgroup for external commands)
- Test: `internal/limits/cgroupv2_linux_test.go` (skip if not available)

**Step 1: Write failing test**
- Detect if cgroups v2 is available; if not, `t.Skip`.
- Create a cgroup, set `pids.max` low, run a fork bomb-ish safe command that exceeds it, assert it fails.

**Step 2: Verify red**
- Run: `go test ./internal/limits -run TestCgroupV2_PidsMax -tags=linux`
- Expected: FAIL.

**Step 3: Implement**
- Create per-command cgroup (or per-session):
  - write limits (memory.max, cpu.max, pids.max)
  - write pid to `cgroup.procs`
  - cleanup on completion

**Step 4: Verify green**
- Expected PASS (or skipped).

---

## Phase 7 — (Optional) gRPC support

> If you want strict parity with `docs/spec.md#11.4`, do this phase. Otherwise, update spec to mark gRPC “future work” and keep `server.grpc.enabled` ignored.

### Task 7.1: Add proto + generated stubs

**Files:**
- Add: `proto/agentsh/v1/agentsh.proto`
- Add: `internal/grpcserver/server.go`
- Add generated: `proto/agentsh/v1/agentsh.pb.go`, `proto/agentsh/v1/agentsh_grpc.pb.go`
- Modify: `go.mod`, `go.sum`

**Step 1: Add build tooling**
- Decide: `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc` (document exact versions).

**Step 2: Implement minimal service**
- Wire Create/Get/List/Destroy/Execute/StreamEvents by calling the existing internal managers (avoid duplicating logic).

**Step 3: Verify**
- Add a small gRPC integration test: start gRPC server on `127.0.0.1:0`, call CreateSession, then Execute `pwd`.

---

## Phase 8 — Documentation alignment

### Task 8.1: Update `docs/spec.md` for recent behavior

**Files:**
- Modify: `docs/spec.md`
- Modify: `README.md`

**Edits:**
- Document `AGENTSH_NO_AUTO=1` and the auto-start/auto-create behavior of `agentsh exec`.
- Document optional session `id` in Create Session request (REST).
- If you do Phase 7 (gRPC), ensure the proto matches reality; otherwise explicitly label it as “planned”.

**Verify:**
- Run: `rg -n \"AGENTSH_NO_AUTO\" docs/spec.md README.md` and ensure it’s referenced.

---

## Final verification (required)

Run:
- `env GOCACHE=$PWD/.gocache GOMODCACHE=$PWD/.gomodcache go test ./cmd/... ./internal/... ./pkg/...`

Expected:
- Exit code `0`.

