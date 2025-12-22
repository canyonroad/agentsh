# Env Env-Policy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement global + per-command-rule environment policies controlling allowed/denied keys, size limits, and optional iteration blocking, with exec-time enforcement and optional runtime shim.

**Architecture:** Extend policy model with env policy fields; have the policy engine return an `EnvPolicy` with the decision. In the server exec path, build the child environment per policy (global merged with rule overrides), enforce limits, and optionally set a flag to activate an LD_PRELOAD shim that blocks iteration/logs accesses. Behavior stays unchanged when env policy is unset.

**Tech Stack:** Go, existing policy engine, Go tests; optional C shim; docs updates.

---

### Task 0: Baseline (env + tests)
- Set `GOCACHE=$(pwd)/.gocache` and run `go test ./...` to confirm clean baseline.

### Task 1: Policy schema additions
**Files:** `internal/policy/model.go`, `internal/config/config.go`, `config.yml`, `docs/spec.md`
- Add global `EnvPolicy` struct to `Policy` with fields: `Allow []string`, `Deny []string`, `MaxBytes int`, `MaxKeys int`, `BlockIteration bool`.
- Add per-command-rule fields: `EnvAllow []string`, `EnvDeny []string`, `EnvMaxBytes int`, `EnvMaxKeys int`, `EnvBlockIteration bool`.
- Update sample config and spec to document fields and merge semantics.
- Tests: adjust/extend policy model tests for new fields (parse/validate).

### Task 2: Env policy merge + builder
**Files:** `internal/policy/engine.go` (or new helper), `internal/server/exec` path
- Define an `EnvPolicy` result (global + overrides) returned with command decision.
- Implement merge: start from global, override with rule fields if set; empty slices mean “as set,” not inherit.
- Implement env builder: base minimal env (PATH, LANG, TERM, HOME) → apply allow/deny against parent env → enforce max_bytes/max_keys → return slice.
- Error when limits exceeded; message includes limit type.
- Tests: unit tests for merge + builder (table-driven).

### Task 3: Exec path wiring
**Files:** `internal/api/exec.go` (and streaming/pty variants), `internal/api/exec_stream.go`
- When command decision resolved, obtain `EnvPolicy` and construct child env via builder.
- If `BlockIteration` true, set a flag env (e.g., `AGENTSH_ENV_SHIM=block`) for shim activation.
- Ensure current behavior is preserved when no env policy is defined (fallback to existing env construction).
- Tests: integration-ish test that a command sees only allowed vars; another that denied vars are absent; size limit triggers error.

### Task 4: Optional LD_PRELOAD shim (minimal)
**Files:** `internal/policy/envshim/` (new) + build script, small C source
- Intercept `getenv`, `setenv`, `putenv`, `clearenv`, `environ` access; when `AGENTSH_ENV_SHIM=block`, return empty for iteration and block denied keys (keys list passed via env? keep simple: block iteration only in v1).
- Log accesses (key names) to stderr or fd=3 (configurable) with throttling.
- Add build target to Makefile (optional; can be skipped if too much for now).
- Tests: basic C shim unit test (if feasible) or document manual test.

### Task 5: Docs and examples
**Files:** `README.md`, `docs/spec.md`, `config.yml`, `Dockerfile.example`, `docker-compose.yml`
- Document global vs per-rule env policy, merge order, limits, and shim flag.
- Note limitation: static binaries can bypass shim; recommend not passing secrets via env.

### Task 6: Full test sweep
- Run `GOCACHE=$(pwd)/.gocache go test ./...`.
- Summarize results.

### Task 7: Commit & PR (if needed)
- Commit changes with clear message.
- Update PR or open new PR.

