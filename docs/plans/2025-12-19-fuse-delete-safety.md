# FUSE Delete Safety Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add auditing and optional soft-delete/blocking for destructive operations on the FUSE mount, with restore/purge tooling and clear feedback to the AI/CLI.

**Architecture:** Intercept destructive FUSE ops, emit structured audit events via a bounded async logger, and optionally divert targets into a trash area. Trash manifests enable restore and cleanup. Policy is configured in `config.yml` and enforced in the FUSE handlers with strict backpressure handling.

**Tech Stack:** Go, FUSE server (existing), jsonl logging, CLI (`cobra`).

## Specification (concise)

- Modes: `monitor` (log), `soft_block` (deny), `soft_delete` (divert to trash), `strict` (fail ops if audit/logging unhealthy applied atop selected mode). Configurable per instance/session.
- Covered ops: `unlink`, `rmdir`, `rename` (overwrite or cross-mount), `create`, `open(O_TRUNC)`, `write` (metadata size delta), `setattr` truncation. Cross-mount rename inside→outside treated as delete; outside→inside as create.
- Audit event fields: op type, src/dst paths, inode & parent, pid/ppid/uid/gid, exe/cmdline, agent session/run id, timestamps, link_count_before/after, size_before/after (when cheap), policy result (`allowed|blocked|diverted|error`), reason, trash token (if any).
- Logging: bounded channel → jsonl at `~/.agentsh/fuse-audit.log`; drop-oldest unless in strict, where ops fail if sink unhealthy/full. 
- Soft-delete: divert target to `.agentsh_trash/<ts>-<session>/<orig-path>`, prefer `rename`, fallback to copy+unlink cross-device. Manifest entry (json) stores original path, trash path, mode, uid/gid, mtime, size, optional hash for small files, session id, command, timestamp. Feedback to caller: stderr note with restore command token.
- CLI: `agentsh trash list`, `restore <token> [--dest PATH] [--force-overwrite]`, `purge [--ttl 7d] [--quota 5GB] [--session ID]`. Session teardown optionally runs purge for that session.
- Cleanup: TTL + quota enforced via purge; background/teardown purge only touches `.agentsh_trash`. Strict path normalization to avoid escapes; operations on file handles where possible.
- Performance/robustness: avoid hashing large files; non-blocking logging; path normalization and symlink safety; clear error messages on block/divert failure.

---

### Task 1: Add configuration knobs
Status: Done (2025-12-19) — defaults, parsing, validation, and tests in place.

**Files:**
- Modify: `configs/default-policy.yml`
- Modify: `config.yml`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Steps:**
1. Write failing tests adding new config fields (`fuse.audit.enabled`, `mode`, `trash_path`, `ttl`, `quota`, `strict_on_audit_failure`, `max_event_queue`, `hash_small_files_under`) with defaults and validation.
2. Run `go test ./internal/config -run TestConfig`.
3. Implement fields, defaults, and validation; update yaml parsing.
4. Run `go test ./internal/config -run TestConfig`.

### Task 2: Introduce audit event sink
Status: Done (2025-12-19) — bounded async logger with drop-oldest/strict modes; tests pass.

**Files:**
- Create: `internal/fsmonitor/audit/audit.go`
- Create: `internal/fsmonitor/audit/audit_test.go`

**Steps:**
1. Write failing tests for bounded async logger: drop-oldest vs strict mode, jsonl formatting, includes pid/uid/session, and behavior when sink unavailable.
2. Run `go test ./internal/fsmonitor/audit -run Test`.
3. Implement event struct, bounded channel, drop-oldest policy, strict failure path, and writer to `~/.agentsh/fuse-audit.log`.
4. Run `go test ./internal/fsmonitor/audit -run Test`.

### Task 3: Wire FUSE handlers with policy and auditing
Status: Done (2025-12-19) — destructive ops covered; cross-mount delete/create with size/nlink; integration tests passing.

**Files:**
- Modify: `internal/fsmonitor/fuse.go` (or relevant FUSE server file)
- Modify: `internal/fsmonitor/fsmonitor_test.go` (add coverage)
- Modify/Create: `internal/fsmonitor/policy.go` (helper to evaluate mode)

**Steps:**
1. Add/extend tests that exercise `unlink`, `rmdir`, `rename` overwrite, cross-mount rename, `open` with `O_TRUNC`, and truncating `setattr`, asserting audit events and policy outcomes (monitor, soft_block, strict failure).
2. Run `go test ./internal/fsmonitor -run Test`.
3. Implement `auditAndMaybeDivert` helper, mode evaluation, and calls from handlers; include cross-mount detection and symlink-safe path normalization.
4. Run `go test ./internal/fsmonitor -run Test`.

### Task 4: Implement trash diversion & CLI tools
Status: Done (2025-12-19) — divert/manifest/restore/purge plus CLI commands and tests.

**Files:**
- Create: `internal/trash/trash.go`
- Create: `internal/trash/trash_test.go`
- Create: `internal/cli/trash.go`

**Steps:**
1. Write failing tests for diversion (rename vs copy fallback), manifest writing, restore (default path and `--dest`, `--force-overwrite`), and purge (TTL/quota/session filter).
2. Run `go test ./internal/trash -run Test`.
3. Implement diversion helpers used by FUSE, manifest format, restore/purge functions.
4. Implement `agentsh trash list|restore|purge` CLI wiring to trash package.
5. Run `go test ./internal/trash -run Test && go test ./internal/cli -run TestTrash` (or nearest CLI test).

### Task 5: Session teardown hook and integration verification
Status: Done (2025-12-19) — session destroy triggers trash purge per audit config; `internal/api/app_destroy_test.go` verifies.

**Files:**
- Modify: `internal/session/session.go` (or appropriate session lifecycle file)
- Modify/Create: `internal/session/session_test.go`
- Modify: `docs` if CLI help needs update (optional)

**Steps:**
1. Add failing test ensuring session teardown triggers `trash purge --session <id>` when enabled and respects config.
2. Run `go test ./internal/session -run Test`.
3. Implement teardown hook invoking trash purge; ensure errors surfaced/logged per mode.
4. Run `go test ./internal/session -run Test`.
5. Run full suite `go test ./...` in worktree.

---

After plan approval, execute with superpowers:executing-plans task-by-task in this worktree.
