# Env Env-Policy Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden environment variable handling for agent-executed commands by combining a global env policy with per-rule overrides, limiting exposed keys, blocking enumeration, and auditing access—all without kernel modules and with minimal perf impact.

**Architecture:** Add env policy constructs to the policy model (global + per command rule), enforce them at exec time in the server, and provide optional runtime shims/auditing for env reads/mutations. Selection must still respect existing policy evaluation (first match wins).

**Tech Stack:** Go, existing policy engine, optional LD_PRELOAD shim (C) / eBPF uprobes (if available), seccomp/AppArmor configs.

---

## Requirements
- Global env policy defaults, with per-rule overrides for command rules (first-match applies).
- Allowlist-based env construction; denylist support; size/key-count caps.
- No secrets passed via env; require explicit allow listing even if present in parent env.
- Optional blocking of env iteration (filtered or empty view) for matched commands.
- Audit: log initial env snapshot (redacted) and optionally log accesses/mutations (shim/uprobes).
- Performance: negligible overhead on command startup; optional features can be off by default.
- Compatibility: if no env policy defined, preserve current behavior (minimal env with PATH/LANG/HOME/TERM or existing default).

## Data Model Changes
- **Global (PoliciesConfig / Policy):**
  - `env_policy` (optional):
    - `allow` []string (exact keys, glob allowed?)
    - `deny` []string
    - `max_bytes` int
    - `max_keys` int
    - `block_iteration` bool (if true, return empty env view to child)
- **Per Command Rule:**
  - `env_allow` []string
  - `env_deny` []string
  - `env_max_bytes` int (optional override)
  - `env_max_keys` int (optional override)
  - `env_block_iteration` bool (optional override)
- Resolution: start from global env_policy; merge rule overrides (rule values override global; empty slice means “no extra allow” not “inherit parent”).

## Behavior
1) **Env construction at exec:**
   - Start from minimal base env (PATH, LANG, HOME, TERM). Optionally add configured defaults (e.g., `SHELL`?).
   - Apply global allowlist: include keys from parent env if in global allow and not in global deny.
   - If rule matched: apply rule allow/deny on top (rule allow adds keys from parent env; rule deny removes).
   - Enforce size/key limits (rule overrides global). If exceeded, fail command with clear error.
   - If `block_iteration`/`env_block_iteration` is true, inject shim flag to block env iteration in child (see below).
2) **Runtime blocking/audit (optional features):**
   - LD_PRELOAD shim for libc: intercept getenv/setenv/putenv/clearenv + environ; block or filter iteration when flag set; log key names for accesses/mutations to fd.
   - eBPF uprobes (optional) on libc getenv/setenv to log key names (no block) for audit.
   - Seccomp/AppArmor rule to deny `openat` on `/proc/self/environ` to reduce enumeration.
3) **Secrets handling:** Document: do not place secrets in parent env; use file/FD; env policy cannot elevate blocked keys.

## Open Questions
- Allow glob patterns in allow/deny? (Recommend simple prefix/glob via `filepath.Match`).
- Default base env contents? (Keep PATH/LANG/TERM/HOME only.)
- Where to store shim binary and how to toggle (env flag or config)?
- eBPF availability in target deployments? Might remain optional doc-only.

## Out of Scope (for now)
- Per-file or per-network-rule env controls.
- Enforcement inside statically linked binaries (shim/uprobes won’t catch). Document as limitation.

---

## Rollout Plan
- Add schema and defaults (global + rule overrides) without changing behavior when unset.
- Implement exec-time env builder with merge semantics + limits.
- Add optional iteration-block shim wiring (flag-based) and basic logging (key names only).
- Update docs/examples (config.yml, Dockerfile, compose, README/spec).
- Add tests: unit merge/limit; integration command sees only allowed keys; iteration blocked when set.

