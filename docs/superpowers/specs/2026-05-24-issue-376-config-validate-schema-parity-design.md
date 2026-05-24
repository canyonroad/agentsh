# config validate / startup schema-validation parity Design

Issue: #376

## Summary

`agentsh config validate` reports `ok` for configs the server then rejects at startup, so misconfiguration surfaces at runtime as a generic "connection refused" (via the shim) instead of a clear validation error pre-deploy. The reported case is the `sandbox.ptrace` + `unix_sockets` "execve-only" constraint, which is enforced only at server startup (`cfg.Sandbox.Validate()`), not in the `config.Load` path that `config validate` uses.

This design makes `config.Load`'s `validateConfig` the single authority for **config-schema** validation by adding the two pure config-schema cross-field validators currently enforced only at startup — `cfg.Sandbox.Validate()` and `cfg.Policies.Signing.Validate()` — with error messages identical to the startup messages. Host/environment checks (capabilities, etc.) intentionally stay at startup.

## Goals

- `config validate` (and `config.Load`, hence the server and shim auto-start) rejects the `sandbox.ptrace` + `unix_sockets` non-execve-only config with the same message the server prints today.
- Close the identical latent gap for `cfg.Policies.Signing.Validate()` in the same change (same bug class).
- Establish and document the dividing principle: config-file invariants validate in `validateConfig`; host/environment checks stay at startup.
- Add regression tests so the gap cannot silently reopen.

## Non-Goals

- Do not move host/environment checks (`capabilities.CheckAll`, duration parsing, etc.) into `config validate` — they validate the machine, not the file, and would cause false failures when validating a config destined for another host.
- Do not relocate the other config-only startup checks (approvals-requires-auth, pkgcheck/skillcheck provider/dir requirements) — larger, entangled with `server.New`, and unreported. Possible follow-up.
- Do not remove the startup validation calls; keep them as defense-in-depth.

## Background

- `config validate` → `loadLocalConfig` → `config.LoadWithSource` → `config.Load` → `validateConfig(cfg)` (`internal/config/config.go`, ~L2365-2441). `validateConfig` checks many enums/bounds (package_checks, landlock self-lockout, watchtower, blocked_socket_families, …) but does **not** call `cfg.Sandbox.Validate()` or `cfg.Policies.Signing.Validate()`.
- `cfg.Sandbox.Validate()` (`config.go:368`) enforces: `ptrace` + `seccomp.execve` mutual exclusion; `ptrace` + `unix_sockets` requires execve-only tracing; and delegates to `Ptrace.Validate()`.
- These two validators are called only at `internal/server/server.go:143` (`sandbox config: %w`) and `:147` (`signing config: %w`).
- The server always obtains its config via `config.Load` (single production `server.New` call site, fed by `loadLocalConfig`), so anything added to `validateConfig` runs before the server sees the config.

## Design

### 1. Add the two validators to `validateConfig`

At the end of `validateConfig` (before its final `return nil`), add:

```go
// Config-schema cross-field invariants that the server also enforces at
// startup. Validated here so `agentsh config validate` (and the shim's
// auto-start path) catch them before deploy rather than surfacing as a
// generic "server unreachable" at runtime (issue #376). Host/environment
// checks (capabilities, etc.) intentionally stay at server startup.
if err := cfg.Sandbox.Validate(); err != nil {
    return fmt.Errorf("sandbox config: %w", err)
}
if err := cfg.Policies.Signing.Validate(); err != nil {
    return fmt.Errorf("signing config: %w", err)
}
```

The `sandbox config:` / `signing config:` prefixes match `server.go:144,148` verbatim, so the messages from `config validate` and startup are identical.

### 2. Guardrail comment at `server.go`

Above the `cfg.Sandbox.Validate()` / `cfg.Policies.Signing.Validate()` calls (`server.go:143-149`), add a comment:

```go
// These config-schema invariants are also enforced by config.validateConfig
// (so `agentsh config validate` catches them pre-deploy, issue #376). The
// calls here are defense-in-depth for any server built from a config that did
// not pass through config.Load. New config-schema invariants belong in
// config.validateConfig, not here.
```

The calls stay (defense-in-depth; no behavior removed). For a config that came through `Load`, they re-run and pass.

### 3. Environment checks unchanged

`capabilities.CheckAll(cfg)` and the other startup-only operational/duration checks remain at `server.New`.

## Error handling

No new error types. The two added checks return the existing validator errors wrapped with the existing prefixes. A config that previously passed `config validate` but is invalid will now fail at `validateConfig` time (the intended fix); failure modes and messages are unchanged from startup.

## Testing

In `internal/config` (model on existing validation tests; use `validateConfig` or `Load` against in-memory/temp configs):

1. **ptrace + unix_sockets non-execve-only → rejected:** `sandbox.ptrace.enabled=true`, `unix_sockets.enabled=true`, `ptrace.trace.execve=true` with `file/network/signal=true` → error contains `sandbox config:` and `requires execve-only tracing`.
2. **ptrace + seccomp.execve → rejected:** both enabled → error contains `sandbox config:` and `mutually exclusive`.
3. **signing mode enforce without trust store → rejected:** error contains `signing config:`.
4. **valid baseline config → accepted:** a representative valid config (e.g. defaults, or execve-only ptrace + unix_sockets) passes `validateConfig`/`Load`.

Confirm the existing `internal/config` and `internal/server` suites still pass (no fixture relied on loading an invalid config successfully).

## Affected files

- `internal/config/config.go` — two validator calls appended to `validateConfig`.
- `internal/config/validate_sandbox_signing_test.go` (new) — regression tests, following the existing `TestValidateConfig_*` convention (e.g. `pkgcheck_test.go`).
- `internal/server/server.go` — guardrail comment above the existing startup validation calls.

## Out of scope (possible follow-up)

- Moving approvals-requires-auth, pkgcheck/skillcheck provider+dir requirements, and duration parsing into `validateConfig` for full startup-invariant parity.
- The orphaned `ResolverConfig.Validate()` (defined, never called).
