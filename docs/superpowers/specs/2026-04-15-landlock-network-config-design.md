# Landlock network config wiring — Design Spec

**Date:** 2026-04-15
**Status:** Approved
**Author:** design session between Eran Sandler and Claude

## Problem

`internal/config/config.go` defines `LandlockNetworkConfig` with YAML-tagged `allow_connect_tcp`, `allow_bind_tcp`, and `bind_ports` fields. The YAML is parsed, but nothing on the production enforcement path reads the parsed values.

The sole production path that applies Landlock is the wrapper (`cmd/agentsh-unixwrap`), which receives its config as a JSON blob in `AGENTSH_SECCOMP_CONFIG`. The server builds that blob at two sites, both of which hardcode the TCP allow flags to `true`:

- `internal/api/wrap.go:177-178` — `seccompCfg.AllowNetwork = true; seccompCfg.AllowBind = true`
- `internal/api/core.go:245-246` — same

As a result, Landlock network restriction never applies: `bind()` and `connect()` succeed from agent processes regardless of `landlock.network.*` config.

A secondary path exists — `internal/landlock/policy.go:290`, reached via `BuildFromConfig` in `landlock_hook.go` / `landlock_exec.go` — which does read the config correctly. However, those entry points are only exercised in tests; no production caller wires them up.

## Goal

Make `landlock.network.allow_connect_tcp` and `landlock.network.allow_bind_tcp` semantically real on the production (wrapper) path, with safe defaults and explicit validation against self-lockout. Reserve `bind_ports` for a follow-up.

## Non-Goals

- Port-scoped bind rules (`bind_ports` enforcement). Requires `LANDLOCK_RULE_NET_PORT` support in `internal/landlock/ruleset.go`; tracked as a follow-up.
- Resurrecting the dead in-process path (`LandlockHook.Apply`, `MakeLandlockPostStartHook`). Tangential; left in place as-is.
- UDP support. Landlock ABI does not yet offer UDP access controls in the versions agentsh targets.

## Architecture

### Data flow (Linux, wrapper path)

```
YAML config
  → config.LandlockNetworkConfig { AllowConnectTCP *bool, AllowBindTCP *bool, BindPorts []int }
  → applyDefaults: AllowConnectTCP=nil → ptr(true); AllowBindTCP=nil → ptr(false)
  → validateConfig: if Landlock.Enabled && !*AllowConnectTCP && Sandbox.Network.Enabled → error
  → api/core.go + api/wrap.go build seccompWrapperConfig:
        AllowNetwork = *cfg.Landlock.Network.AllowConnectTCP
        AllowBind    = *cfg.Landlock.Network.AllowBindTCP
  → json.Marshal → AGENTSH_SECCOMP_CONFIG env var
  → cmd/agentsh-unixwrap: cfg.AllowNetwork, cfg.AllowBind
  → builder.SetNetworkAccess(cfg.AllowNetwork, cfg.AllowBind)
  → Landlock ruleset applied in child, pre-exec
```

### Files touched

**Modify:**
- `internal/config/config.go` — `LandlockNetworkConfig` fields become `*bool`; new defaults and validation in `applyDefaults`/`validateConfig`; `bind_ports` warning.
- `internal/api/core.go:243-246` — replace hardcoded `true` with reads from `a.cfg.Landlock.Network.AllowConnectTCP/AllowBindTCP`. Update the adjacent comment to reflect the new semantics.
- `internal/api/wrap.go:176-178` — same replacement, same comment update.

**Create:**
- `internal/config/landlock_network_test.go` — defaults + validation unit tests.

**Modify (tests):**
- `internal/api/core_test.go` (or the appropriate existing test file) — integration tests for the core.go construction path.
- `internal/api/wrap_test.go` (or appropriate) — integration tests for the wrap.go construction path.

## Config schema change

### Before

```go
type LandlockNetworkConfig struct {
    AllowConnectTCP bool  `yaml:"allow_connect_tcp"`
    AllowBindTCP    bool  `yaml:"allow_bind_tcp"`
    BindPorts       []int `yaml:"bind_ports"`
}
```

### After

```go
type LandlockNetworkConfig struct {
    AllowConnectTCP *bool `yaml:"allow_connect_tcp"` // default: true
    AllowBindTCP    *bool `yaml:"allow_bind_tcp"`    // default: false
    BindPorts       []int `yaml:"bind_ports"`        // reserved; not yet enforced
}
```

Pointer types are required to distinguish "user explicitly set `false`" from "user didn't set the field." This pattern is already used elsewhere in the codebase (`cfg.Sandbox.UnixSockets.Enabled` is `*bool`, consumed at `internal/api/wrap.go:183`).

## Defaults (in `applyDefaults`)

```go
if cfg.Landlock.Network.AllowConnectTCP == nil {
    v := true
    cfg.Landlock.Network.AllowConnectTCP = &v
}
if cfg.Landlock.Network.AllowBindTCP == nil {
    v := false
    cfg.Landlock.Network.AllowBindTCP = &v
}
```

Defaults are applied unconditionally (regardless of `landlock.enabled`). When Landlock is disabled, the fields are simply unused — the wrapper's Landlock construction block only runs inside `if a.cfg.Landlock.Enabled && llResult.Available`, and `SetNetworkAccess` is only called when Landlock is being built. Unconditional defaulting keeps the config shape predictable for diagnostic dumps, policy-change audit tooling, and anyone reading `cfg.Landlock.Network.AllowConnectTCP` without a nil-check.

## Validation (in `validateConfig`)

```go
if cfg.Landlock.Enabled &&
    cfg.Landlock.Network.AllowConnectTCP != nil &&
    !*cfg.Landlock.Network.AllowConnectTCP &&
    cfg.Sandbox.Network.Enabled {
    return fmt.Errorf(
        "landlock.network.allow_connect_tcp is false but sandbox.network.enabled " +
        "is true: agent processes cannot reach the agentsh proxy without outbound TCP. " +
        "Either set landlock.network.allow_connect_tcp to true, or set " +
        "sandbox.network.enabled to false.")
}
```

No validation for `allow_bind_tcp` — disabling bind is the intended secure case.

### `bind_ports` warning

```go
if len(cfg.Landlock.Network.BindPorts) > 0 {
    slog.Warn("landlock.network.bind_ports is set but not yet enforced",
        "bind_ports", cfg.Landlock.Network.BindPorts,
        "note", "port-scoped bind rules are a planned follow-up")
}
```

One-time warning at config load so users aren't silently ignored.

## Consumer updates

### `internal/api/core.go:243-246`

**Before:**
```go
// Allow all network by default — agentsh proxy handles network policy.
// Without this, Landlock ABI v4+ blocks ALL TCP connections.
seccompCfg.AllowNetwork = true
seccompCfg.AllowBind = true
```

**After:**
```go
// Honor landlock.network.* config. Validation in validateConfig already rejects
// allow_connect_tcp=false while sandbox.network.enabled=true, so reaching this
// point with AllowConnectTCP=false implies the user opted out of proxy TCP.
seccompCfg.AllowNetwork = *a.cfg.Landlock.Network.AllowConnectTCP
seccompCfg.AllowBind = *a.cfg.Landlock.Network.AllowBindTCP
```

### `internal/api/wrap.go:176-178`

Same replacement.

### `cmd/agentsh-unixwrap/main.go:313`

No change. `builder.SetNetworkAccess(cfg.AllowNetwork, cfg.AllowBind)` already consumes the JSON-passed values correctly.

## Testing

### Unit tests (`internal/config/landlock_network_test.go`)

- `TestDefaults_LandlockEnabled_FillsConnectTrueBindFalse` — empty `landlock.network` block + `landlock.enabled: true` → after `applyDefaults`, `*AllowConnectTCP == true`, `*AllowBindTCP == false`.
- `TestDefaults_ExplicitValuesPreserved` — user sets `allow_connect_tcp: false` and `allow_bind_tcp: true` → `applyDefaults` does not overwrite.
- `TestDefaults_LandlockDisabled_StillDefaults` — `landlock.enabled: false` → defaults still applied (diagnostic-friendly).
- `TestValidation_ConnectFalseWithProxyEnabled_Errors` — `landlock.enabled + allow_connect_tcp=false + sandbox.network.enabled=true` → `validateConfig` returns the named error.
- `TestValidation_ConnectFalseWithProxyDisabled_OK` — same, but `sandbox.network.enabled=false` → accepted.
- `TestValidation_BindTCPFalse_AlwaysOK` — `allow_bind_tcp=false + sandbox.network.enabled=true` → accepted (no bind validation).
- `TestBindPortsWarning` — non-empty `bind_ports` triggers slog warning (capture via `slog.Handler`).

### Integration tests (per construction site)

- `TestCoreSeccompConfig_HonorsLandlockNetworkConfig` — construct an `App` with `AllowConnectTCP=ptr(false), AllowBindTCP=ptr(true)`, mock Landlock as available, invoke the core.go construction path, assert `seccompWrapperConfig.AllowNetwork == false && AllowBind == true`.
- `TestWrapSeccompConfig_HonorsLandlockNetworkConfig` — equivalent for `wrap.go:150` construction path.
- `TestCoreSeccompConfig_DefaultsPropagate` — end-to-end: YAML without `landlock.network` block, pass through config load + construction, assert `AllowNetwork=true, AllowBind=false`.

### Back-compat test

- `TestBackCompat_NoLandlockNetworkBlock` — minimal config `{landlock: {enabled: true}}` → after full pipeline, `AllowNetwork=true, AllowBind=false`. Explicitly documents the one intentional behavior change (bind flips from permissive to restrictive).

### What is NOT tested here

- Kernel-level Landlock enforcement. Covered by existing `internal/landlock/integration_test.go`. The bug is in wiring, not enforcement.
- The in-process `BuildFromConfig` path. Already correct, already tested, not on the production path.

## Rollout + back-compat

### Single intentional behavior change

`landlock.network.allow_bind_tcp` now takes effect. Previously, agent processes could bind to any TCP port regardless of Landlock. New default: `false` (bind blocked).

### Changelog entry

> **Breaking (security hardening):** `landlock.network.allow_bind_tcp` now takes effect. Previously, agent processes running under Landlock could `bind()` to any TCP port regardless of this field. The new default is `false` (bind blocked). Set `landlock.network.allow_bind_tcp: true` in your config if your agent workloads need to listen on TCP ports.
>
> **Fixed:** `landlock.network.allow_connect_tcp` is now honored. Attempting to set it to `false` while `sandbox.network.enabled` is `true` now fails fast at startup with an explanatory error rather than silently breaking proxy connectivity mid-session.
>
> **Reserved:** `landlock.network.bind_ports` is parsed but not yet enforced. A warning is logged if set. Port-scoped bind rules are a planned follow-up.

### No migration needed

- Existing configs continue to parse (field already existed in YAML).
- Users who set `allow_bind_tcp: true` get the behavior they always expected.
- Users who set `allow_bind_tcp: false` finally get the behavior they asked for.
- Users who set nothing get the tightened default (`false`).
- Users who set `allow_connect_tcp: false` with `sandbox.network.enabled=true` now fail at startup instead of running with silently-ignored config.

### Non-Linux platforms

`landlock_hook_other.go`, `landlock_exec_other.go`, and `ruleset_other.go` stubs already ignore network fields entirely. No change.

## Risks

- **False sense of security from orphan `bind_ports`.** Mitigated by the startup warning and the reserved-field comment in the struct.
- **User with `allow_bind_tcp: true` in their config is unaffected** — this is the original, accidentally permissive behavior. No regression for them.
- **User depending on the accidental permissive default** (i.e., their agent binds but `allow_bind_tcp` is unset) loses that ability. Mitigation: changelog, startup warning could be added if we want to flag "bind blocked" to ops teams — not in scope for v1.

## Open questions resolved during design

- **Why `*bool` instead of fail-closed zero-value defaults?** Because yaml.v3 cannot distinguish "field absent" from "field set to `false`" with non-pointer booleans. The existing codebase already uses `*bool` for `Sandbox.UnixSockets.Enabled` — consistent pattern.
- **Why validate instead of silently force `connect_tcp=true`?** Silent overrides hide user intent. Failing loudly at startup with a descriptive error is strictly better for operators than either (a) silently ignoring the config or (b) breaking mid-session with opaque `ECONNREFUSED`.
- **Why not remove `bind_ports` now?** It's already in people's YAML configs (struct tag exists). Removing it would be a parse-time breaking change for zero security benefit. Leaving it with a warning costs nothing and preserves the option to implement port-scoped rules cleanly later.
