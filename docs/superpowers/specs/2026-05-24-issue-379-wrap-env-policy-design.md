# Enforce env_policy on the wrap path Design

Issue: #379 (follow-up to #374)

## Summary

On the client-spawned wrap path (shell shim / kernel-install and `agentsh wrap`), the executed command inherits the launcher's full environment (`syscall.Exec(cmdPath, args, os.Environ())` in `cmd/agentsh-unixwrap/main.go`). `policy.BuildEnv` — which enforces env `allow`/`deny`/`max_bytes`/`max_keys` — runs only on the server-spawned exec path (`internal/api/exec.go`). So env_policy allow/deny isolation never runs on the wrap path: commands (including any secrets in the launcher env) see everything. #374 plumbed `env_inject` through this path; this closes the env_policy gap.

The fix plumbs the resolved env policy through `WrapInitResponse` (exactly as #374 did for `EnvInject`) and applies a **subtractive** `policy.BuildEnv` filter client-side over the inherited environment, **gated behind an opt-in config flag**, **fail-open**. Default-off means zero behavior change for existing deployments until an operator enables it.

## Goals

- When enabled, the wrap path filters the executed command's environment per the resolved env policy: `deny` + the built-in `defaultSecretDeny` list strip secrets; `env_allow` (when set) tightens to allowlist; `max_bytes`/`max_keys` apply.
- Default-off: no change to any existing wrap/shim deployment until `sandbox.wrap_env_policy.enabled: true`.
- Fail-open: any filter error falls back to the unfiltered inherited env; a command is never blocked by env filtering.
- Mixed-version safe: old server / new client and new server / old client both degrade to today's behavior (no filtering).
- agentsh's own markers (`AGENTSH_*`, notify/signal FDs, wrapper env, proxy markers) and operator `env_inject` are never stripped.

## Non-Goals

- **No minimal-base rebuild** (the exec path's deny-by-default minimal base). We keep the inherited env as the base and subtract — preserving the inheritance the wrap path's platforms (Blaxel/E2B/Daytona) and the documented `BASH_ENV`/`env_inject` workaround depend on.
- **`block_iteration` is not applied** on the wrap path. It relies on replacing `environ`, which is incompatible with shells (documented in `exec.go` `maybeAddShimEnv`). Only allow/deny/max are enforced.
- No per-inner-command env rebuild: the filter applies once to the wrapped shell's env at launch; nested commands inherit it. (Coarser than exec by nature; documented.)
- No change to the server-spawned exec path, Windows/darwin wrap, or `block_iteration` semantics elsewhere.
- Not flipping the default to on (a later, separately-decided rollout step).

## Background

- Server exec resolves the env policy as `dec.EnvPolicy` (`policy.ResolvedEnvPolicy{Allow, Deny, MaxBytes, MaxKeys, BlockIteration}`) from the command `Decision` and passes it to `buildPolicyEnv` → `policy.BuildEnv(pol, minimalBase, add)` (`internal/api/core.go:1071`, `exec.go:705`).
- `policy.BuildEnv(pol, baseEnv, addKeys)` (`internal/policy/env_policy.go:55`): with no `allow` patterns it keeps everything except `deny` matches and a built-in `defaultSecretDeny` list; with `allow` patterns it keeps only allowed keys; then applies `max_bytes`/`max_keys`; `addKeys` are merged after filtering. Applying it over the **full** inherited env (not a minimal base) yields the subtractive behavior we want.
- The wrap handler `wrapInitCore` (`internal/api/wrap.go:124`) already builds the response and sets `EnvInject: mergeEnvInject(a.cfg, a.policyEngineFor(s))` at two sites: ptrace (`wrap.go:283`) and seccomp (`wrap.go:519`). `dec` (the command decision at `wrap.go:164`) is scoped to the `req.Mode == "shim"` block, so env-policy resolution for the response uses a dedicated helper rather than that `dec`.
- `WrapInitResponse` is in `pkg/types/sessions.go`, which must not import `internal/policy`; the wire type is therefore a primitive struct mapped to/from `policy.ResolvedEnvPolicy` on each side.
- Clients build the wrapped env in two places, both of which already `import` `internal/envinject` and apply `envinject.Apply`:
  - `internal/cli/wrap_linux.go`: ptrace branch (~L30) and seccomp branch (~L138) — base is `os.Environ()`, then `buildWrapEnv(base, …)` adds markers, then `envinject.Apply`.
  - `internal/shim/kernelinstall/install_linux.go:200`: `assembleWrapperEnv(filterShimInternalEnv(p.Env), p.Argv0, resp.WrapperEnv, resp.EnvInject)`.

## Design

### 1. Opt-in config flag

Add `WrapEnvPolicy SandboxWrapEnvPolicyConfig `yaml:"wrap_env_policy"`` to `SandboxConfig`, where:

```go
type SandboxWrapEnvPolicyConfig struct {
    Enabled bool `yaml:"enabled"` // default false; opt-in (issue #379)
}
```

No default needed (zero value `false` = off); no validation needed (bool).

### 2. Wire the resolved policy through `WrapInitResponse`

In `pkg/types/sessions.go`:

```go
// EnvPolicyWire carries the resolved env allow/deny/limits for the client
// (shell shim / CLI wrap) to filter the executed command's inherited
// environment. Nil/omitted means "no filtering" (the field is only populated
// when sandbox.wrap_env_policy.enabled is true), which also makes mixed-version
// deployments degrade safely. block_iteration is intentionally not carried:
// it is not enforceable on the wrap path (shells read environ directly).
// Issue #379.
type EnvPolicyWire struct {
    Allow    []string `json:"allow,omitempty"`
    Deny     []string `json:"deny,omitempty"`
    MaxBytes int      `json:"max_bytes,omitempty"`
    MaxKeys  int      `json:"max_keys,omitempty"`
}
```

and add `EnvPolicy *EnvPolicyWire `json:"env_policy,omitempty"`` to `WrapInitResponse`.

Server: a helper `(a *App) wrapEnvPolicyWire(s *session.Session, req types.WrapInitRequest) *types.EnvPolicyWire` returns `nil` when `!a.cfg.Sandbox.WrapEnvPolicy.Enabled`; otherwise it resolves the env policy for the wrapped command (`a.policyEngineFor(s).CheckCommandWithExecve(req.AgentCommand, req.AgentArgs, a.execveEnforcementActive(), a.shellCOpaqueMode()).EnvPolicy`) and maps `{Allow, Deny, MaxBytes, MaxKeys}` to `EnvPolicyWire`. It is set alongside `EnvInject:` at both response sites (`wrap.go:283`, `wrap.go:519`).

### 3. Subtractive filter helper (new package `internal/wrapenv`)

```go
// Filter applies the wrapped command's env policy subtractively over the
// inherited base environment. nil wire ⇒ base returned unchanged (fail-open
// for default-off and mixed-version). On BuildEnv error ⇒ base returned
// unchanged with a slog.Warn (fail-open: env filtering never blocks a command).
// Issue #379.
func Filter(base []string, wire *types.EnvPolicyWire) []string {
    if wire == nil {
        return base
    }
    pol := policy.ResolvedEnvPolicy{
        Allow: wire.Allow, Deny: wire.Deny,
        MaxBytes: wire.MaxBytes, MaxKeys: wire.MaxKeys,
    }
    out, err := policy.BuildEnv(pol, base, nil)
    if err != nil {
        slog.Warn("wrap env policy filter failed; passing inherited env unfiltered", "error", err)
        return base
    }
    return out
}
```

(`internal/wrapenv` may import both `pkg/types` and `internal/policy`.)

### 4. Apply client-side, before markers

The filter runs on the **inherited launcher env only**, before agentsh adds its own vars — so markers, wrapper env, proxy, and `env_inject` are never stripped and `env_inject` still overrides:

- `internal/cli/wrap_linux.go`, both branches: `base := wrapenv.Filter(os.Environ(), wrapResp.EnvPolicy)` then the existing `buildWrapEnv(base, …)` → `envinject.Apply(…)`.
- `internal/shim/kernelinstall/install_linux.go:200`: wrap the base — `assembleWrapperEnv(wrapenv.Filter(filterShimInternalEnv(p.Env), resp.EnvPolicy), p.Argv0, resp.WrapperEnv, resp.EnvInject)`.

Note: as on the exec path, a restrictive `env_allow` will also exclude infra vars (proxy/LLM) unless the operator lists them — identical to `buildPolicyEnv`'s behavior, and documented.

### Why not other approaches

- **Filter inside `agentsh-unixwrap` before `execve`:** single chokepoint, but the wrapper is a minimal static stub; it would require serializing allow/deny globs into its env and reimplementing `BuildEnv`. The Go client already imports `policy`/`envinject` and reuses `BuildEnv` directly — DRY and consistent with how #374 applied `env_inject`.
- **Server returns a fully-filtered env set:** impossible — the launcher env (`os.Environ()`) exists only client-side; the server can send the policy, not the filtered result.
- **Minimal-base rebuild (exec parity):** rejected as a non-goal — breaks inheritance on the exact platforms this path serves.

## Error handling

No new error types. `Filter` is fail-open: nil wire or `BuildEnv` error ⇒ inherited env unchanged (logged). The server helper returns `nil` when disabled. Mixed-version: absent `EnvPolicy` (old server) ⇒ client filters nothing; unknown field (old client) ⇒ ignored.

## Testing

`internal/wrapenv` (table tests):
- nil wire ⇒ identity (same slice contents).
- deny `["SECRET_*"]`, no allow ⇒ `SECRET_TOKEN` stripped, `PATH`/`HOME` kept.
- no allow, no deny ⇒ a `defaultSecretDeny`-listed var (e.g. `AWS_SECRET_ACCESS_KEY`) stripped, ordinary vars kept (confirms baseline secret protection).
- allow `["PATH","HOME"]` ⇒ only those kept.
- `max_keys` / `max_bytes` enforced.
- a var named like an agentsh marker is irrelevant here (markers are added by callers after Filter) — covered by the caller-order tests below.

`internal/api` (wrap helper):
- flag off ⇒ `wrapEnvPolicyWire` returns `nil` (and the response `EnvPolicy` is nil).
- flag on with a policy that denies `FOO` ⇒ returns a wire whose `Deny` contains `FOO`; `Allow`/`MaxBytes`/`MaxKeys` mirror the resolved policy.

`internal/cli` / `internal/shim/kernelinstall` (ordering): a focused test that, given a base containing a denied var plus an agentsh marker added after Filter, the denied var is removed while the marker and an `env_inject` value survive. (If a full wrap launch is impractical to unit-test, assert the helper composition: `envinject.Apply(buildWrapEnv(wrapenv.Filter(base, wire), …), inject)` keeps markers + inject and drops denied vars.)

`internal/config`: `sandbox.wrap_env_policy.enabled` defaults to false; round-trips true from YAML.

Confirm existing `internal/api`, `internal/cli`, `internal/config`, `internal/policy` suites stay green and `GOOS=windows go build ./...` succeeds.

## Affected files

- `pkg/types/sessions.go` — `EnvPolicyWire` type + `EnvPolicy *EnvPolicyWire` field on `WrapInitResponse`.
- `internal/config/config.go` — `SandboxWrapEnvPolicyConfig{Enabled}` + `WrapEnvPolicy` field on `SandboxConfig`.
- `internal/wrapenv/wrapenv.go` (new) + test — the `Filter` helper.
- `internal/api/wrap.go` — `wrapEnvPolicyWire` helper; populate `EnvPolicy` at both response sites.
- `internal/cli/wrap_linux.go` — filter the inherited base in both branches.
- `internal/shim/kernelinstall/install_linux.go` — filter the base in the `assembleWrapperEnv` call.
- Tests in `internal/wrapenv`, `internal/api`, `internal/config`.
