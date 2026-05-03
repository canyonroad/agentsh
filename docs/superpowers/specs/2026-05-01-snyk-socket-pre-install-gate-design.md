# Snyk and Socket Pre-Install Gating

**Date:** 2026-05-01
**Author:** Eran Sandler
**Status:** Design — pending review

## Goal

Add Snyk and Socket as pluggable `CheckProvider` implementations alongside the existing OSV provider, so that intercepted package installs (`npm install`, `pnpm add`, `yarn add`, `pip install`, `uv pip install`, `poetry add`, plus their bulk forms) can be gated **before** the install process runs. Each provider must function as a standalone gate — companies typically license one or the other, not both.

The threat model is the recent wave of supply-chain attacks (Shai-Hulud, `chalk` / `ansi-styles` poisonings, typosquats) that detonate inside `postinstall` scripts. These attacks must be blocked before the install process is allowed to spawn.

## Non-goals

- Snyk manifest-upload path (`POST /test/npm` with package-lock.json). Per-package fan-out only.
- Snyk CLI shell-out. REST only.
- Post-install async scanning. Pre-install gate only for v1.
- Auto-remediation, version-bumping, or rewriting `package.json`.
- Custom finding-rule DSL. Severity thresholds are the only policy knob.
- Net-new UI surface. Verdicts flow through the same channel that existing OSV verdicts use.

## Architecture

The existing `internal/pkgcheck` package already has the right shape. No new orchestration is needed.

```
intercept (interceptor.go)
   → resolve (resolver/npm.go runs `npm install --package-lock-only --ignore-scripts --json`)
       → orchestrate (orchestrator.go fans out to all configured CheckProviders in parallel)
           → providers (provider/osv.go today; provider/socket.go + provider/snyk.go new)
               → cache (internal/pkgcheck/cache, keyed by provider+ecosystem+name+version)
                   → evaluate (evaluator.go merges findings → Verdict → allow/warn/approve/block)
```

Two new files: `internal/pkgcheck/provider/socket.go` and `internal/pkgcheck/provider/snyk.go`. Each implements the existing `pkgcheck.CheckProvider` interface (`Name()`, `Capabilities()`, `CheckBatch(ctx, CheckRequest) (*CheckResponse, error)`).

A small shared helper `internal/pkgcheck/provider/httpclient.go` consolidates retry, rate-limit handling, auth header injection, and circuit-breaker state across the two new providers.

## Per-provider implementations

### Socket (`provider/socket.go`)

- Single `POST /v0/purl` per chunk. Body is a JSON object containing a list of PURLs (`pkg:npm/lodash@4.17.21`, `pkg:pypi/requests@2.31.0`) built from the `[]PackageRef` in the request.
- Hard cap of 100 PURLs per call (Socket's documented limit). Above 100, chunk and parallelize chunks.
- Response → `Finding` mapping:
  - `malware` alert → `FindingMalware`, severity preserved.
  - `installScripts`, `shellAccess`, `networkAccess` → `FindingMalware` for `critical`, `FindingReputation` otherwise.
  - `typosquat`, `suspiciousStarActivity`, `unmaintained` → `FindingReputation`.
  - `cve` alerts → `FindingVulnerability`.
  - `licenseChange`, `nonpermissiveLicense` → `FindingLicense`.
  - Provenance / signing alerts → `FindingProvenance`.
- Auth: `Authorization: Basic <base64(api_key:)>` header, key read from env var.
- Steady-state latency: one round-trip per chunk; for ≤100 packages, one round-trip.

### Snyk (`provider/snyk.go`)

- Per-package `POST /test/{ecosystem}/{name}/{version}` calls fanned out via a concurrency-bounded `errgroup`. Default concurrency: 16.
- Each response → 0..N `Finding` entries (`FindingVulnerability`, `FindingLicense`).
- Auth: `Authorization: token <api_key>` header, key read from env var.
- Cold-install latency: roughly `ceil(N_uncached / 16) * p50_per_call`. Steady-state cache means subsequent installs only fan out the changed packages (typically a handful).

Both providers share the helper for backoff, rate-limit handling, and circuit-breaker state.

## Verdict policy

```yaml
pkgcheck:
  policy:
    block_on:
      malware: any           # any | critical | never
      vulnerability: critical # critical | high | medium | never
      license: never          # any | never
      reputation: never       # any | never
      provenance: never
```

Defaults rationale:

- **Malware always blocks.** A malware finding means "running this *will* attack you" — that is fundamentally different from a CVE ("a known weakness exists") and warrants a stricter default. This is the entire purpose of the gate.
- **Vulnerabilities block on `Critical`, warn on `High`.** Blocking on `High` would block half of `npm install` runs in the npm ecosystem (long tail of `High`-severity ReDoS / prototype-pollution findings) without much real-world risk reduction.
- **License, reputation, provenance default to warn.** Teams with strict policies can flip them to block via config.

The evaluator already merges per-package verdicts using `VerdictAction.weight()`; a single `block` promotes the whole install to `block`. No evaluator changes needed.

## Fail mode

- **Per-HTTP-call timeout:** 5s, configurable. Applies to a single Socket batch call or a single Snyk `/test/...` call. For Snyk, total fan-out wall time is bounded by `ceil(N_uncached / concurrency) * per_call_p50`, not by this timeout.
- **Per-provider total budget:** 30s, configurable. Caps the worst-case wall time for the entire `CheckBatch` call across all retries and fanned-out requests. If the budget is exceeded, the response carries `ResponseMetadata.Partial: true`, `ResponseMetadata.Error` populated, **no findings emitted**.
- Any HTTP-call timeout or transport error rolls into the same partial-response shape.
- **Orchestrator behavior on partial:** if the configured external provider is partial *and* OSV succeeded, emit `Verdict.Action` based on OSV findings only with `Verdict.Summary` prefixed `"degraded: <provider> unavailable"`. Verdict is annotated so callers can render "checked with degraded coverage — N packages not externally verified."
- **Per-environment override** via env var `PKGCHECK_FAIL_MODE`:
  - `closed` — block install when external provider is partial. CI default.
  - `open` — allow install when external provider is partial. Use only with explicit risk acceptance.
  - `degraded` — fall back to OSV findings only, annotated in the verdict. Interactive default.
- **Circuit breaker:** after 3 consecutive provider errors within 60s, the provider is short-circuited for the next 60s — subsequent installs go straight to OSV-only with the `degraded` annotation, skipping the 5s timeout. Prevents holding up every install in the org during an outage.

## Caching

The cache layer at `internal/pkgcheck/cache` already keys by `(provider, ecosystem, name, version)`. Three behaviors to add or formalize:

- **TTL: 24h for "clean" results, indefinite for findings.** A clean result can go stale (a maintainer takeover happens *after* we cached "clean"); 24h is the maximum staleness window. Findings, by contrast, are essentially permanent for a given `(name, version)` — a CVE for `lodash@4.17.20` doesn't go away — so they cache indefinitely. A manual purge command (`pkgcheck cache purge`) handles the rare false-positive case.
- **Negative cache for 404 / "unknown package" responses, TTL 1h.** Private packages return 404 from Socket/Snyk; we don't re-query them every install.
- **Cache key includes provider name** so Snyk findings and Socket findings live in separate keyspaces — switching providers doesn't surface stale data from the other.

The cache is the single biggest reason per-package Snyk fan-out is viable. After the first install, the steady state for unchanged packages is zero network calls.

## Privacy / private-package handling

Two-layer skip rule:

1. **Auto-detect by registry.** A `PackageRef` whose `Registry` field is not on the configured `external_scan_registries` list is skipped. The resolver already populates `Registry` per package from the lockfile, so this is essentially free and correct in 95% of cases.
2. **Scope/prefix denylist override.** A configurable `private_scope_denylist` (e.g. `["@mycompany", "@internal-*"]`) catches packages that slip onto a public registry but should still not be sent externally — e.g., accidentally-published-public internal packages.

Skipped packages are surfaced in the verdict as a separate `Skipped` list (not silently dropped). The CLI/UI renders "N packages not externally checked (private)" so users can see the coverage gap explicitly.

This requires a small additive change to `Verdict`:

```go
type Verdict struct {
    Action   VerdictAction
    Findings []Finding
    Summary  string
    Packages map[string]PackageVerdict
    Skipped  []SkippedPackage  // new
}

type SkippedPackage struct {
    Package PackageRef
    Reason  string  // "private_registry" | "private_scope_denylist"
}
```

## Configuration shape

```yaml
pkgcheck:
  scope: all_installs              # see "Scope implication" below

  providers:
    osv:
      enabled: true                 # always-on local fallback
    socket:
      enabled: true
      api_key_env: SOCKET_API_KEY   # env var name; key never lives in the file
      timeout: 5s                    # per-HTTP-call
      total_budget: 30s              # per-CheckBatch wall-time cap
      max_purls_per_call: 100
    snyk:
      enabled: false                # mutually-exclusive with socket in typical deployments
      api_key_env: SNYK_TOKEN
      timeout: 5s                    # per-HTTP-call
      total_budget: 30s              # per-CheckBatch wall-time cap across fan-out
      concurrency: 16

  privacy:
    external_scan_registries:
      - registry.npmjs.org
      - pypi.org
    private_scope_denylist:
      - "@mycompany"
      - "@internal-*"

  policy:
    block_on:
      malware: any
      vulnerability: critical
      license: never
      reputation: never
      provenance: never

  fail_mode: degraded               # open | closed | degraded; PKGCHECK_FAIL_MODE env var overrides
```

API keys are never read from the config file — only from env vars referenced by `api_key_env`. Keeps secrets out of repos.

## Scope implication (the bare-`npm install` issue)

The current default intercept scope is `new_packages_only`, which **does not intercept bare `npm install`** (the lockfile-driven case). For a pre-install gate against supply-chain attacks, that default is wrong — bare `npm install` and `npm ci` are exactly the entry points through which a poisoned transitive dep gets pulled into a fresh checkout.

**Required change:** when any external provider (Socket or Snyk) is enabled, the scope **defaults to `all_installs`**. Users can override explicitly via config, but the loader emits a validation warning if they configure an external provider with `scope: new_packages_only`:

> "Socket is configured but `scope: new_packages_only` is set — bare `npm install` and `npm ci` will not be intercepted, so supply-chain attacks via lockfile installs will not be blocked. Set `scope: all_installs` to enable full coverage."

No code change to the interceptor itself. Just a default-scope adjustment in the config loader plus the validation warning.

## Testing strategy

- **Unit tests for each provider** using `httptest.Server` fixtures (matches the pattern in `provider/osv_test.go`). Capture real Socket/Snyk responses once into `testdata/`, replay them.
- **Provider-contract test** — a shared test suite that any `CheckProvider` implementation must pass: handles empty input, deduplicates by `name@version`, respects context cancellation, returns `Partial: true` on transport error. Run against OSV, Socket, Snyk.
- **Cache test** — fan out with 100 packages, second call issues zero network requests; 404s hit negative cache for 1h.
- **Fail-mode test** — fake Socket returning 5xx; verify orchestrator emits a degraded verdict with OSV findings only and the "degraded" prefix in summary.
- **Privacy test** — input includes `@mycompany/foo`; verify no outbound HTTP request was made for that package and verdict marks it `skipped: private_scope_denylist`.
- **Circuit-breaker test** — 3 consecutive 5xx in 60s flips the breaker; subsequent calls skip the network entirely for 60s.
- **Cross-compile test** — verify `GOOS=windows go build ./...` still succeeds (no Linux-only deps in the new providers).
- **Integration test** behind a build tag that hits the real Socket/Snyk APIs with a tiny known package set — runs nightly in CI, not on every PR. Catches API contract drift.

## Files touched

New:
- `internal/pkgcheck/provider/socket.go`
- `internal/pkgcheck/provider/socket_test.go`
- `internal/pkgcheck/provider/snyk.go`
- `internal/pkgcheck/provider/snyk_test.go`
- `internal/pkgcheck/provider/httpclient.go` (shared retry / rate-limit / circuit-breaker helper)
- `internal/pkgcheck/provider/httpclient_test.go`
- `internal/pkgcheck/provider/contract_test.go` (shared CheckProvider contract suite)
- `internal/pkgcheck/provider/testdata/socket_*.json`, `snyk_*.json` fixtures

Modified:
- `internal/pkgcheck/types.go` — add `Skipped []SkippedPackage` to `Verdict`, add `SkippedPackage` type.
- `internal/pkgcheck/orchestrator.go` — wire privacy filter (registry / scope denylist) before provider calls; surface `Skipped` in `Verdict`; honor `fail_mode` and circuit-breaker state.
- `internal/pkgcheck/evaluator.go` — apply per-finding-type severity thresholds from `policy.block_on`.
- `internal/pkgcheck/cache/*.go` — distinguish "clean" (24h TTL) from "found" (indefinite) cache entries; add negative-cache for 404s.
- `internal/config/pkgcheck*.go` — add `socket`, `snyk`, `privacy`, `policy`, `fail_mode` fields; default scope to `all_installs` when an external provider is enabled; emit validation warning otherwise.

## Open risks

- **Snyk per-package latency on first cold install.** A 500-dep `npm install` against a cold cache, at concurrency 16 and 200ms per-call p50, is roughly 6.5s of fan-out wall time (`ceil(500/16) * 200ms`). That fits within the 30s per-`CheckBatch` budget. The 5s per-call timeout applies to each individual Snyk request and is not the bound on the fan-out. Total cold-install gate latency is dominated by the resolver's `npm install --package-lock-only` step (5–30s), not by Snyk fan-out. Steady-state with cache is sub-second.
- **Socket alert taxonomy drift.** Socket adds new alert types over time; unrecognized types should map to `FindingReputation` with severity `Medium` rather than be dropped. A test asserts no alert type is silently lost.
- **API quota exhaustion.** Both Snyk and Socket meter API calls. Snyk in particular charges per call. The cache and circuit breaker mitigate; quota dashboards belong in operations docs, not in this design.
