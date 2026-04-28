# Skill Installation Scanning (`skillcheck`) — Design

**Date:** 2026-04-28
**Status:** Draft, awaiting user review
**Related:** `internal/pkgcheck/` (sibling pattern for npm/pip install scanning),
`internal/threatfeed/` (sibling pattern for periodic catalog sync),
`internal/fsmonitor/`, `internal/trash/`, `internal/approval/`, `internal/audit/`.

## Summary

Add a new `internal/skillcheck/` package that intercepts AI agent skill
installations (Claude Code skill directories under `~/.claude/skills/`
and plugin-bundled skills under `~/.claude/plugins/*/skills/`) and
runs them through pluggable security scanners before they become
loadable by the agent.

The architecture mirrors `internal/pkgcheck/`:

- `CheckProvider` interface, `Orchestrator` (parallel fan-out, per-provider
  timeout, `OnFailure: warn|deny|allow`), `Evaluator` (severity → action
  mapping), and four-state `Verdict` (`allow|warn|approve|block`).
- The differences from `pkgcheck` are forced by the artifact: a skill is
  a directory of files (markdown + scripts) rather than a `name@version`,
  and there is no canonical "skill install command" to wrap.

Two trigger paths feed one pipeline:

1. An **fsmonitor watcher** observes the watch roots for new `SKILL.md`
   landings (covers all install paths: git clone, marketplace plugin,
   manual `cp`).
2. An **`agentsh skillcheck` CLI** for one-off scans, hook integrations,
   and quarantine management.

Three scanners ship in v1, plus two stubs for v2:

| Provider | Category | Integration |
|---|---|---|
| `local` | Offline rule engine | Native Go |
| `snyk` | Active scanner | Subprocess: `uvx snyk-agent-scan@latest --skills <path> --json` |
| `skills_sh` | Provenance signal | HTTP HEAD/GET against `https://skills.sh/<owner>/<repo>/<skill>`; optional `__NEXT_DATA__` parsing for audit badges |
| `chainguard` | (v2) Provenance | Periodic catalog sync — interface only in v1 |
| `repello` | (v2) Active scanner | Stub only in v1 |

The `block` action quarantines the skill directory via `internal/trash`
(reversible soft-delete). The `approve` action prompts via
`internal/approval`. All actions emit `skillcheck.*` audit events.

## Motivation

Malicious AI agent skills are now an established supply-chain attack
vector ([Snyk Labs ClawHavoc analysis][clawhavoc],
[Antiy CERT 1,184 malicious skills on ClawHub][antiy],
[Embrace The Red on hidden Unicode in skills][etr]). Installation
happens through many channels — git clone, marketplace plugins,
manual copies — and once a `SKILL.md` lands in a watched directory it
is loadable by the next agent session. Today agentsh has no enforcement
layer for this artifact class even though it has a complete pattern
for the analogous npm/pip case (`internal/pkgcheck/`).

This design extends that protection to skills using the same
architectural pattern, the same verdict spectrum, and the same audit
sink, so operators have one mental model for "agentsh blocked
something dangerous from being installed."

[clawhavoc]: https://repello.ai/blog/clawhavoc-supply-chain-attack
[antiy]: https://blog.cyberdesserts.com/ai-agent-security-risks/
[etr]: https://embracethered.com/blog/posts/2026/scary-agent-skills/

## Non-Goals

- **Web-uploaded skill zips** (claude.ai web app). agentsh has no
  chokepoint there; that is Repello SkillCheck's product surface, not
  ours. Add later only if we ship a server-side scanner product.
- **MCP server scanning.** Out of scope for this spec; covered (today
  partially) by `internal/mcpinspect/`. A future spec may unify the
  two under a shared interface.
- **Runtime monitoring of skill execution.** This spec covers
  install-time gating only. Runtime enforcement remains a
  seccomp/landlock concern.
- **Repello and Chainguard real integrations.** Stubs only in v1
  because neither exposes a public API today (Snyk acquired Invariant
  but the merged hosted API is "contact us"; Chainguard Agent Skills
  is beta-gated; Repello SkillCheck has only a browser scanner
  publicly).
- **Building or publishing a registry.** We are a consumer, not a
  publisher.

## Trigger Decisions

Two triggers, two reasons:

- **fsmonitor on watch roots** catches every install path including
  manual `cp` and `git clone`. Fires on `SKILL.md` landing inside a
  fresh dir under `~/.claude/skills/` or `~/.claude/plugins/*/skills/`.
  Post-write trigger — see "Quarantine" below for the race-window
  argument.
- **`agentsh skillcheck` CLI** is a fall-through for explicit hook
  integrations (Claude Code `SessionStart`/`PreToolUse`) and manual
  audits.

Both feed the same pipeline. The CLI is also the only way to
quarantine/restore from outside the daemon.

## Artifact Decisions

**Format scope:** Claude Code skill directories only (`SKILL.md` +
supporting files). Plugin-bundled skills are covered transparently
because their on-disk layout is structurally identical to user-installed
skills; the only difference is the watch root.

Web zips and other skill formats are deferred (see Non-Goals).

## Architecture

```
              fsmonitor watch                 agentsh skillcheck <path>
                ~/.claude/skills/                       │
                ~/.claude/plugins/*/skills/             │
                       │                                │
                       ▼                                ▼
            debounce + classify (new SKILL.md)   load skill from path
                       │                                │
                       └────────────┬───────────────────┘
                                    ▼
                    loader: build SkillRef
                    (canonical SHA, manifest, file map, origin)
                                    ▼
                            cache lookup by SHA256
                                    │
                          ┌─────────┴──────────┐
                        hit                    miss
                          │                    │
                          │                    ▼
                          │       orchestrator.ScanAll
                          │       (providers in parallel,
                          │        per-provider timeout/OnFailure)
                          │                    │
                          │                    ▼
                          │       persist findings to cache
                          └─────────┬──────────┘
                                    ▼
                    evaluator: severity + provenance → action
                                    ▼
                    action layer: allow / warn / approve / block
                                    ▼
                    audit event + trash on block
```

### Package layout

```
internal/skillcheck/
  doc.go
  types.go            # SkillRef, ScanRequest, ScanResponse, Finding,
                      # Verdict, VerdictAction, FindingType, Severity
  loader.go           # walk dir, parse SKILL.md, hash, detect git origin
  loader_test.go
  watcher.go          # wraps internal/fsmonitor; debounce; glob plugin paths
  watcher_test.go
  orchestrator.go     # mirrors pkgcheck/orchestrator.go
  orchestrator_test.go
  evaluator.go        # severity + provenance → action
  evaluator_test.go
  action.go           # allow/warn/approve/block dispatch
  action_test.go
  cache/              # mirrors pkgcheck/cache, content-addressed
    cache.go
    cache_test.go
  cli.go              # `agentsh skillcheck {scan, scan --all, list-quarantined,
                      # restore, doctor, cache prune}`
  cli_test.go
  daemon.go           # wires watcher + orchestrator into long-running daemon
  daemon_test.go
  provider.go         # CheckProvider interface
  provider/
    local.go          # built-in offline rule engine
    local_test.go
    snyk.go           # subprocess wrapper for snyk-agent-scan
    snyk_test.go
    skills_sh.go      # HTTP-based provenance lookup
    skills_sh_test.go
    chainguard.go     # v2 stub returning "not yet implemented"
    chainguard_test.go
    repello.go        # v2 stub returning "not yet implemented"
    repello_test.go
  testdata/
    skills/           # fixture skills covering rule positive/negative cases,
                      # OWASP Agentic Skills Top 10 patterns, oversized,
                      # broken frontmatter, git-cloned, non-git
    snyk-agent-scan-fake  # canned-JSON fake CLI for snyk subprocess tests
    skills_sh/        # canned HTTP responses for HEAD-mode and __NEXT_DATA__
                      # parsing tests
```

## Core Types

```go
// SkillRef identifies a single skill on disk.
type SkillRef struct {
    Name     string         // dir name, e.g. "supply-chain-guard"
    Source   string         // "user" | "plugin:<plugin-name>" | "explicit"
    Path     string         // absolute path on disk
    SHA256   string         // hash of canonical file tree (cache key)
    Origin   *GitOrigin     // nil if not a git checkout
    Manifest SkillManifest  // parsed SKILL.md frontmatter
}

type GitOrigin struct {
    URL string // canonical https URL, e.g. "https://github.com/owner/repo"
    Ref string // commit SHA at time of scan
}

type SkillManifest struct {
    Name        string
    Description string
    Allowed     []string // tools/permissions declared in frontmatter
    Source      string   // optional `source:` field, used as fallback for Origin
}

type ScanRequest struct {
    Skill  SkillRef
    Files  map[string][]byte // relative-path -> contents (size-capped)
    Config map[string]string
}

type ScanResponse struct {
    Provider string
    Findings []Finding
    Metadata ResponseMetadata
}

type Finding struct {
    Type     FindingType
    Provider string
    Skill    SkillRef
    Severity Severity
    Title    string
    Detail   string
    Reasons  []Reason
    Links    []string
    Metadata map[string]string
}

type FindingType string

const (
    FindingPromptInjection  FindingType = "prompt_injection"
    FindingExfiltration     FindingType = "exfiltration"
    FindingHiddenUnicode    FindingType = "hidden_unicode"
    FindingMalware          FindingType = "malware"
    FindingPolicyViolation  FindingType = "policy_violation"  // scope mismatch
    FindingCredentialLeak   FindingType = "credential_leak"
    FindingProvenance       FindingType = "provenance"        // positive signal
)

// Severity, Reason, ResponseMetadata, VerdictAction, Verdict, PackageVerdict-equivalent
// (SkillVerdict): identical shape to pkgcheck/types.go; reproduced verbatim except
// PackageRef → SkillRef.
```

`CheckProvider`:

```go
type CheckProvider interface {
    Name() string
    Capabilities() []FindingType
    Scan(ctx context.Context, req ScanRequest) (*ScanResponse, error)
}
```

`ProviderEntry { Provider, Timeout, OnFailure }` and `Orchestrator.ScanAll`
are direct copies of the `pkgcheck` equivalents with `CheckRequest`
renamed to `ScanRequest`.

## Loader

Given a skill directory:

1. Walk the tree depth-first; reject if total size > `total_bytes`
   limit (default 4 MiB) — emit a `policy_violation` finding instead
   of failing the scan.
2. For each file: reject contents above `per_file_bytes` (default
   256 KiB) with the same finding-emission semantics.
3. Read `SKILL.md`; parse YAML/Markdown frontmatter into
   `SkillManifest`.
4. Detect git origin if a `.git/` directory or symlinked repo root is
   present. Read `origin` remote URL and current `HEAD` commit. Fallback
   to `manifest.Source` if no `.git`. Leave `Origin` nil if neither
   resolves.
5. Compute canonical SHA256: sort relative paths, hash
   `len(path) || path || len(content) || content` for each file in
   sequence. Stable across re-clones because it ignores filesystem
   metadata.
6. Return `SkillRef` and the file map for the providers.

## Watcher

Wraps `internal/fsmonitor` with two roots:
- `~/.claude/skills/` (literal)
- `~/.claude/plugins/*/skills/` (glob — re-evaluated when a new plugin
  dir is created)

Event filtering:
- Only fire on `SKILL.md` close-write or rename-into events.
- 500ms debounce per skill dir to coalesce git-clone bursts.
- Suppress events whose target skill SHA is in the per-session
  restore-allowlist (set by `restore` command).

Robustness:
- On daemon startup, walk both roots once and enqueue any skill not
  present in the cache (catches installs that happened while daemon
  was down).
- Re-glob plugin path on each new plugin dir creation event.

## Cache

Content-addressed by `SHA256`. Entry stores: per-provider findings,
final verdict, scan timestamp. TTL configurable (default 24h).
Identical pattern to `internal/pkgcheck/cache`.

User-approved skills (from the `approve` verdict path) get a separate
allowlist record keyed by SHA, persisted across daemon restarts, that
short-circuits future scans of the same content.

## Providers

### `local` — built-in offline rule engine

Native Go, always runs, no network. Detects:

| Rule | Severity | Detail |
|---|---|---|
| Hidden Unicode (Tag chars U+E0000–U+E007F, bidi overrides U+202A–U+202E, zero-width joiners) | high | Documented agent-skill attack vector ([Embrace The Red][etr]) |
| Embedded base64 blob > 1 KiB in any file | medium | Often exfil payload; bumped to high if blob decodes to executable bytes |
| Shell snippet that `eval`s an env var or HTTP response | high | Direct RCE pattern |
| Subprocess invocation not declared in `Allowed:` frontmatter | medium | Scope-creep / undeclared capability |
| Prompt-injection markers in skill body (`ignore previous instructions`, `<system>`, etc.) | medium | OWASP Agentic Top 10 signal |
| `Allowed:` declares `read-only` but body contains `rm`, `curl -X POST`, etc. | high | Permission-scope mismatch |

`Capabilities()` returns all rule types.
`OnFailure: deny` (default) — local should never fail; if it does,
fail closed.

### `snyk` — subprocess wrapper

Resolution order at startup and on each scan:
1. `config.providers.snyk.binary_path` (explicit override)
2. `snyk-agent-scan` on `PATH`
3. `uvx snyk-agent-scan@latest` (if `uvx` is on `PATH`)

If none resolve **and** the provider is enabled:
- Emit one `skillcheck.provider_unavailable` audit event at daemon
  startup (deduped across the session).
- Each scan returns `ScanResponse{ Metadata: { Error: "snyk: no
  executable found" } }`. The orchestrator's `OnFailure` handles the
  rest (recommended default `OnFailure: warn` for snyk).
- `agentsh skillcheck doctor` reports the failure with remediation
  text ("install uvx via `pipx install uv`, or run `pipx install
  snyk-agent-scan` and set `providers.snyk.binary_path`").

Invocation: `<resolved> --skills <skill-dir> --json` with
`ProviderEntry.Timeout` (default 60s — uvx cold-start is slow).

JSON parsing: version-tolerant. Unknown fields → ignored. Required
fields missing → `Metadata.Partial: true` plus a single
`Reason{ Code: "snyk_schema_drift" }`. Pin the schema at first
bring-up by running the tool once and committing the observed envelope
shape into the parser.

### `skills_sh` — provenance lookup

Two modes, controlled by `providers.skills_sh.probe_audits`:

**Default mode (provenance only):**
1. Skip if `SkillRef.Origin == nil` — `Capabilities()` returns `[]`
   for that scan.
2. From `Origin.URL`, derive the skills.sh canonical URL:
   `https://skills.sh/<owner>/<repo>/<skill-name>`.
3. HTTP HEAD with timeout (default 10s).
4. `200 OK` → emit `Finding{ Type: provenance, Severity: info,
   Title: "Registered on skills.sh", Reasons: [{Code: "skills_sh_registered"}] }`.
5. `404` → no finding (neutral signal).
6. Other status / error → `Metadata.Error` set; `OnFailure: allow` by
   default (missing provenance is not itself a finding).

**Probe-audits mode (opt-in):**
- HTTP GET instead of HEAD.
- Parse the `<script id="__NEXT_DATA__">` tag (standard Next.js
  embed) for the audit-result props (Snyk, Socket, Gen Agent Trust
  Hub pass/fail).
- Emit one `provenance` finding per audit, severity = info on pass,
  high on fail. (Still positive findings — interpretation is in the
  evaluator.)
- If `__NEXT_DATA__` is missing or malformed → degrade silently to
  default-mode behavior; emit an audit event
  `skillcheck.skills_sh_probe_failed` (deduped per skill).

### `chainguard` (v2 stub)

File exists with `CheckProvider` interface implemented:
```go
func (p *chainguardProvider) Capabilities() []FindingType { return nil }
func (p *chainguardProvider) Scan(ctx context.Context, req ScanRequest) (*ScanResponse, error) {
    return &ScanResponse{
        Provider: p.Name(),
        Metadata: ResponseMetadata{ Error: "chainguard: not yet implemented (beta access pending)" },
    }, nil
}
```
Config gates it `enabled: false` by default. Single test asserts the
documented response. When Chainguard publishes the catalog format,
implement a `internal/skillcheck/chainguard/syncer.go` (mirror
`internal/threatfeed/syncer.go`) and replace the stub.

### `repello` (v2 stub)

Identical structure to the chainguard stub. Replace when Repello
publishes documented REST API.

## Evaluator

```
findings → group by skill →
  1. base = max(severity of all non-provenance findings)
  2. provenance adjustment:
       all skills_sh audits pass        → -1 step
       any skills_sh audit fail         → +1 step
       not registered (or HEAD-only)    → no change
  3. severity → action via configured threshold table:
       info     → allow
       low      → allow (configurable warn)
       medium   → warn
       high     → approve
       critical → block
```

Threshold table is fully configurable per `pkgcheck` precedent.

## Action Layer

| Verdict | Action |
|---|---|
| `allow` | No-op |
| `warn` | Emit `skillcheck.scan_completed` audit event with the warn verdict |
| `approve` | Block on `internal/approval` prompt; on deny → `block`; on approve → cache the SHA in user-approved allowlist (skip future re-scans of identical content) |
| `block` | `trash.Move(skillDir, reason)` via `internal/trash`; emit `skillcheck.quarantined` with trash record ID |

Race window note: fsmonitor is post-write, so a malicious skill
could be loaded by a concurrently-running Claude session in the
narrow window between `SKILL.md` landing and quarantine completing.
This is acceptable because:
1. Quarantine still removes the skill before any *future* session loads
   it.
2. Most installs happen between sessions (`git clone`, then start
   Claude).
3. The alternative — pre-write blocking — would require wrapping every
   possible install command, which is intractable for this artifact
   class (unlike npm/pip where a single binary is the chokepoint).

The design accepts this trade-off and documents it.

## CLI Surface

```
agentsh skillcheck scan <path>          # one-off scan, prints verdict
agentsh skillcheck scan --all           # walk both watch roots
agentsh skillcheck list-quarantined     # show quarantined skills
agentsh skillcheck restore <skill-name> # restore from trash + add to
                                        # restore-allowlist for the
                                        # next watcher event
agentsh skillcheck doctor               # provider availability report
agentsh skillcheck cache prune          # clear cache
```

`scan` and `scan --all` exit non-zero on `block` (for hook
integrations: a Claude Code `SessionStart` hook can call
`agentsh skillcheck scan --all` and abort startup if any skill is
blocked).

## Audit Events

New event family `skillcheck.*` in `internal/audit`:

| Event | Fields |
|---|---|
| `skillcheck.scan_started` | skill_ref, providers_selected |
| `skillcheck.scan_completed` | skill_ref, findings[], verdict |
| `skillcheck.provider_unavailable` | provider, reason (deduped per startup) |
| `skillcheck.quarantined` | skill_ref, verdict, trash_record_id |
| `skillcheck.restored` | skill_ref, trash_record_id |
| `skillcheck.user_approved` | skill_ref, sha, user_id |
| `skillcheck.skills_sh_probe_failed` | skill_ref, reason (deduped per skill) |

Routed through the existing audit sink alongside `pkgcheck.*` events.

## Configuration

```yaml
skillcheck:
  enabled: true
  watch_roots:
    - ~/.claude/skills
    - ~/.claude/plugins/*/skills
  scan_size_limits:
    per_file_bytes: 262144      # 256 KiB
    total_bytes: 4194304        # 4 MiB
  thresholds:
    low: allow
    medium: warn
    high: approve
    critical: block
  cache:
    ttl: 24h
  providers:
    local:
      enabled: true
      timeout: 5s
      on_failure: deny
    snyk:
      enabled: true
      timeout: 60s
      on_failure: warn
      binary_path: ""           # empty → auto-resolve via uvx/PATH
    skills_sh:
      enabled: true
      timeout: 10s
      on_failure: allow         # missing provenance is not a finding
      probe_audits: false       # opt-in __NEXT_DATA__ parsing
    chainguard:
      enabled: false            # v2 stub
    repello:
      enabled: false            # v2 stub
```

## Testing Strategy

| Component | Tests |
|---|---|
| `local` | Table-driven per rule (positive + negative). Golden fixtures in `testdata/skills/` covering OWASP Agentic Skills Top 10 patterns. |
| `snyk` | Fake CLI binary fixture (`testdata/snyk-agent-scan-fake`) emitting canned JSON. Cases: success, schema drift (unknown fields), exit-code variants, timeout, binary-not-found alert path, all three resolution branches. |
| `skills_sh` | `httptest.NewServer` returning canned responses. Cases: 200/404, malformed HTML, missing `__NEXT_DATA__`, timeout, audit-badge state matrix. |
| `chainguard` / `repello` stubs | Single test confirming "not yet implemented" response. |
| `loader` | Fixtures for: minimal valid skill, oversized skill, deep dir tree, broken frontmatter, git-cloned skill (origin detection), non-git skill, skill with `source:` frontmatter fallback. |
| `watcher` | Synthetic fsmonitor events via in-process channel. Cases: skill landing, partial-write coalescing, plugin glob expansion, restore-allowlist suppression, daemon-startup catch-up. |
| `evaluator` | Table-driven over `(severity, provenance)` matrix → expected action. |
| `orchestrator` | Reuse `pkgcheck` test patterns. |
| `cache` | Reuse `pkgcheck/cache` test patterns. |
| `action` | Mock `trash` and `approval`; assert correct dispatch + audit events per verdict. |
| Integration | Drop a malicious fixture skill into a temp watch root; assert `quarantined` audit + skill removed + restore round-trip + no re-quarantine after restore. |

Cross-platform: per `CLAUDE.md`, verify `GOOS=windows go build ./...`
succeeds. `internal/fsmonitor` is already cross-platform; no new
platform-specific code expected.

## Open Questions / Future Work

- **Snyk hosted API.** Reach out to Snyk for the merged
  Snyk+Invariant hosted API (post-acquisition). When granted, swap the
  subprocess adapter for an HTTP one without touching the rest of the
  system.
- **Chainguard beta access.** Request beta access in parallel with v1
  shipping. Replace the stub when the catalog format is published.
- **Repello REST API.** Same — request access; replace stub.
- **`npx skills` CLI subprocess mode for skills_sh.** If/when the
  Vercel CLI exposes a non-mutating `inspect` or `audit` query
  command, add a third skills.sh mode (subprocess) parallel to the
  Snyk integration. Until then, HEAD-only and `__NEXT_DATA__`
  parsing are the only verified paths.
- **Unify with `internal/mcpinspect/`.** A future spec may extract a
  shared interface for "agent component scanner" covering both skills
  and MCP servers.
