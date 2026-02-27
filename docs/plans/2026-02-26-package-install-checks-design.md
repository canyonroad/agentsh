# Package Install Checks — Design Document

**Date:** 2026-02-26
**Status:** Draft
**Author:** Brainstorm session

## 1. Problem Statement

AI coding agents running under AgentSH routinely install packages — `npm install`,
`pip install`, `poetry add` — as part of their workflow. These installs are
unsupervised by default: the agent decides what to install based on LLM reasoning,
documentation it read, or Stack Overflow snippets.

This creates a unique threat surface:

1. **The agent has no security judgment.** It will install `event-stream@3.3.6` if a
   tutorial says to.
2. **The agent can be manipulated.** Prompt injection, poisoned documentation, or
   malicious MCP tool responses can direct it to install attacker-chosen packages.
3. **The blast radius is high.** npm/PyPI install scripts run arbitrary code at
   install time — before any application code executes.
4. **The attack is invisible.** A transitive dependency pulled in silently can contain
   malware, and the agent won't notice.

### Threat Model

| Threat | Vector | Impact |
|--------|--------|--------|
| Known vulnerability | Agent installs package with published CVE | Code execution, data exfil |
| Typosquat / dependency confusion | LLM hallucinates package name; attacker registers it | Malware at install time |
| Install script attack | `postinstall` (npm) or `setup.py` runs malware | Arbitrary code execution |
| License violation | Agent adds AGPL dep to proprietary codebase | Legal/compliance risk |
| Supply-chain compromise | Maintainer account compromised; new version contains malware | Malware in trusted package |
| Exfiltration via dependency | Package phones home with env vars, source code, tokens | Data theft |
| Prompt-injection-driven install | Poisoned docs tell agent to `pip install evil-helper` | Agent installs attacker's package |
| Stale/abandoned package | Agent picks unmaintained package | Long-term vulnerability exposure |

### What This Feature Does

Inserts a policy checkpoint between the agent's intent to install a package and the
actual execution of the install command. The checkpoint resolves the full install plan,
evaluates it against multiple security/compliance providers, and returns a verdict
before the package manager touches disk or network.

---

## 2. Design Decisions

All decisions were made during the brainstorm session. Refer to this table for context
on why each approach was chosen.

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Interception point | Command-level primary + network-level backstop | Command gives intent + UX; network catches bypasses (curl-to-pip, programmatic installs) |
| 2 | Install plan resolution | Shell out to package manager dry-run | Real resolver handles complex version constraints; avoids reimplementing npm/pip resolution |
| 3 | Provider plugin boundary | In-process built-ins + exec protocol for custom | Fast defaults; extensible for proprietary scanners |
| 4 | Transitive depth | Direct deps: full checks. Transitives: bulk vuln APIs | OSV/npm-audit batch endpoints handle hundreds of packages in one call |
| 5 | Caching | TTL-based disk cache (Watchtower replaces later) | Simple; effective; license/provenance entries get long TTL since they're immutable per version |
| 6 | Private packages | Configurable per-registry trust policy | Customers control what leaks where; safe default for unknown registries |
| 7 | Install scope | Intercept all, configurable to `new_packages_only` (default) | Don't re-scan lockfiles that CI tools already cover; Watchtower handles proactive scanning later |
| 8 | Approval UX | Extended payload through existing ApprovalManager | Informed decisions; no new infrastructure |
| 9 | Provider failure | Per-provider `on_failure` with sensible defaults | Free providers: warn. Paid providers: approve. Avoids brittleness |
| 10 | Network backstop | Allowlist gate — command check produces approved set | No duplicate API calls; blocks bypass attempts |
| 11 | Policy engine integration | Hybrid: CommandRules trigger, PackageRules define policy | Mirrors MCP inspector pattern |
| 12 | MVP vendors | OSV.dev, deps.dev, local scan, Socket.dev, Snyk | Three free + two keyed; useful out of the box |

---

## 3. Architecture

### High-Level Flow

```
Agent issues command: "npm install express"
        |
        v
+---------------------+
|  Shell Shim/Seccomp  |  <- Intercepts command
|  (existing infra)    |
+--------+------------+
         | recognized as install command
         v
+---------------------+
|  Install Interceptor |  <- Classifies command, selects resolver
+--------+------------+
         |
         v
+---------------------+
|  Resolver            |  <- Runs dry-run in sandbox, produces InstallPlan
|  (per-tool)          |     e.g., npm install --package-lock-only
+--------+------------+
         | InstallPlan{direct: [express@5.1.0], transitive: [accepts@2.0.0, ...]}
         v
+---------------------+
|  PackageRules        |  <- Static allowlist/denylist check (fast path)
|  (policy engine)     |     "always allow express" / "always block event-stream"
+--------+------------+
         | packages not matched by static rules
         v
+---------------------+
|  Check Orchestrator  |  <- Fans out to providers in parallel
|                      |     Merges results into unified findings
+--------+------------+
    +----+----+----+----+
    v    v    v    v    v
  OSV  deps  Local Socket Snyk   <- Providers (+ exec-protocol custom)
  .dev .dev  Scan  .dev
    |    |    |    |    |
    +----+----+----+----+
         | []Finding
         v
+---------------------+
|  Policy Evaluator    |  <- Applies policy rules to findings
+--------+------------+
         | Verdict{allow|warn|approve|block}
         v
+---------------------+
|  Verdict Handler     |  <- allow: proceed + audit
|                      |     warn: proceed + display + audit
|                      |     approve: invoke ApprovalManager
|                      |     block: deny command + display + audit
+--------+------------+
         | if allowed/approved
         v
+---------------------+
|  Network Allowlist   |  <- Write approved (pkg, version) tuples
|                      |     Network layer enforces during install
+---------------------+
         |
         v
   Original command executes
```

### Component Responsibilities

| Component | Package | Responsibility |
|-----------|---------|---------------|
| Install Interceptor | `internal/pkgcheck/interceptor.go` | Recognizes install commands, extracts args, routes to resolver |
| Resolver | `internal/pkgcheck/resolver/` | Per-tool implementations; runs dry-run, parses output into `InstallPlan` |
| Check Orchestrator | `internal/pkgcheck/orchestrator.go` | Provider lifecycle, parallel checks, timeouts, result merging |
| Provider | `internal/pkgcheck/provider/` | Each implements `CheckProvider`. Built-ins: `osv`, `depsdev`, `local`, `socket`, `snyk` |
| Policy Evaluator | `internal/pkgcheck/evaluator.go` | Applies `PackageRules` to merged findings, produces final `Verdict` |
| Network Allowlist | `internal/pkgcheck/allowlist.go` | Short-lived in-memory approved set, consulted by network interceptor |

### Integration Points With Existing Code

1. **`internal/policy/model.go`** — add `PackageRules []PackageRule` and `PackageCheckConfig`
2. **`internal/policy/engine.go`** — install command detection delegates to package check subsystem
3. **`internal/events/types.go`** — new events: `PackageCheckStarted`, `PackageCheckCompleted`, `PackageBlocked`, `PackageApproved`, `PackageWarning`, `ProviderError`
4. **`internal/config/config.go`** — add `PackageChecks PackageChecksConfig` to `Config`
5. **Network interceptor** (`internal/platform/*/network.go`) — consult allowlist for registry domains

### Supported Tools

| Ecosystem | Tools | Resolver Command |
|-----------|-------|-----------------|
| npm | `npm install`, `pnpm add`, `yarn add` | `npm install --package-lock-only`, `pnpm install --lockfile-only`, `yarn install --mode update-lockfile` |
| PyPI | `pip install`, `uv pip install`, `uv add`, `poetry add` | `pip install --dry-run --report -`, `uv pip install --dry-run`, `uv lock`, `poetry lock --no-update` |

---

## 4. Interfaces & Data Structures

### Resolver Interface

```go
// internal/pkgcheck/resolver/resolver.go

type Resolver interface {
    // Name returns the tool name (e.g., "npm", "pnpm", "pip", "uv")
    Name() string

    // CanResolve returns true if this resolver handles the given command.
    CanResolve(command string, args []string) bool

    // Resolve runs dry-run resolution and returns the install plan.
    Resolve(ctx context.Context, command string, args []string, workDir string) (*InstallPlan, error)
}

type InstallPlan struct {
    Tool       string       // "npm", "pnpm", "yarn", "pip", "uv", "poetry"
    Ecosystem  string       // "npm" or "pypi"
    WorkDir    string       // directory where install was invoked
    Command    string       // original command string
    Direct     []PackageRef // explicitly requested packages
    Transitive []PackageRef // resolved transitive dependencies
    Registry   string       // registry URL used for resolution
    ResolvedAt time.Time
}

type PackageRef struct {
    Name     string // e.g., "express", "requests"
    Version  string // exact resolved version, e.g., "5.1.0"
    Registry string // which registry this comes from
    Direct   bool   // true if explicitly requested by the agent
}
```

### Provider Interface

```go
// internal/pkgcheck/provider/provider.go

type CheckProvider interface {
    // Name returns a unique identifier (e.g., "osv", "depsdev", "socket")
    Name() string

    // Capabilities declares what finding types this provider returns.
    Capabilities() []FindingType

    // CheckBatch evaluates a batch of packages and returns findings.
    CheckBatch(ctx context.Context, req *CheckRequest) (*CheckResponse, error)
}

type CheckRequest struct {
    Ecosystem string
    Packages  []PackageRef
    Config    ProviderConfig
}

type CheckResponse struct {
    Provider string
    Findings []Finding
    Metadata ResponseMetadata
}

type ResponseMetadata struct {
    Duration    time.Duration
    FromCache   bool
    RateLimited bool
    Partial     bool   // true if provider couldn't check all packages
    Error       string // non-fatal error
}
```

### Unified Finding Schema

```go
// internal/pkgcheck/finding.go

type FindingType string

const (
    FindingVulnerability FindingType = "vulnerability"
    FindingLicense       FindingType = "license"
    FindingProvenance    FindingType = "provenance"
    FindingReputation    FindingType = "reputation"
    FindingMalware       FindingType = "malware"
)

type Finding struct {
    Type      FindingType
    Provider  string     // which provider produced this
    Package   PackageRef
    Severity  Severity   // critical, high, medium, low, info
    Title     string     // human-readable summary
    Detail    string     // longer explanation
    Reasons   []Reason   // machine-readable reasons for policy evaluation
    Links     []string   // CVE URLs, advisory links
    Metadata  map[string]any
}

type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type Reason struct {
    Code    string // machine-readable: "vuln_no_fix", "license_denied", "typosquat"
    Message string // human-readable explanation
}
```

### Verdict

```go
// internal/pkgcheck/verdict.go

type VerdictAction string

const (
    VerdictAllow   VerdictAction = "allow"
    VerdictWarn    VerdictAction = "warn"
    VerdictApprove VerdictAction = "approve"
    VerdictBlock   VerdictAction = "block"
)

type Verdict struct {
    Action   VerdictAction
    Findings []Finding
    Summary  string                      // human-readable one-liner
    Packages map[string]PackageVerdict   // per-package, keyed by "name@version"
}

type PackageVerdict struct {
    Package  PackageRef
    Action   VerdictAction
    Findings []Finding
}
```

### Exec Protocol for Custom Providers

Custom providers are executables that speak JSON over stdin/stdout:

**Input (stdin):**
```json
{
  "ecosystem": "npm",
  "packages": [{"name": "express", "version": "5.1.0"}],
  "config": {"custom_key": "value"}
}
```

**Output (stdout):**
```json
{
  "provider": "acme-internal-scanner",
  "findings": [
    {
      "type": "license",
      "package": {"name": "express", "version": "5.1.0"},
      "severity": "info",
      "title": "MIT license detected",
      "reasons": [{"code": "license_allowed", "message": "MIT is in allow list"}]
    }
  ],
  "metadata": {"duration_ms": 42}
}
```

**Exit codes:** 0 = success, 1 = partial results (check stderr), 2 = total failure.

---

## 5. Configuration Schema

### Operational Config (`agentsh.yaml`)

```yaml
package_checks:
  enabled: true
  scope: new_packages_only  # "new_packages_only" | "all_installs"

  cache:
    dir: "${DATA_DIR}/pkgcache"
    ttl:
      vulnerability: 24h
      license: 168h        # 7 days — immutable per version
      provenance: 168h
      reputation: 72h      # 3 days
      malware: 12h
    max_size_mb: 500

  registries:
    "https://registry.npmjs.org":
      trust: check_full
    "https://pypi.org":
      trust: check_full
    "https://npm.pkg.github.com":
      trust: check_full
    "https://npm.internal.acme.com":
      trust: check_local_only
      scopes: ["@acme"]
    default:
      trust: check_local_only

  providers:
    osv:
      enabled: true
      priority: 1
      timeout: 10s
      on_failure: warn

    depsdev:
      enabled: true
      priority: 2
      timeout: 10s
      on_failure: warn

    local:
      enabled: true
      priority: 0
      on_failure: warn

    socket:
      enabled: false
      priority: 3
      timeout: 15s
      on_failure: approve
      api_key_env: SOCKET_API_KEY
      options:
        detect_typosquats: true
        detect_install_scripts: true

    snyk:
      enabled: false
      priority: 4
      timeout: 15s
      on_failure: approve
      api_key_env: SNYK_TOKEN
      options:
        org_id_env: SNYK_ORG_ID

    # Custom exec-protocol provider example
    acme-compliance:
      enabled: false
      type: exec
      command: /usr/local/bin/acme-pkg-check
      timeout: 30s
      on_failure: deny
      priority: 5

  resolvers:
    npm:
      dry_run_command: "npm install --package-lock-only --ignore-scripts"
      timeout: 60s
    pnpm:
      dry_run_command: "pnpm install --lockfile-only --ignore-scripts"
      timeout: 60s
    yarn:
      dry_run_command: "yarn install --mode update-lockfile"
      timeout: 60s
    pip:
      dry_run_command: "pip install --dry-run --report -"
      timeout: 60s
    uv:
      dry_run_command: "uv pip install --dry-run"
      timeout: 30s
    poetry:
      dry_run_command: "poetry lock --no-update"
      timeout: 60s
```

### Policy Rules (policy YAML files)

```yaml
package_rules:
  # --- Static allowlists/denylists (evaluated before providers) ---

  - match:
      packages:
        - "typescript"
        - "eslint"
        - "prettier"
        - "pytest"
        - "black"
        - "ruff"
    action: allow
    reason: "Trusted development tooling"

  - match:
      packages:
        - "event-stream@3.3.6"
        - "ua-parser-js@0.7.29"
        - "coa@2.0.3"
    action: deny
    reason: "Known supply-chain compromise"

  - match:
      name_patterns:
        - "^(lodash|express|react)[_-]\\w{1,3}$"
        - ".*-malware.*"
    action: deny
    reason: "Package name matches typosquat pattern"

  # --- Vulnerability rules ---

  - match:
      finding_type: vulnerability
      severity: [critical]
      reasons: [vuln_no_fix]
    action: deny
    reason: "Critical vulnerability with no available fix"

  - match:
      finding_type: vulnerability
      severity: [critical, high]
    action: deny
    reason: "High/critical vulnerability — use a patched version"

  - match:
      finding_type: vulnerability
      severity: [medium]
    action: warn
    reason: "Medium vulnerability — review before using"

  # --- License rules ---

  - match:
      finding_type: license
      license_spdx:
        allow: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0,
                Unlicense, 0BSD, BlueOak-1.0.0]
    action: allow
    reason: "Permissive license"

  - match:
      finding_type: license
      license_spdx:
        deny: [AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0, EUPL-1.1, EUPL-1.2]
    action: deny
    reason: "Copyleft/viral license incompatible with proprietary code"

  - match:
      finding_type: license
      license_spdx:
        deny: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later,
               LGPL-2.1-only, LGPL-3.0-only, MPL-2.0]
    action: approve
    reason: "Copyleft license — requires legal review"

  - match:
      finding_type: license
      reasons: [license_unknown, license_missing]
    action: warn
    reason: "No license detected — verify manually"

  # --- Reputation / provenance rules ---

  - match:
      finding_type: reputation
      reasons: [package_too_new]
      options:
        max_age_days: 30
    action: approve
    reason: "Package published less than 30 days ago"

  - match:
      finding_type: reputation
      reasons: [low_scorecard]
      options:
        min_score: 4.0
    action: warn
    reason: "Low OpenSSF Scorecard score"

  - match:
      finding_type: malware
    action: deny
    reason: "Malware detected by provider"

  - match:
      finding_type: reputation
      reasons: [typosquat]
    action: deny
    reason: "Package flagged as potential typosquat"

  # --- Per-ecosystem overrides ---

  - match:
      ecosystem: pypi
      finding_type: reputation
      reasons: [has_install_script]
    action: warn
    reason: "Package has setup.py with arbitrary code execution"

  - match:
      ecosystem: npm
      finding_type: reputation
      reasons: [has_install_script, has_network_access]
    action: deny
    reason: "Install script with network access"

  # --- Default ---

  - match: {}
    action: allow
    reason: "No issues found"
```

### Config Notes

- **`scope`** — `new_packages_only` (default) gates `npm install foo`, `pip install
  requests`, etc. `all_installs` also gates `npm ci`, `pip install -r requirements.txt`.
- **Provider `priority`** is display ordering only; all providers run in parallel.
- **`api_key_env`** references env var names, never raw keys in config.
- **`match` clauses** support static matching (package names, patterns) and
  finding-based matching (severity, SPDX IDs, reason codes).
- **First-match-wins** — consistent with all other rule types in AgentSH.
- **Final `match: {}`** catch-all ensures a verdict is always produced.

---

## 6. Hard Choices

| # | Choice | Recommendation | Rationale |
|---|--------|----------------|-----------|
| 1 | Default scope | `new_packages_only` | Customers have CI tools for lockfile scanning. Watchtower covers the rest later. |
| 2 | Default when no providers configured | `allow` + audit event | Feature is opt-in at the provider level. Don't brick workflows. |
| 3 | Default when all providers fail | `warn` | Provider outage shouldn't halt development. Strict customers override to `deny`. |
| 4 | Dry-run resolution fails | Let the install fail naturally | If the package doesn't exist, npm/pip will error anyway. |
| 5 | Conflicting findings across providers | Strictest finding wins | If OSV says clean but Socket says malware, respect the malware finding. |
| 6 | Transitive dep triggers `approve` | Block whole install, show which dep triggered it | Partial installs are fragile. |
| 7 | Private package not in any DB | Depends on registry trust level. `check_full` -> warn. `check_local_only`/`trusted` -> skip. | Different semantics for public vs private registry. |
| 8 | Package version already in lockfile | Skip if cached result exists and not expired | Avoids redundant checks. |
| 9 | Multiple versions of same package | Check all versions | Different versions have different vulns. |
| 10 | Resolver timeout | Block with clear error | No install plan = no informed decision. |
| 11 | Agent retries after block | Serve cached block within TTL | Deterministic behavior; prevents retry loops. |
| 12 | License on transitive vs direct | Same for deny-list; relaxed (warn) for weak copyleft on transitives | AGPL transitive is just as viral. MPL transitive approval would be too noisy. |

---

## 7. Agent UX

### Block

```
!! Package install blocked

  npm install event-stream@3.3.6

  BLOCKED - 2 findings:
  +- [CRITICAL] Malware: Backdoor in flatmap-stream@0.1.1 (transitive)
  |  CVE-2018-16487 - https://nvd.nist.gov/vuln/detail/CVE-2018-16487
  |  Provider: osv, socket
  +- [HIGH] Supply-chain compromise: Maintainer account hijacked
     Provider: socket

  Action: Choose a different package or request human approval.
```

### Warn

```
** Package install warning

  pip install requests==2.28.0

  ALLOWED with warnings - 1 finding:
  +- [MEDIUM] Vulnerability: CRLF injection in urllib3 dependency
     CVE-2023-43804 - Fix available in requests>=2.31.0
     Provider: osv

  Proceeding with install.
```

### Approval Required

```
?? Package install requires approval

  pnpm add new-shiny-lib@0.1.0

  APPROVAL REQUIRED - 2 findings:
  +- [INFO] Reputation: Package published 12 days ago
  |  Reason: package_too_new (threshold: 30 days)
  |  Provider: depsdev
  +- [INFO] License: MPL-2.0 detected
     Reason: Weak copyleft - requires legal review
     Provider: local

  Waiting for approval... (local_tty)
```

---

## 8. Caching Strategy

- **Storage:** SQLite or bbolt database in `${DATA_DIR}/pkgcache/`.
- **Key:** `(provider, ecosystem, package_name, version)`.
- **TTL per finding type:**
  - Vulnerability: 24h (advisory databases update frequently)
  - License: 168h / 7 days (immutable per published version)
  - Provenance: 168h / 7 days (immutable per published version)
  - Reputation: 72h / 3 days (scorecard scores change slowly)
  - Malware: 12h (new detections matter quickly)
- **Invalidation:** TTL-based only for MVP. Watchtower adds event-driven invalidation later.
- **Size limit:** Configurable max (default 500 MB), LRU eviction.
- **Privacy:** Cache stores findings locally. No package names sent to disk unencrypted
  beyond what the provider already returned. Private package names from `trusted` or
  `check_local_only` registries never leave the machine.

---

## 9. Security & Privacy

- **No leakage by default.** Unknown registries default to `check_local_only`. Only
  packages from explicitly `check_full` registries are sent to external providers.
- **API keys via env vars.** Config references `api_key_env: SOCKET_API_KEY`, never
  raw tokens. Keys are read at runtime, never written to disk or logs.
- **Redaction in audit logs.** If a private package name appears in an audit event,
  it is only included when the registry trust level permits it.
- **Sandboxed resolution.** Dry-run commands run inside the existing AgentSH sandbox
  with `--ignore-scripts` (npm/pnpm) or equivalent to prevent install-time code
  execution during resolution.
- **Exec-protocol isolation.** Custom provider executables receive only the package
  list on stdin. They do not inherit AgentSH's environment variables (API keys for
  other providers are stripped).

---

## 10. Testing Strategy

| Layer | Approach |
|-------|----------|
| Resolver parsing | Golden fixture tests: recorded dry-run output for each tool, assert correct `InstallPlan` |
| Provider API clients | Recorded HTTP responses (go-vcr or httptest). Test success, partial failure, timeout, rate-limit cases |
| Policy evaluation | Table-driven tests: `(findings, rules) -> expected verdict` for every rule type |
| Orchestrator | Mock providers with configurable delay/failure. Test parallel execution, timeout handling, `on_failure` behavior |
| Network allowlist | Integration test: install approved package succeeds, unapproved registry fetch is blocked |
| Exec protocol | Test with a sample shell script provider. Verify JSON round-trip, exit code handling |
| End-to-end | Docker-based test: agent runs `npm install express`, verify audit events, cache population, verdict |
| Cache | Unit tests: hit/miss/expiry/eviction. Timing assertions for cache hits |
| Config validation | Reject invalid SPDX IDs, unknown provider names, missing required fields |
| Cross-compilation | `GOOS=windows go build ./...` in CI |

---

## 11. MVP Scope

### In MVP

1. Install command interception for: `npm install`, `pnpm add`, `yarn add`,
   `pip install`, `uv pip install`, `uv add`, `poetry add`
2. Dry-run resolution for all six tools, producing standardized `InstallPlan`
3. Five built-in providers: OSV.dev, deps.dev, local metadata scan, Socket.dev, Snyk
4. Policy evaluation with `PackageRules` (static allow/deny, vuln severity, license
   SPDX, package age, malware/typosquat detection)
5. Four verdict actions: allow, warn, approve, block
6. Network allowlist gate for registry domains
7. TTL-based disk cache
8. Per-registry trust policy
9. Audit events for every check
10. Extended approval payload through existing ApprovalManager
11. Exec protocol for custom providers
12. Configurable `scope` and per-provider `on_failure`

### Deferred (Post-MVP)

| Feature | Target |
|---------|--------|
| Proactive lockfile scanning on session start | Watchtower |
| Vulnerability feed subscriptions | Watchtower |
| Event-driven cache invalidation | Watchtower |
| Full transitive dep checking (all providers) | Post-MVP config knob |
| Provider weight/trust scoring for conflicts | Post-MVP |
| Go modules, Cargo, Maven, Gem ecosystems | Post-MVP per demand |
| HTML approval report page | Post-MVP |
| SBOM generation from install plans | Post-MVP |
| `--force` bypass with audit trail | Post-MVP |
| Dependency pinning recommendations | Post-MVP |

---

## 12. Staged Roadmap

```
MVP (this design)
|-- Install interception for 6 tools (npm, pnpm, yarn, pip, uv, poetry)
|-- 5 built-in providers (3 free + 2 keyed)
|-- Policy evaluation with PackageRules
|-- Network allowlist backstop
|-- TTL disk cache
|-- Exec protocol for custom providers
+-- Audit events

Post-MVP
|-- Full transitive checking (opt-in knob)
|-- Dependency pinning recommendations
|-- Go modules + Cargo support
|-- Provider weight/trust scoring
|-- SBOM export from install plans
+-- --force bypass with audit trail

Watchtower Integration
|-- Proactive lockfile scanning
|-- Vulnerability feed subscriptions
|-- Event-driven cache invalidation
|-- Continuous monitoring dashboard
+-- Fleet-wide package policy analytics
```

---

## 13. MVP Definition of Done

- [ ] All six package managers intercepted and tested
- [ ] Dry-run resolution produces correct `InstallPlan` for each tool (golden fixtures)
- [ ] OSV, deps.dev, and local scan providers return correct findings (mock API tests)
- [ ] Socket and Snyk providers work when API keys provided (recorded response tests)
- [ ] Policy evaluation correct for: critical vuln -> block, medium vuln -> warn,
      AGPL -> block, unknown license -> warn, package < 30 days -> approve
- [ ] Cache hit skips provider calls (unit test with timing assertion)
- [ ] Network allowlist blocks registry fetch for non-approved package
- [ ] Approval flow shows package details, vuln info, license findings
- [ ] Audit events emitted for every verdict
- [ ] `on_failure: warn` degrades correctly when provider unreachable
- [ ] Private registry with `trust: check_local_only` does not leak names externally
- [ ] Exec-protocol custom provider JSON round-trip works
- [ ] Config validation rejects invalid SPDX IDs, unknown providers, missing fields
- [ ] Cross-compilation: `GOOS=windows go build ./...` passes
