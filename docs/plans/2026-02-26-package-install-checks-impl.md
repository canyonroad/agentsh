# Package Install Checks — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a policy layer that evaluates npm/PyPI packages before agents can install them, with pluggable security providers, configurable policy rules, and network-level enforcement.

**Architecture:** Command interception (shell shim/seccomp) triggers dry-run resolution via the real package manager, fans out to security providers in parallel (OSV, deps.dev, local scan, Socket, Snyk), merges findings against PackageRules, and returns a verdict (allow/warn/approve/block). A network allowlist gate enforces approved packages during the actual install.

**Tech Stack:** Go, YAML config, HTTP clients for provider APIs, SQLite/bbolt for cache, existing policy engine and approval infrastructure.

**Design doc:** `docs/plans/2026-02-26-package-install-checks-design.md`

---

## Phase 1: Foundation — Types, Config, Events, Policy Model

### Task 1: Core types package

**Files:**
- Create: `internal/pkgcheck/types.go`
- Test: `internal/pkgcheck/types_test.go`

**Step 1: Write the test**

```go
// internal/pkgcheck/types_test.go
package pkgcheck

import (
    "testing"
)

func TestPackageRefString(t *testing.T) {
    ref := PackageRef{Name: "express", Version: "5.1.0", Registry: "https://registry.npmjs.org"}
    if ref.String() != "express@5.1.0" {
        t.Errorf("got %q, want %q", ref.String(), "express@5.1.0")
    }
}

func TestVerdictHighestAction(t *testing.T) {
    tests := []struct {
        name     string
        packages map[string]PackageVerdict
        want     VerdictAction
    }{
        {"all allow", map[string]PackageVerdict{
            "a@1": {Action: VerdictAllow},
            "b@2": {Action: VerdictAllow},
        }, VerdictAllow},
        {"one warn", map[string]PackageVerdict{
            "a@1": {Action: VerdictAllow},
            "b@2": {Action: VerdictWarn},
        }, VerdictWarn},
        {"block wins", map[string]PackageVerdict{
            "a@1": {Action: VerdictWarn},
            "b@2": {Action: VerdictBlock},
        }, VerdictBlock},
        {"approve over warn", map[string]PackageVerdict{
            "a@1": {Action: VerdictWarn},
            "b@2": {Action: VerdictApprove},
        }, VerdictApprove},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            v := Verdict{Packages: tt.packages}
            if v.HighestAction() != tt.want {
                t.Errorf("got %q, want %q", v.HighestAction(), tt.want)
            }
        })
    }
}

func TestSeverityOrder(t *testing.T) {
    if SeverityCritical.Weight() <= SeverityHigh.Weight() {
        t.Error("critical should outweigh high")
    }
    if SeverityHigh.Weight() <= SeverityMedium.Weight() {
        t.Error("high should outweigh medium")
    }
}

func TestFindingTypeConstants(t *testing.T) {
    // Ensure all finding types are distinct
    types := []FindingType{FindingVulnerability, FindingLicense, FindingProvenance, FindingReputation, FindingMalware}
    seen := map[FindingType]bool{}
    for _, ft := range types {
        if seen[ft] {
            t.Errorf("duplicate finding type: %s", ft)
        }
        seen[ft] = true
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/pkgcheck/ -v -run TestPackageRef`
Expected: FAIL — package does not exist

**Step 3: Write the implementation**

```go
// internal/pkgcheck/types.go
package pkgcheck

import (
    "fmt"
    "time"
)

// Ecosystem represents a package ecosystem.
type Ecosystem string

const (
    EcosystemNPM  Ecosystem = "npm"
    EcosystemPyPI Ecosystem = "pypi"
)

// PackageRef identifies a specific package version.
type PackageRef struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Registry string `json:"registry,omitempty"`
    Direct   bool   `json:"direct,omitempty"`
}

func (p PackageRef) String() string {
    return fmt.Sprintf("%s@%s", p.Name, p.Version)
}

// InstallPlan is the resolved set of packages from a dry-run.
type InstallPlan struct {
    Tool       string       `json:"tool"`
    Ecosystem  Ecosystem    `json:"ecosystem"`
    WorkDir    string       `json:"work_dir"`
    Command    string       `json:"command"`
    Direct     []PackageRef `json:"direct"`
    Transitive []PackageRef `json:"transitive"`
    Registry   string       `json:"registry"`
    ResolvedAt time.Time    `json:"resolved_at"`
}

// AllPackages returns direct + transitive combined.
func (p *InstallPlan) AllPackages() []PackageRef {
    all := make([]PackageRef, 0, len(p.Direct)+len(p.Transitive))
    all = append(all, p.Direct...)
    all = append(all, p.Transitive...)
    return all
}

// FindingType categorizes a security/compliance finding.
type FindingType string

const (
    FindingVulnerability FindingType = "vulnerability"
    FindingLicense       FindingType = "license"
    FindingProvenance    FindingType = "provenance"
    FindingReputation    FindingType = "reputation"
    FindingMalware       FindingType = "malware"
)

// Severity represents the severity of a finding.
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

// Weight returns a numeric weight for ordering (higher = more severe).
func (s Severity) Weight() int {
    switch s {
    case SeverityCritical:
        return 4
    case SeverityHigh:
        return 3
    case SeverityMedium:
        return 2
    case SeverityLow:
        return 1
    case SeverityInfo:
        return 0
    default:
        return -1
    }
}

// Reason is a machine-readable reason code with human-readable message.
type Reason struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

// Finding represents a single security/compliance finding from a provider.
type Finding struct {
    Type     FindingType    `json:"type"`
    Provider string         `json:"provider"`
    Package  PackageRef     `json:"package"`
    Severity Severity       `json:"severity"`
    Title    string         `json:"title"`
    Detail   string         `json:"detail,omitempty"`
    Reasons  []Reason       `json:"reasons"`
    Links    []string       `json:"links,omitempty"`
    Metadata map[string]any `json:"metadata,omitempty"`
}

// VerdictAction is the final action for a package install.
type VerdictAction string

const (
    VerdictAllow   VerdictAction = "allow"
    VerdictWarn    VerdictAction = "warn"
    VerdictApprove VerdictAction = "approve"
    VerdictBlock   VerdictAction = "block"
)

// weight returns numeric weight for ordering (higher = stricter).
func (v VerdictAction) weight() int {
    switch v {
    case VerdictBlock:
        return 3
    case VerdictApprove:
        return 2
    case VerdictWarn:
        return 1
    case VerdictAllow:
        return 0
    default:
        return -1
    }
}

// PackageVerdict is the verdict for a single package.
type PackageVerdict struct {
    Package  PackageRef  `json:"package"`
    Action   VerdictAction `json:"action"`
    Findings []Finding     `json:"findings,omitempty"`
}

// Verdict is the final result for an entire install plan.
type Verdict struct {
    Action   VerdictAction              `json:"action"`
    Findings []Finding                  `json:"findings"`
    Summary  string                     `json:"summary"`
    Packages map[string]PackageVerdict  `json:"packages"`
}

// HighestAction returns the strictest action across all packages.
func (v *Verdict) HighestAction() VerdictAction {
    highest := VerdictAllow
    for _, pv := range v.Packages {
        if pv.Action.weight() > highest.weight() {
            highest = pv.Action
        }
    }
    return highest
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/pkgcheck/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/pkgcheck/types.go internal/pkgcheck/types_test.go
git commit -m "feat(pkgcheck): add core types — PackageRef, InstallPlan, Finding, Verdict"
```

---

### Task 2: Provider and Resolver interfaces

**Files:**
- Create: `internal/pkgcheck/provider.go`
- Create: `internal/pkgcheck/resolver.go`
- Test: `internal/pkgcheck/provider_test.go`

**Step 1: Write the test**

```go
// internal/pkgcheck/provider_test.go
package pkgcheck

import (
    "context"
    "testing"
    "time"
)

// mockProvider implements CheckProvider for testing.
type mockProvider struct {
    name         string
    capabilities []FindingType
    findings     []Finding
    err          error
}

func (m *mockProvider) Name() string                  { return m.name }
func (m *mockProvider) Capabilities() []FindingType   { return m.capabilities }
func (m *mockProvider) CheckBatch(ctx context.Context, req *CheckRequest) (*CheckResponse, error) {
    if m.err != nil {
        return nil, m.err
    }
    return &CheckResponse{
        Provider: m.name,
        Findings: m.findings,
        Metadata: ResponseMetadata{Duration: 10 * time.Millisecond},
    }, nil
}

func TestCheckProviderInterface(t *testing.T) {
    p := &mockProvider{
        name:         "test",
        capabilities: []FindingType{FindingVulnerability},
        findings: []Finding{
            {Type: FindingVulnerability, Provider: "test", Severity: SeverityHigh, Title: "CVE-2024-1234"},
        },
    }

    var cp CheckProvider = p // compile-time interface check
    if cp.Name() != "test" {
        t.Errorf("got %q, want %q", cp.Name(), "test")
    }

    resp, err := cp.CheckBatch(context.Background(), &CheckRequest{
        Ecosystem: EcosystemNPM,
        Packages:  []PackageRef{{Name: "foo", Version: "1.0.0"}},
    })
    if err != nil {
        t.Fatal(err)
    }
    if len(resp.Findings) != 1 {
        t.Fatalf("got %d findings, want 1", len(resp.Findings))
    }
    if resp.Findings[0].Title != "CVE-2024-1234" {
        t.Errorf("got %q", resp.Findings[0].Title)
    }
}

// mockResolver implements Resolver for testing.
type mockResolver struct {
    name string
    can  bool
    plan *InstallPlan
    err  error
}

func (m *mockResolver) Name() string { return m.name }
func (m *mockResolver) CanResolve(command string, args []string) bool { return m.can }
func (m *mockResolver) Resolve(ctx context.Context, command string, args []string, workDir string) (*InstallPlan, error) {
    return m.plan, m.err
}

func TestResolverInterface(t *testing.T) {
    r := &mockResolver{
        name: "npm",
        can:  true,
        plan: &InstallPlan{
            Tool:      "npm",
            Ecosystem: EcosystemNPM,
            Direct:    []PackageRef{{Name: "express", Version: "5.1.0", Direct: true}},
        },
    }

    var res Resolver = r // compile-time check
    if !res.CanResolve("npm", []string{"install", "express"}) {
        t.Error("should resolve npm install")
    }

    plan, err := res.Resolve(context.Background(), "npm", []string{"install", "express"}, "/tmp")
    if err != nil {
        t.Fatal(err)
    }
    if len(plan.Direct) != 1 || plan.Direct[0].Name != "express" {
        t.Errorf("unexpected plan: %+v", plan)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/pkgcheck/ -v -run TestCheckProviderInterface`
Expected: FAIL — types not defined

**Step 3: Write the interfaces**

```go
// internal/pkgcheck/provider.go
package pkgcheck

import (
    "context"
    "time"
)

// CheckProvider evaluates packages against a security/compliance data source.
type CheckProvider interface {
    Name() string
    Capabilities() []FindingType
    CheckBatch(ctx context.Context, req *CheckRequest) (*CheckResponse, error)
}

// CheckRequest is the input to a provider's CheckBatch method.
type CheckRequest struct {
    Ecosystem Ecosystem    `json:"ecosystem"`
    Packages  []PackageRef `json:"packages"`
    Config    map[string]any `json:"config,omitempty"`
}

// CheckResponse is the output of a provider's CheckBatch method.
type CheckResponse struct {
    Provider string           `json:"provider"`
    Findings []Finding        `json:"findings"`
    Metadata ResponseMetadata `json:"metadata"`
}

// ResponseMetadata contains provider response metadata.
type ResponseMetadata struct {
    Duration    time.Duration `json:"duration"`
    FromCache   bool          `json:"from_cache"`
    RateLimited bool          `json:"rate_limited"`
    Partial     bool          `json:"partial"`
    Error       string        `json:"error,omitempty"`
}
```

```go
// internal/pkgcheck/resolver.go
package pkgcheck

import "context"

// Resolver turns a raw install command into a structured InstallPlan.
type Resolver interface {
    Name() string
    CanResolve(command string, args []string) bool
    Resolve(ctx context.Context, command string, args []string, workDir string) (*InstallPlan, error)
}
```

**Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/pkgcheck/provider.go internal/pkgcheck/resolver.go internal/pkgcheck/provider_test.go
git commit -m "feat(pkgcheck): add CheckProvider and Resolver interfaces"
```

---

### Task 3: Config schema

**Files:**
- Create: `internal/config/pkgcheck.go`
- Modify: `internal/config/config.go` — add `PackageChecks` field to `Config` struct
- Test: `internal/config/pkgcheck_test.go`

**Step 1: Write the test**

```go
// internal/config/pkgcheck_test.go
package config

import (
    "testing"
    "time"

    "gopkg.in/yaml.v3"
)

func TestPackageChecksConfigDefaults(t *testing.T) {
    cfg := DefaultPackageChecksConfig()
    if cfg.Scope != "new_packages_only" {
        t.Errorf("default scope: got %q, want %q", cfg.Scope, "new_packages_only")
    }
    if !cfg.Cache.TTL.Vulnerability.IsSet() || cfg.Cache.TTL.Vulnerability.Duration != 24*time.Hour {
        t.Errorf("default vuln TTL: got %v, want 24h", cfg.Cache.TTL.Vulnerability)
    }
    if len(cfg.Registries) != 3 {
        t.Errorf("default registries: got %d, want 3", len(cfg.Registries))
    }
}

func TestPackageChecksConfigYAML(t *testing.T) {
    input := `
enabled: true
scope: all_installs
providers:
  osv:
    enabled: true
    timeout: 10s
    on_failure: warn
  socket:
    enabled: true
    timeout: 15s
    on_failure: approve
    api_key_env: SOCKET_API_KEY
registries:
  "https://registry.npmjs.org":
    trust: check_full
  "https://internal.corp.com":
    trust: trusted
    scopes: ["@corp"]
`
    var cfg PackageChecksConfig
    if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
        t.Fatal(err)
    }
    if cfg.Scope != "all_installs" {
        t.Errorf("scope: got %q", cfg.Scope)
    }
    osvCfg, ok := cfg.Providers["osv"]
    if !ok {
        t.Fatal("osv provider not found")
    }
    if osvCfg.OnFailure != "warn" {
        t.Errorf("osv on_failure: got %q", osvCfg.OnFailure)
    }
    reg, ok := cfg.Registries["https://internal.corp.com"]
    if !ok {
        t.Fatal("internal registry not found")
    }
    if reg.Trust != "trusted" {
        t.Errorf("trust: got %q", reg.Trust)
    }
    if len(reg.Scopes) != 1 || reg.Scopes[0] != "@corp" {
        t.Errorf("scopes: got %v", reg.Scopes)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -v -run TestPackageChecks`
Expected: FAIL — types not defined

**Step 3: Write the config types**

Create `internal/config/pkgcheck.go`. This file defines the YAML-bindable config structs. Use the existing `duration` type from the codebase if one exists, or use `time.Duration` with a custom YAML unmarshaler. Check how `ThreatFeedsConfig` handles durations and follow the same pattern.

```go
// internal/config/pkgcheck.go
package config

import "time"

type PackageChecksConfig struct {
    Enabled    bool                           `yaml:"enabled"`
    Scope      string                         `yaml:"scope"`      // "new_packages_only" | "all_installs"
    Cache      PackageCacheConfig             `yaml:"cache"`
    Registries map[string]RegistryTrustConfig `yaml:"registries"`
    Providers  map[string]ProviderConfig      `yaml:"providers"`
    Resolvers  map[string]ResolverConfig      `yaml:"resolvers"`
}

type PackageCacheConfig struct {
    Dir       string          `yaml:"dir"`
    TTL       PackageCacheTTL `yaml:"ttl"`
    MaxSizeMB int             `yaml:"max_size_mb"`
}

type PackageCacheTTL struct {
    Vulnerability Duration `yaml:"vulnerability"`
    License       Duration `yaml:"license"`
    Provenance    Duration `yaml:"provenance"`
    Reputation    Duration `yaml:"reputation"`
    Malware       Duration `yaml:"malware"`
}

type RegistryTrustConfig struct {
    Trust  string   `yaml:"trust"` // "check_full" | "check_local_only" | "trusted"
    Scopes []string `yaml:"scopes,omitempty"`
}

type ProviderConfig struct {
    Enabled   bool           `yaml:"enabled"`
    Type      string         `yaml:"type,omitempty"` // "" (built-in) | "exec"
    Command   string         `yaml:"command,omitempty"`
    Priority  int            `yaml:"priority"`
    Timeout   Duration       `yaml:"timeout"`
    OnFailure string         `yaml:"on_failure"` // "warn" | "deny" | "allow" | "approve"
    APIKeyEnv string         `yaml:"api_key_env,omitempty"`
    Options   map[string]any `yaml:"options,omitempty"`
}

type ResolverConfig struct {
    DryRunCommand string   `yaml:"dry_run_command"`
    Timeout       Duration `yaml:"timeout"`
}

func DefaultPackageChecksConfig() PackageChecksConfig {
    return PackageChecksConfig{
        Enabled: false,
        Scope:   "new_packages_only",
        Cache: PackageCacheConfig{
            Dir:       "${DATA_DIR}/pkgcache",
            MaxSizeMB: 500,
            TTL: PackageCacheTTL{
                Vulnerability: Duration{Duration: 24 * time.Hour, set: true},
                License:       Duration{Duration: 168 * time.Hour, set: true},
                Provenance:    Duration{Duration: 168 * time.Hour, set: true},
                Reputation:    Duration{Duration: 72 * time.Hour, set: true},
                Malware:       Duration{Duration: 12 * time.Hour, set: true},
            },
        },
        Registries: map[string]RegistryTrustConfig{
            "https://registry.npmjs.org": {Trust: "check_full"},
            "https://pypi.org":           {Trust: "check_full"},
            "default":                    {Trust: "check_local_only"},
        },
        Providers: map[string]ProviderConfig{
            "osv":    {Enabled: true, Priority: 1, Timeout: Duration{Duration: 10 * time.Second, set: true}, OnFailure: "warn"},
            "depsdev": {Enabled: true, Priority: 2, Timeout: Duration{Duration: 10 * time.Second, set: true}, OnFailure: "warn"},
            "local":  {Enabled: true, Priority: 0, OnFailure: "warn"},
        },
    }
}
```

Note: Check how the existing `Duration` type works in the config package. The `ThreatFeedsConfig` uses `time.Duration` directly — check if there's a custom YAML unmarshaler. If the codebase uses a wrapper type, use that. If it uses `time.Duration` with a custom YAML tag, match that pattern. The `IsSet()` method is for distinguishing "not set" from "set to zero" — if the existing codebase doesn't need this, simplify.

Then add to `Config` struct in `internal/config/config.go`:

```go
// Add after ThreatFeeds field:
PackageChecks PackageChecksConfig `yaml:"package_checks"`
```

**Step 4: Run tests**

Run: `go test ./internal/config/ -v -run TestPackageChecks`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/pkgcheck.go internal/config/pkgcheck_test.go internal/config/config.go
git commit -m "feat(pkgcheck): add PackageChecksConfig with defaults and YAML binding"
```

---

### Task 4: Event types

**Files:**
- Modify: `internal/events/types.go` — add package check event constants

**Step 1: Write the test**

```go
// Add to existing test file or create internal/events/pkgcheck_events_test.go
package events

import "testing"

func TestPackageCheckEventTypes(t *testing.T) {
    pkgEvents := []EventType{
        EventPackageCheckStarted,
        EventPackageCheckCompleted,
        EventPackageBlocked,
        EventPackageApproved,
        EventPackageWarning,
        EventProviderError,
    }
    for _, et := range pkgEvents {
        if _, ok := EventCategory[et]; !ok {
            t.Errorf("event %q missing from EventCategory map", et)
        }
    }
    // Verify they're in AllEventTypes
    allSet := map[EventType]bool{}
    for _, et := range AllEventTypes {
        allSet[et] = true
    }
    for _, et := range pkgEvents {
        if !allSet[et] {
            t.Errorf("event %q missing from AllEventTypes", et)
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/events/ -v -run TestPackageCheckEvent`
Expected: FAIL — constants not defined

**Step 3: Add event constants**

In `internal/events/types.go`, add a new const block after the existing MCP or Policy group:

```go
// Package check events
const (
    EventPackageCheckStarted   EventType = "package_check_started"
    EventPackageCheckCompleted EventType = "package_check_completed"
    EventPackageBlocked        EventType = "package_blocked"
    EventPackageApproved       EventType = "package_approved"
    EventPackageWarning        EventType = "package_warning"
    EventProviderError         EventType = "package_provider_error"
)
```

Add to `EventCategory` map:

```go
EventPackageCheckStarted:   "package",
EventPackageCheckCompleted: "package",
EventPackageBlocked:        "package",
EventPackageApproved:       "package",
EventPackageWarning:        "package",
EventProviderError:         "package",
```

Add to `AllEventTypes` slice:

```go
EventPackageCheckStarted,
EventPackageCheckCompleted,
EventPackageBlocked,
EventPackageApproved,
EventPackageWarning,
EventProviderError,
```

**Step 4: Run tests**

Run: `go test ./internal/events/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/events/types.go internal/events/pkgcheck_events_test.go
git commit -m "feat(pkgcheck): add package check event types"
```

---

### Task 5: Policy model — PackageRules

**Files:**
- Modify: `internal/policy/model.go` — add `PackageRules` and related structs
- Test: `internal/policy/pkgcheck_model_test.go`

**Step 1: Write the test**

```go
// internal/policy/pkgcheck_model_test.go
package policy

import (
    "testing"

    "gopkg.in/yaml.v3"
)

func TestPackageRuleYAMLParsing(t *testing.T) {
    input := `
package_rules:
  - match:
      packages: ["express", "lodash"]
    action: allow
    reason: "trusted"
  - match:
      finding_type: vulnerability
      severity: [critical, high]
    action: deny
    reason: "high severity vuln"
  - match:
      finding_type: license
      license_spdx:
        deny: [AGPL-3.0-only]
    action: deny
    reason: "copyleft"
  - match:
      ecosystem: npm
      finding_type: reputation
      reasons: [typosquat]
    action: deny
    reason: "typosquat"
  - match: {}
    action: allow
    reason: "default allow"
`
    var p Policy
    if err := yaml.Unmarshal([]byte(input), &p); err != nil {
        t.Fatal(err)
    }
    if len(p.PackageRules) != 5 {
        t.Fatalf("got %d rules, want 5", len(p.PackageRules))
    }
    // Static match
    r0 := p.PackageRules[0]
    if len(r0.Match.Packages) != 2 {
        t.Errorf("rule 0 packages: got %d", len(r0.Match.Packages))
    }
    if r0.Action != "allow" {
        t.Errorf("rule 0 action: got %q", r0.Action)
    }
    // Vuln match
    r1 := p.PackageRules[1]
    if r1.Match.FindingType != "vulnerability" {
        t.Errorf("rule 1 finding_type: got %q", r1.Match.FindingType)
    }
    if len(r1.Match.Severity) != 2 {
        t.Errorf("rule 1 severity: got %d", len(r1.Match.Severity))
    }
    // License match
    r2 := p.PackageRules[2]
    if len(r2.Match.LicenseSPDX.Deny) != 1 {
        t.Errorf("rule 2 license deny: got %d", len(r2.Match.LicenseSPDX.Deny))
    }
    // Ecosystem-scoped
    r3 := p.PackageRules[3]
    if r3.Match.Ecosystem != "npm" {
        t.Errorf("rule 3 ecosystem: got %q", r3.Match.Ecosystem)
    }
    // Empty match (catch-all)
    r4 := p.PackageRules[4]
    if r4.Match.FindingType != "" || len(r4.Match.Packages) != 0 {
        t.Error("rule 4 should be empty match (catch-all)")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v -run TestPackageRuleYAML`
Expected: FAIL — PackageRules field doesn't exist

**Step 3: Add to model.go**

Add to the `Policy` struct in `internal/policy/model.go`:

```go
PackageRules []PackageRule `yaml:"package_rules,omitempty"`
```

Add new structs (after existing rule types):

```go
// PackageRule defines a policy rule for package installs.
type PackageRule struct {
    Match   PackageMatch `yaml:"match"`
    Action  string       `yaml:"action"`  // "allow" | "deny" | "warn" | "approve"
    Reason  string       `yaml:"reason"`
}

// PackageMatch defines conditions for matching a package or finding.
type PackageMatch struct {
    // Static matching (pre-provider)
    Packages     []string `yaml:"packages,omitempty"`      // "express" or "express@5.1.0"
    NamePatterns []string `yaml:"name_patterns,omitempty"` // regex patterns

    // Finding-based matching (post-provider)
    FindingType string   `yaml:"finding_type,omitempty"` // "vulnerability", "license", etc.
    Severity    []string `yaml:"severity,omitempty"`     // ["critical", "high"]
    Reasons     []string `yaml:"reasons,omitempty"`      // ["vuln_no_fix", "typosquat"]

    // License-specific
    LicenseSPDX *LicenseSPDXMatch `yaml:"license_spdx,omitempty"`

    // Ecosystem-scoped
    Ecosystem string `yaml:"ecosystem,omitempty"` // "npm" | "pypi"

    // Options for configurable thresholds
    Options map[string]any `yaml:"options,omitempty"`
}

// LicenseSPDXMatch defines license allow/deny lists.
type LicenseSPDXMatch struct {
    Allow []string `yaml:"allow,omitempty"`
    Deny  []string `yaml:"deny,omitempty"`
}
```

**Step 4: Run tests**

Run: `go test ./internal/policy/ -v -run TestPackageRuleYAML`
Expected: PASS

Also run full policy tests to ensure nothing broke:
Run: `go test ./internal/policy/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/model.go internal/policy/pkgcheck_model_test.go
git commit -m "feat(pkgcheck): add PackageRules to policy model"
```

---

## Phase 2: Install Interceptor & Resolvers

### Task 6: Install command classifier

**Files:**
- Create: `internal/pkgcheck/interceptor.go`
- Test: `internal/pkgcheck/interceptor_test.go`

The interceptor recognizes install commands and extracts the requested packages.

**Step 1: Write the test**

```go
// internal/pkgcheck/interceptor_test.go
package pkgcheck

import "testing"

func TestClassifyInstallCommand(t *testing.T) {
    tests := []struct {
        name    string
        command string
        args    []string
        scope   string // "new_packages_only" | "all_installs"
        want    *InstallIntent
    }{
        // new_packages_only scope
        {"npm install pkg", "npm", []string{"install", "express"}, "new_packages_only",
            &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, Packages: []string{"express"}}},
        {"npm i shorthand", "npm", []string{"i", "lodash"}, "new_packages_only",
            &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, Packages: []string{"lodash"}}},
        {"npm ci skipped", "npm", []string{"ci"}, "new_packages_only", nil},
        {"npm install no args skipped", "npm", []string{"install"}, "new_packages_only", nil},
        {"pnpm add", "pnpm", []string{"add", "react"}, "new_packages_only",
            &InstallIntent{Tool: "pnpm", Ecosystem: EcosystemNPM, Packages: []string{"react"}}},
        {"yarn add", "yarn", []string{"add", "vue"}, "new_packages_only",
            &InstallIntent{Tool: "yarn", Ecosystem: EcosystemNPM, Packages: []string{"vue"}}},
        {"pip install", "pip", []string{"install", "requests"}, "new_packages_only",
            &InstallIntent{Tool: "pip", Ecosystem: EcosystemPyPI, Packages: []string{"requests"}}},
        {"pip install -r skipped", "pip", []string{"install", "-r", "requirements.txt"}, "new_packages_only", nil},
        {"uv pip install", "uv", []string{"pip", "install", "flask"}, "new_packages_only",
            &InstallIntent{Tool: "uv", Ecosystem: EcosystemPyPI, Packages: []string{"flask"}}},
        {"uv add", "uv", []string{"add", "httpx"}, "new_packages_only",
            &InstallIntent{Tool: "uv", Ecosystem: EcosystemPyPI, Packages: []string{"httpx"}}},
        {"poetry add", "poetry", []string{"add", "django"}, "new_packages_only",
            &InstallIntent{Tool: "poetry", Ecosystem: EcosystemPyPI, Packages: []string{"django"}}},
        {"unrelated command", "ls", []string{"-la"}, "new_packages_only", nil},

        // all_installs scope — npm ci is now captured
        {"npm ci captured", "npm", []string{"ci"}, "all_installs",
            &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, BulkInstall: true}},
        {"pip install -r captured", "pip", []string{"install", "-r", "requirements.txt"}, "all_installs",
            &InstallIntent{Tool: "pip", Ecosystem: EcosystemPyPI, BulkInstall: true}},
        {"poetry install captured", "poetry", []string{"install"}, "all_installs",
            &InstallIntent{Tool: "poetry", Ecosystem: EcosystemPyPI, BulkInstall: true}},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
            if tt.want == nil {
                if got != nil {
                    t.Errorf("expected nil, got %+v", got)
                }
                return
            }
            if got == nil {
                t.Fatal("expected non-nil intent")
            }
            if got.Tool != tt.want.Tool {
                t.Errorf("tool: got %q, want %q", got.Tool, tt.want.Tool)
            }
            if got.Ecosystem != tt.want.Ecosystem {
                t.Errorf("ecosystem: got %q, want %q", got.Ecosystem, tt.want.Ecosystem)
            }
            if got.BulkInstall != tt.want.BulkInstall {
                t.Errorf("bulk: got %v, want %v", got.BulkInstall, tt.want.BulkInstall)
            }
            if len(tt.want.Packages) > 0 {
                if len(got.Packages) != len(tt.want.Packages) {
                    t.Errorf("packages: got %v, want %v", got.Packages, tt.want.Packages)
                }
            }
        })
    }
}

func TestClassifyIgnoresFlags(t *testing.T) {
    // npm install --save-dev express should extract "express"
    got := ClassifyInstallCommand("npm", []string{"install", "--save-dev", "express"}, "new_packages_only")
    if got == nil {
        t.Fatal("expected non-nil")
    }
    if len(got.Packages) != 1 || got.Packages[0] != "express" {
        t.Errorf("packages: got %v, want [express]", got.Packages)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/pkgcheck/ -v -run TestClassify`
Expected: FAIL

**Step 3: Implement**

```go
// internal/pkgcheck/interceptor.go
package pkgcheck

import (
    "path/filepath"
    "strings"
)

// InstallIntent represents a detected package install command.
type InstallIntent struct {
    Tool        string
    Ecosystem   Ecosystem
    Packages    []string // package names/specs from command args
    BulkInstall bool     // true for "npm ci", "pip install -r", etc.
    OrigCommand string
    OrigArgs    []string
}

// ClassifyInstallCommand determines if a command is a package install.
// Returns nil if the command is not a recognized install command or is
// excluded by the scope setting.
func ClassifyInstallCommand(command string, args []string, scope string) *InstallIntent {
    base := filepath.Base(command)

    switch base {
    case "npm":
        return classifyNPM(args, scope)
    case "pnpm":
        return classifyPNPM(args, scope)
    case "yarn":
        return classifyYarn(args, scope)
    case "pip", "pip3":
        return classifyPip(args, scope)
    case "uv":
        return classifyUV(args, scope)
    case "poetry":
        return classifyPoetry(args, scope)
    }
    return nil
}

func classifyNPM(args []string, scope string) *InstallIntent {
    if len(args) == 0 {
        return nil
    }
    sub := args[0]
    switch sub {
    case "install", "i", "add":
        pkgs := extractPackageArgs(args[1:])
        if len(pkgs) == 0 {
            // "npm install" with no package args = bulk install from lockfile
            if scope == "all_installs" {
                return &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, BulkInstall: true}
            }
            return nil
        }
        return &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, Packages: pkgs}
    case "ci":
        if scope == "all_installs" {
            return &InstallIntent{Tool: "npm", Ecosystem: EcosystemNPM, BulkInstall: true}
        }
    }
    return nil
}

func classifyPNPM(args []string, scope string) *InstallIntent {
    if len(args) == 0 {
        return nil
    }
    switch args[0] {
    case "add":
        pkgs := extractPackageArgs(args[1:])
        if len(pkgs) == 0 {
            return nil
        }
        return &InstallIntent{Tool: "pnpm", Ecosystem: EcosystemNPM, Packages: pkgs}
    case "install", "i":
        if scope == "all_installs" {
            return &InstallIntent{Tool: "pnpm", Ecosystem: EcosystemNPM, BulkInstall: true}
        }
    }
    return nil
}

func classifyYarn(args []string, scope string) *InstallIntent {
    if len(args) == 0 {
        return nil
    }
    switch args[0] {
    case "add":
        pkgs := extractPackageArgs(args[1:])
        if len(pkgs) == 0 {
            return nil
        }
        return &InstallIntent{Tool: "yarn", Ecosystem: EcosystemNPM, Packages: pkgs}
    case "install":
        if scope == "all_installs" {
            return &InstallIntent{Tool: "yarn", Ecosystem: EcosystemNPM, BulkInstall: true}
        }
    }
    return nil
}

func classifyPip(args []string, scope string) *InstallIntent {
    if len(args) == 0 || args[0] != "install" {
        return nil
    }
    // Check for -r / --requirement flag
    for _, a := range args[1:] {
        if a == "-r" || a == "--requirement" {
            if scope == "all_installs" {
                return &InstallIntent{Tool: "pip", Ecosystem: EcosystemPyPI, BulkInstall: true}
            }
            return nil
        }
    }
    pkgs := extractPackageArgs(args[1:])
    if len(pkgs) == 0 {
        return nil
    }
    return &InstallIntent{Tool: "pip", Ecosystem: EcosystemPyPI, Packages: pkgs}
}

func classifyUV(args []string, scope string) *InstallIntent {
    if len(args) == 0 {
        return nil
    }
    switch args[0] {
    case "pip":
        if len(args) < 2 || args[1] != "install" {
            return nil
        }
        pkgs := extractPackageArgs(args[2:])
        if len(pkgs) == 0 {
            if scope == "all_installs" {
                return &InstallIntent{Tool: "uv", Ecosystem: EcosystemPyPI, BulkInstall: true}
            }
            return nil
        }
        return &InstallIntent{Tool: "uv", Ecosystem: EcosystemPyPI, Packages: pkgs}
    case "add":
        pkgs := extractPackageArgs(args[1:])
        if len(pkgs) == 0 {
            return nil
        }
        return &InstallIntent{Tool: "uv", Ecosystem: EcosystemPyPI, Packages: pkgs}
    }
    return nil
}

func classifyPoetry(args []string, scope string) *InstallIntent {
    if len(args) == 0 {
        return nil
    }
    switch args[0] {
    case "add":
        pkgs := extractPackageArgs(args[1:])
        if len(pkgs) == 0 {
            return nil
        }
        return &InstallIntent{Tool: "poetry", Ecosystem: EcosystemPyPI, Packages: pkgs}
    case "install":
        if scope == "all_installs" {
            return &InstallIntent{Tool: "poetry", Ecosystem: EcosystemPyPI, BulkInstall: true}
        }
    }
    return nil
}

// extractPackageArgs filters out flags (starting with -) and returns package names.
func extractPackageArgs(args []string) []string {
    var pkgs []string
    skipNext := false
    for _, a := range args {
        if skipNext {
            skipNext = false
            continue
        }
        if strings.HasPrefix(a, "-") {
            // Flags that take a value: skip next arg too
            if a == "--save-dev" || a == "-D" || a == "--save-peer" || a == "--save-optional" ||
                a == "-g" || a == "--global" || a == "--save-exact" || a == "-E" {
                continue
            }
            // Flags with separate value
            if a == "--registry" || a == "--tag" || a == "--scope" {
                skipNext = true
            }
            continue
        }
        pkgs = append(pkgs, a)
    }
    return pkgs
}
```

**Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -v -run TestClassify`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/pkgcheck/interceptor.go internal/pkgcheck/interceptor_test.go
git commit -m "feat(pkgcheck): add install command classifier for npm/pnpm/yarn/pip/uv/poetry"
```

---

### Task 7: Resolver registry and npm resolver

**Files:**
- Create: `internal/pkgcheck/resolver/registry.go`
- Create: `internal/pkgcheck/resolver/npm.go`
- Test: `internal/pkgcheck/resolver/npm_test.go`
- Test fixtures: `internal/pkgcheck/resolver/testdata/npm_dry_run.json`

The resolver registry holds all registered resolvers and dispatches to the right one. The npm resolver shells out to `npm install --package-lock-only` and parses the result.

**Step 1: Write the test with golden fixtures**

Create `internal/pkgcheck/resolver/testdata/npm_dry_run.json` with recorded output from `npm install --package-lock-only --json express`. The exact format depends on npm's output — capture real output during development.

```go
// internal/pkgcheck/resolver/npm_test.go
package resolver

import (
    "context"
    "os"
    "testing"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

func TestNPMResolverCanResolve(t *testing.T) {
    r := NewNPMResolver(NPMResolverConfig{})
    tests := []struct {
        cmd  string
        args []string
        want bool
    }{
        {"npm", []string{"install", "express"}, true},
        {"npm", []string{"i", "lodash"}, true},
        {"npm", []string{"ci"}, false},
        {"pip", []string{"install", "requests"}, false},
    }
    for _, tt := range tests {
        got := r.CanResolve(tt.cmd, tt.args)
        if got != tt.want {
            t.Errorf("CanResolve(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
        }
    }
}

func TestNPMResolverParsePlan(t *testing.T) {
    data, err := os.ReadFile("testdata/npm_dry_run.json")
    if err != nil {
        t.Skip("testdata not available; run 'go generate' to create fixtures")
    }
    plan, err := parseNPMDryRunOutput(data, "express", "/tmp/test")
    if err != nil {
        t.Fatal(err)
    }
    if plan.Tool != "npm" {
        t.Errorf("tool: got %q", plan.Tool)
    }
    if plan.Ecosystem != pkgcheck.EcosystemNPM {
        t.Errorf("ecosystem: got %q", plan.Ecosystem)
    }
    if len(plan.Direct) == 0 {
        t.Error("expected at least one direct dependency")
    }
    // express should be in direct deps
    found := false
    for _, d := range plan.Direct {
        if d.Name == "express" {
            found = true
            if d.Version == "" {
                t.Error("express version should not be empty")
            }
        }
    }
    if !found {
        t.Error("express not found in direct deps")
    }
}
```

**Step 2: Write the registry**

```go
// internal/pkgcheck/resolver/registry.go
package resolver

import "github.com/canyonroad/agentsh/internal/pkgcheck"

// Registry holds all registered resolvers and dispatches to the right one.
type Registry struct {
    resolvers []pkgcheck.Resolver
}

func NewRegistry() *Registry {
    return &Registry{}
}

func (r *Registry) Register(res pkgcheck.Resolver) {
    r.resolvers = append(r.resolvers, res)
}

// Find returns the first resolver that can handle the given command.
func (r *Registry) Find(command string, args []string) pkgcheck.Resolver {
    for _, res := range r.resolvers {
        if res.CanResolve(command, args) {
            return res
        }
    }
    return nil
}
```

**Step 3: Write the npm resolver**

```go
// internal/pkgcheck/resolver/npm.go
package resolver

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "path/filepath"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

type NPMResolverConfig struct {
    DryRunCommand string
    Timeout       time.Duration
}

type npmResolver struct {
    cfg NPMResolverConfig
}

func NewNPMResolver(cfg NPMResolverConfig) pkgcheck.Resolver {
    if cfg.DryRunCommand == "" {
        cfg.DryRunCommand = "npm install --package-lock-only --ignore-scripts"
    }
    if cfg.Timeout == 0 {
        cfg.Timeout = 60 * time.Second
    }
    return &npmResolver{cfg: cfg}
}

func (r *npmResolver) Name() string { return "npm" }

func (r *npmResolver) CanResolve(command string, args []string) bool {
    base := filepath.Base(command)
    if base != "npm" {
        return false
    }
    if len(args) == 0 {
        return false
    }
    return args[0] == "install" || args[0] == "i" || args[0] == "add"
}

func (r *npmResolver) Resolve(ctx context.Context, command string, args []string, workDir string) (*pkgcheck.InstallPlan, error) {
    ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
    defer cancel()

    // Build dry-run command: "npm install --package-lock-only --ignore-scripts <packages>"
    pkgs := extractPkgArgs(args)
    cmdArgs := []string{"install", "--package-lock-only", "--ignore-scripts", "--json"}
    cmdArgs = append(cmdArgs, pkgs...)

    cmd := exec.CommandContext(ctx, "npm", cmdArgs...)
    cmd.Dir = workDir

    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("npm dry-run failed: %w", err)
    }

    return parseNPMDryRunOutput(output, pkgs[0], workDir)
}

func parseNPMDryRunOutput(data []byte, directPkg string, workDir string) (*pkgcheck.InstallPlan, error) {
    // npm --json output structure
    var result struct {
        Added []struct {
            Name    string `json:"name"`
            Version string `json:"version"`
        } `json:"added"`
    }
    if err := json.Unmarshal(data, &result); err != nil {
        return nil, fmt.Errorf("parsing npm output: %w", err)
    }

    plan := &pkgcheck.InstallPlan{
        Tool:       "npm",
        Ecosystem:  pkgcheck.EcosystemNPM,
        WorkDir:    workDir,
        Registry:   "https://registry.npmjs.org",
        ResolvedAt: time.Now().UTC(),
    }

    for _, pkg := range result.Added {
        ref := pkgcheck.PackageRef{
            Name:     pkg.Name,
            Version:  pkg.Version,
            Registry: plan.Registry,
            Direct:   pkg.Name == directPkg,
        }
        if ref.Direct {
            plan.Direct = append(plan.Direct, ref)
        } else {
            plan.Transitive = append(plan.Transitive, ref)
        }
    }

    return plan, nil
}

// extractPkgArgs pulls package names from npm install args, skipping flags.
func extractPkgArgs(args []string) []string {
    var pkgs []string
    for _, a := range args[1:] { // skip "install"/"i"/"add"
        if a == "" || a[0] == '-' {
            continue
        }
        pkgs = append(pkgs, a)
    }
    return pkgs
}
```

Note: The actual npm JSON output format may differ. During implementation, run `npm install --package-lock-only --json express` in a temp dir to capture the real output structure, create the golden fixture, and adjust `parseNPMDryRunOutput` accordingly.

**Step 4: Run tests**

Run: `go test ./internal/pkgcheck/resolver/ -v -run TestNPMResolver`
Expected: PASS (CanResolve test passes; ParsePlan test may skip if fixture not yet created)

**Step 5: Commit**

```bash
git add internal/pkgcheck/resolver/
git commit -m "feat(pkgcheck): add resolver registry and npm resolver"
```

---

### Task 8: pip and uv resolvers

**Files:**
- Create: `internal/pkgcheck/resolver/pip.go`
- Create: `internal/pkgcheck/resolver/uv.go`
- Test: `internal/pkgcheck/resolver/pip_test.go`
- Test fixtures: `internal/pkgcheck/resolver/testdata/pip_dry_run.json`

Follow the same pattern as Task 7. Key differences:

- **pip**: `pip install --dry-run --report - <package>` outputs JSON with `install` array containing `{metadata: {name, version}, ...}` objects. The `--report -` flag (pip 23.0+) writes the install report to stdout.
- **uv**: `uv pip install --dry-run <package>` outputs human-readable text. Parse lines like `Would install flask-3.0.0 jinja2-3.1.2 ...`. Alternatively `uv pip compile` produces a requirements.txt-like output with pinned versions.

Write `CanResolve` tests for pip/uv, parse tests with golden fixtures. Same TDD pattern.

**Commit:**

```bash
git add internal/pkgcheck/resolver/pip.go internal/pkgcheck/resolver/uv.go internal/pkgcheck/resolver/pip_test.go
git commit -m "feat(pkgcheck): add pip and uv resolvers"
```

---

### Task 9: pnpm, yarn, and poetry resolvers

**Files:**
- Create: `internal/pkgcheck/resolver/pnpm.go`
- Create: `internal/pkgcheck/resolver/yarn.go`
- Create: `internal/pkgcheck/resolver/poetry.go`
- Tests for each

Follow the same pattern:

- **pnpm**: `pnpm install --lockfile-only --ignore-scripts`. Parse `pnpm-lock.yaml` diff or use `pnpm list --json` post-resolution.
- **yarn**: `yarn install --mode update-lockfile`. Parse `yarn.lock` diff or `yarn info --json`.
- **poetry**: `poetry lock --no-update`. Parse `poetry.lock` diff.

**Commit:**

```bash
git add internal/pkgcheck/resolver/pnpm.go internal/pkgcheck/resolver/yarn.go internal/pkgcheck/resolver/poetry.go
git commit -m "feat(pkgcheck): add pnpm, yarn, and poetry resolvers"
```

---

## Phase 3: Providers

### Task 10: Local metadata scan provider

**Files:**
- Create: `internal/pkgcheck/provider/local.go`
- Test: `internal/pkgcheck/provider/local_test.go`

The local provider extracts license information from package metadata without any network calls. For npm, it reads the `license` field from the registry metadata (already available from the resolver). For PyPI, it reads `Classifier` fields.

For MVP, this provider takes the `PackageRef` list and checks if license info was provided in the install plan metadata. If not, it produces a `license_missing` finding.

**Step 1: Write the test**

```go
// internal/pkgcheck/provider/local_test.go
package provider

import (
    "context"
    "testing"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

func TestLocalProvider(t *testing.T) {
    p := NewLocalProvider()

    if p.Name() != "local" {
        t.Errorf("name: got %q", p.Name())
    }

    caps := p.Capabilities()
    if len(caps) != 1 || caps[0] != pkgcheck.FindingLicense {
        t.Errorf("capabilities: got %v", caps)
    }
}

func TestLocalProviderCheckBatch(t *testing.T) {
    p := NewLocalProvider()
    resp, err := p.CheckBatch(context.Background(), &pkgcheck.CheckRequest{
        Ecosystem: pkgcheck.EcosystemNPM,
        Packages: []pkgcheck.PackageRef{
            {Name: "express", Version: "5.1.0"},
        },
    })
    if err != nil {
        t.Fatal(err)
    }
    if resp.Provider != "local" {
        t.Errorf("provider: got %q", resp.Provider)
    }
    // Local provider with no registry data should produce license_unknown findings
    if len(resp.Findings) == 0 {
        t.Error("expected at least one finding for unknown license")
    }
}
```

**Step 2: Implement**

```go
// internal/pkgcheck/provider/local.go
package provider

import (
    "context"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

type localProvider struct{}

func NewLocalProvider() pkgcheck.CheckProvider {
    return &localProvider{}
}

func (p *localProvider) Name() string { return "local" }

func (p *localProvider) Capabilities() []pkgcheck.FindingType {
    return []pkgcheck.FindingType{pkgcheck.FindingLicense}
}

func (p *localProvider) CheckBatch(ctx context.Context, req *pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
    start := time.Now()
    var findings []pkgcheck.Finding

    for _, pkg := range req.Packages {
        // Check if license metadata is available (from package.json license field,
        // PKG-INFO classifiers, etc.) — for MVP we flag as unknown since we don't
        // have the tarball at this point. The resolver can optionally populate
        // license metadata from registry API responses.
        license, ok := extractLicenseFromMetadata(pkg)
        if !ok {
            findings = append(findings, pkgcheck.Finding{
                Type:     pkgcheck.FindingLicense,
                Provider: "local",
                Package:  pkg,
                Severity: pkgcheck.SeverityInfo,
                Title:    "License information not available locally",
                Reasons:  []pkgcheck.Reason{{Code: "license_unknown", Message: "No license metadata available without registry lookup"}},
            })
            continue
        }
        findings = append(findings, pkgcheck.Finding{
            Type:     pkgcheck.FindingLicense,
            Provider: "local",
            Package:  pkg,
            Severity: pkgcheck.SeverityInfo,
            Title:    "License: " + license,
            Reasons:  []pkgcheck.Reason{{Code: "license_detected", Message: license}},
            Metadata: map[string]any{"spdx": license},
        })
    }

    return &pkgcheck.CheckResponse{
        Provider: "local",
        Findings: findings,
        Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)},
    }, nil
}

func extractLicenseFromMetadata(pkg pkgcheck.PackageRef) (string, bool) {
    // For MVP: check if metadata was populated by the resolver.
    // This will be populated when we add registry metadata fetching to resolvers.
    if pkg.Metadata != nil {
        if lic, ok := pkg.Metadata["license"].(string); ok && lic != "" {
            return lic, true
        }
    }
    return "", false
}
```

Note: The `PackageRef` struct doesn't yet have a `Metadata` field. Either add `Metadata map[string]any` to `PackageRef` in `types.go` (preferred — resolvers can populate it from registry responses), or defer this and have the local provider always return `license_unknown` for MVP.

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/provider/ -v
git add internal/pkgcheck/provider/local.go internal/pkgcheck/provider/local_test.go
git commit -m "feat(pkgcheck): add local metadata scan provider"
```

---

### Task 11: OSV.dev provider

**Files:**
- Create: `internal/pkgcheck/provider/osv.go`
- Test: `internal/pkgcheck/provider/osv_test.go`
- Test fixtures: `internal/pkgcheck/provider/testdata/osv_batch_response.json`

OSV has a batch API at `POST https://api.osv.dev/v1/querybatch`. Request body:

```json
{"queries": [{"package": {"name": "express", "ecosystem": "npm"}, "version": "4.17.1"}]}
```

Response contains `results` array with vulnerabilities.

**Step 1: Write the test**

```go
// internal/pkgcheck/provider/osv_test.go
package provider

import (
    "context"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

func TestOSVProviderName(t *testing.T) {
    p := NewOSVProvider(OSVConfig{})
    if p.Name() != "osv" {
        t.Errorf("name: got %q", p.Name())
    }
    caps := p.Capabilities()
    if len(caps) != 1 || caps[0] != pkgcheck.FindingVulnerability {
        t.Errorf("capabilities: got %v", caps)
    }
}

func TestOSVProviderCheckBatch(t *testing.T) {
    // Load fixture
    fixture, err := os.ReadFile("testdata/osv_batch_response.json")
    if err != nil {
        t.Skip("fixture not available")
    }

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/v1/querybatch" {
            t.Errorf("unexpected path: %s", r.URL.Path)
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write(fixture)
    }))
    defer srv.Close()

    p := NewOSVProvider(OSVConfig{BaseURL: srv.URL})
    resp, err := p.CheckBatch(context.Background(), &pkgcheck.CheckRequest{
        Ecosystem: pkgcheck.EcosystemNPM,
        Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.17.1"}},
    })
    if err != nil {
        t.Fatal(err)
    }
    if resp.Provider != "osv" {
        t.Errorf("provider: got %q", resp.Provider)
    }
    // Fixture should contain vulnerabilities for express@4.17.1
    // Adjust assertions based on actual fixture content
}
```

**Step 2: Implement**

```go
// internal/pkgcheck/provider/osv.go
package provider

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

type OSVConfig struct {
    BaseURL string
    Timeout time.Duration
}

type osvProvider struct {
    client  *http.Client
    baseURL string
}

func NewOSVProvider(cfg OSVConfig) pkgcheck.CheckProvider {
    if cfg.BaseURL == "" {
        cfg.BaseURL = "https://api.osv.dev"
    }
    if cfg.Timeout == 0 {
        cfg.Timeout = 10 * time.Second
    }
    return &osvProvider{
        client:  &http.Client{Timeout: cfg.Timeout},
        baseURL: cfg.BaseURL,
    }
}

func (p *osvProvider) Name() string { return "osv" }

func (p *osvProvider) Capabilities() []pkgcheck.FindingType {
    return []pkgcheck.FindingType{pkgcheck.FindingVulnerability}
}

func (p *osvProvider) CheckBatch(ctx context.Context, req *pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
    start := time.Now()

    // Map ecosystem to OSV ecosystem name
    osvEcosystem := mapEcosystem(req.Ecosystem)

    // Build batch request
    type query struct {
        Package struct {
            Name      string `json:"name"`
            Ecosystem string `json:"ecosystem"`
        } `json:"package"`
        Version string `json:"version"`
    }
    var queries []query
    for _, pkg := range req.Packages {
        q := query{Version: pkg.Version}
        q.Package.Name = pkg.Name
        q.Package.Ecosystem = osvEcosystem
        queries = append(queries, q)
    }

    body, err := json.Marshal(map[string]any{"queries": queries})
    if err != nil {
        return nil, err
    }

    httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/querybatch", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    httpReq.Header.Set("Content-Type", "application/json")

    httpResp, err := p.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("osv API request failed: %w", err)
    }
    defer httpResp.Body.Close()

    if httpResp.StatusCode != http.StatusOK {
        respBody, _ := io.ReadAll(httpResp.Body)
        return nil, fmt.Errorf("osv API returned %d: %s", httpResp.StatusCode, string(respBody))
    }

    var result struct {
        Results []struct {
            Vulns []osvVuln `json:"vulns"`
        } `json:"results"`
    }
    if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("parsing osv response: %w", err)
    }

    var findings []pkgcheck.Finding
    for i, r := range result.Results {
        if i >= len(req.Packages) {
            break
        }
        pkg := req.Packages[i]
        for _, v := range r.Vulns {
            findings = append(findings, vulnToFinding(pkg, v))
        }
    }

    return &pkgcheck.CheckResponse{
        Provider: "osv",
        Findings: findings,
        Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)},
    }, nil
}

type osvVuln struct {
    ID       string `json:"id"`
    Summary  string `json:"summary"`
    Details  string `json:"details"`
    Severity []struct {
        Type  string `json:"type"`
        Score string `json:"score"`
    } `json:"severity"`
    References []struct {
        Type string `json:"type"`
        URL  string `json:"url"`
    } `json:"references"`
}

func vulnToFinding(pkg pkgcheck.PackageRef, v osvVuln) pkgcheck.Finding {
    severity := mapOSVSeverity(v)
    var links []string
    for _, ref := range v.References {
        links = append(links, ref.URL)
    }
    reasons := []pkgcheck.Reason{{Code: "vulnerability", Message: v.Summary}}

    return pkgcheck.Finding{
        Type:     pkgcheck.FindingVulnerability,
        Provider: "osv",
        Package:  pkg,
        Severity: severity,
        Title:    v.ID + ": " + v.Summary,
        Detail:   v.Details,
        Reasons:  reasons,
        Links:    links,
        Metadata: map[string]any{"osv_id": v.ID},
    }
}

func mapOSVSeverity(v osvVuln) pkgcheck.Severity {
    for _, s := range v.Severity {
        if s.Type == "CVSS_V3" {
            // Parse CVSS score string to float and map to severity
            // For MVP, use a simple heuristic based on score ranges
            return pkgcheck.SeverityMedium // placeholder — parse properly
        }
    }
    return pkgcheck.SeverityMedium
}

func mapEcosystem(e pkgcheck.Ecosystem) string {
    switch e {
    case pkgcheck.EcosystemNPM:
        return "npm"
    case pkgcheck.EcosystemPyPI:
        return "PyPI"
    default:
        return string(e)
    }
}
```

**Step 3: Run tests, create fixture, commit**

Run: `go test ./internal/pkgcheck/provider/ -v -run TestOSV`

```bash
git add internal/pkgcheck/provider/osv.go internal/pkgcheck/provider/osv_test.go internal/pkgcheck/provider/testdata/
git commit -m "feat(pkgcheck): add OSV.dev vulnerability provider"
```

---

### Task 12: deps.dev provider

**Files:**
- Create: `internal/pkgcheck/provider/depsdev.go`
- Test: `internal/pkgcheck/provider/depsdev_test.go`

deps.dev API: `GET https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{name}/versions/{version}` returns license info, OpenSSF Scorecard, links, etc.

Follow the same pattern as Task 11: httptest server with recorded fixtures, parse response into `FindingLicense` and `FindingReputation` findings.

**Commit:**

```bash
git add internal/pkgcheck/provider/depsdev.go internal/pkgcheck/provider/depsdev_test.go
git commit -m "feat(pkgcheck): add deps.dev license and scorecard provider"
```

---

### Task 13: Socket.dev and Snyk providers

**Files:**
- Create: `internal/pkgcheck/provider/socket.go`
- Create: `internal/pkgcheck/provider/snyk.go`
- Tests for each

These require API keys. They are enabled only when the key env var is set. Follow the same httptest pattern with fixtures.

- **Socket**: `POST https://api.socket.dev/v0/npm/issues` — returns supply-chain signals, typosquat detection, install script analysis
- **Snyk**: `POST https://api.snyk.io/rest/orgs/{org}/packages/{ecosystem}/{name}/issues` — returns vulnerability and license findings

**Commit:**

```bash
git add internal/pkgcheck/provider/socket.go internal/pkgcheck/provider/snyk.go
git commit -m "feat(pkgcheck): add Socket.dev and Snyk providers"
```

---

### Task 14: Exec protocol provider

**Files:**
- Create: `internal/pkgcheck/provider/exec.go`
- Test: `internal/pkgcheck/provider/exec_test.go`
- Test fixture: `internal/pkgcheck/provider/testdata/sample_provider.sh`

**Step 1: Write the test**

```go
// internal/pkgcheck/provider/exec_test.go
package provider

import (
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

func TestExecProvider(t *testing.T) {
    // Create a temp script that echoes a valid JSON response
    dir := t.TempDir()
    script := filepath.Join(dir, "test-provider.sh")
    err := os.WriteFile(script, []byte(`#!/bin/sh
cat <<'JSON'
{"provider":"test","findings":[{"type":"license","package":{"name":"foo","version":"1.0.0"},"severity":"info","title":"MIT","reasons":[{"code":"license_detected","message":"MIT"}]}],"metadata":{"duration_ms":5}}
JSON
`), 0755)
    if err != nil {
        t.Fatal(err)
    }

    p := NewExecProvider("test", ExecProviderConfig{Command: script})
    resp, err := p.CheckBatch(context.Background(), &pkgcheck.CheckRequest{
        Ecosystem: pkgcheck.EcosystemNPM,
        Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1.0.0"}},
    })
    if err != nil {
        t.Fatal(err)
    }
    if resp.Provider != "test" {
        t.Errorf("provider: got %q", resp.Provider)
    }
    if len(resp.Findings) != 1 {
        t.Fatalf("findings: got %d, want 1", len(resp.Findings))
    }
    if resp.Findings[0].Title != "MIT" {
        t.Errorf("title: got %q", resp.Findings[0].Title)
    }
}

func TestExecProviderFailure(t *testing.T) {
    p := NewExecProvider("bad", ExecProviderConfig{Command: "/nonexistent"})
    _, err := p.CheckBatch(context.Background(), &pkgcheck.CheckRequest{
        Ecosystem: pkgcheck.EcosystemNPM,
        Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1.0.0"}},
    })
    if err == nil {
        t.Error("expected error for missing command")
    }
}
```

**Step 2: Implement**

```go
// internal/pkgcheck/provider/exec.go
package provider

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

type ExecProviderConfig struct {
    Command string
    Timeout time.Duration
    Config  map[string]any
}

type execProvider struct {
    name string
    cfg  ExecProviderConfig
}

func NewExecProvider(name string, cfg ExecProviderConfig) pkgcheck.CheckProvider {
    if cfg.Timeout == 0 {
        cfg.Timeout = 30 * time.Second
    }
    return &execProvider{name: name, cfg: cfg}
}

func (p *execProvider) Name() string { return p.name }

func (p *execProvider) Capabilities() []pkgcheck.FindingType {
    // Exec providers can return any finding type
    return []pkgcheck.FindingType{
        pkgcheck.FindingVulnerability, pkgcheck.FindingLicense,
        pkgcheck.FindingProvenance, pkgcheck.FindingReputation, pkgcheck.FindingMalware,
    }
}

func (p *execProvider) CheckBatch(ctx context.Context, req *pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
    defer cancel()

    // Marshal request to JSON for stdin
    input := struct {
        Ecosystem string             `json:"ecosystem"`
        Packages  []pkgcheck.PackageRef `json:"packages"`
        Config    map[string]any     `json:"config,omitempty"`
    }{
        Ecosystem: string(req.Ecosystem),
        Packages:  req.Packages,
        Config:    p.cfg.Config,
    }
    inputJSON, err := json.Marshal(input)
    if err != nil {
        return nil, err
    }

    cmd := exec.CommandContext(ctx, p.cfg.Command)
    cmd.Stdin = bytes.NewReader(inputJSON)

    // Don't inherit parent env — strip sensitive vars
    cmd.Env = []string{}

    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    start := time.Now()
    err = cmd.Run()

    if err != nil {
        exitErr, ok := err.(*exec.ExitError)
        if ok && exitErr.ExitCode() == 1 {
            // Partial results — continue parsing stdout
        } else {
            return nil, fmt.Errorf("exec provider %q failed: %w (stderr: %s)", p.name, err, stderr.String())
        }
    }

    var resp pkgcheck.CheckResponse
    if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
        return nil, fmt.Errorf("parsing exec provider %q output: %w", p.name, err)
    }
    resp.Provider = p.name
    resp.Metadata.Duration = time.Since(start)

    return &resp, nil
}
```

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/provider/ -v -run TestExecProvider
git add internal/pkgcheck/provider/exec.go internal/pkgcheck/provider/exec_test.go
git commit -m "feat(pkgcheck): add exec protocol provider for custom integrations"
```

---

## Phase 4: Cache

### Task 15: TTL-based disk cache

**Files:**
- Create: `internal/pkgcheck/cache/cache.go`
- Test: `internal/pkgcheck/cache/cache_test.go`

The cache stores provider responses keyed by `(provider, ecosystem, package, version)` with per-finding-type TTLs.

**Step 1: Write the test**

```go
// internal/pkgcheck/cache/cache_test.go
package cache

import (
    "testing"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

func TestCachePutGet(t *testing.T) {
    dir := t.TempDir()
    c, err := New(Config{Dir: dir, MaxSizeMB: 10, DefaultTTL: 1 * time.Hour})
    if err != nil {
        t.Fatal(err)
    }
    defer c.Close()

    key := Key{Provider: "osv", Ecosystem: "npm", Package: "express", Version: "5.1.0"}
    findings := []pkgcheck.Finding{
        {Type: pkgcheck.FindingVulnerability, Provider: "osv", Severity: pkgcheck.SeverityHigh, Title: "CVE-2024-1234"},
    }

    c.Put(key, findings)

    got, ok := c.Get(key)
    if !ok {
        t.Fatal("cache miss")
    }
    if len(got) != 1 || got[0].Title != "CVE-2024-1234" {
        t.Errorf("unexpected: %+v", got)
    }
}

func TestCacheExpiry(t *testing.T) {
    dir := t.TempDir()
    c, err := New(Config{Dir: dir, MaxSizeMB: 10, DefaultTTL: 1 * time.Millisecond})
    if err != nil {
        t.Fatal(err)
    }
    defer c.Close()

    key := Key{Provider: "osv", Ecosystem: "npm", Package: "express", Version: "5.1.0"}
    c.Put(key, []pkgcheck.Finding{})

    time.Sleep(5 * time.Millisecond)

    _, ok := c.Get(key)
    if ok {
        t.Error("expected cache miss after expiry")
    }
}

func TestCacheMiss(t *testing.T) {
    dir := t.TempDir()
    c, err := New(Config{Dir: dir, MaxSizeMB: 10, DefaultTTL: 1 * time.Hour})
    if err != nil {
        t.Fatal(err)
    }
    defer c.Close()

    key := Key{Provider: "osv", Ecosystem: "npm", Package: "nonexistent", Version: "0.0.0"}
    _, ok := c.Get(key)
    if ok {
        t.Error("expected miss")
    }
}
```

**Step 2: Implement**

Use bbolt (already likely a dependency) or a simple JSON-file-per-entry approach. For MVP, an in-memory map with periodic flush to a single JSON file is sufficient. For production, use bbolt.

```go
// internal/pkgcheck/cache/cache.go
package cache

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
)

type Key struct {
    Provider  string
    Ecosystem string
    Package   string
    Version   string
}

func (k Key) String() string {
    return k.Provider + ":" + k.Ecosystem + ":" + k.Package + ":" + k.Version
}

type entry struct {
    Findings  []pkgcheck.Finding `json:"findings"`
    ExpiresAt time.Time          `json:"expires_at"`
}

type Config struct {
    Dir        string
    MaxSizeMB  int
    DefaultTTL time.Duration
    TTLByType  map[pkgcheck.FindingType]time.Duration
}

type Cache struct {
    mu      sync.RWMutex
    entries map[string]entry
    cfg     Config
    file    string
}

func New(cfg Config) (*Cache, error) {
    if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
        return nil, err
    }
    c := &Cache{
        entries: make(map[string]entry),
        cfg:     cfg,
        file:    filepath.Join(cfg.Dir, "pkgcache.json"),
    }
    c.loadFromDisk()
    return c, nil
}

func (c *Cache) Get(key Key) ([]pkgcheck.Finding, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    e, ok := c.entries[key.String()]
    if !ok {
        return nil, false
    }
    if time.Now().After(e.ExpiresAt) {
        return nil, false
    }
    return e.Findings, true
}

func (c *Cache) Put(key Key, findings []pkgcheck.Finding) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.entries[key.String()] = entry{
        Findings:  findings,
        ExpiresAt: time.Now().Add(c.cfg.DefaultTTL),
    }
}

func (c *Cache) Close() error {
    return c.saveToDisk()
}

func (c *Cache) loadFromDisk() {
    data, err := os.ReadFile(c.file)
    if err != nil {
        return
    }
    var entries map[string]entry
    if err := json.Unmarshal(data, &entries); err != nil {
        return
    }
    c.entries = entries
}

func (c *Cache) saveToDisk() error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    data, err := json.Marshal(c.entries)
    if err != nil {
        return err
    }
    return os.WriteFile(c.file, data, 0600)
}
```

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/cache/ -v
git add internal/pkgcheck/cache/
git commit -m "feat(pkgcheck): add TTL-based disk cache for provider results"
```

---

## Phase 5: Orchestrator & Policy Evaluator

### Task 16: Check orchestrator

**Files:**
- Create: `internal/pkgcheck/orchestrator.go`
- Test: `internal/pkgcheck/orchestrator_test.go`

The orchestrator fans out to all enabled providers in parallel, handles timeouts and failures per provider, and merges results.

**Step 1: Write the test**

```go
// internal/pkgcheck/orchestrator_test.go
package pkgcheck

import (
    "context"
    "errors"
    "testing"
    "time"
)

func TestOrchestratorParallelExecution(t *testing.T) {
    slow := &mockProvider{
        name: "slow",
        capabilities: []FindingType{FindingVulnerability},
        findings: []Finding{{Type: FindingVulnerability, Provider: "slow", Severity: SeverityHigh, Title: "vuln1"}},
    }
    fast := &mockProvider{
        name: "fast",
        capabilities: []FindingType{FindingLicense},
        findings: []Finding{{Type: FindingLicense, Provider: "fast", Severity: SeverityInfo, Title: "MIT"}},
    }

    o := NewOrchestrator(OrchestratorConfig{
        Providers: map[string]ProviderEntry{
            "slow": {Provider: slow, Timeout: 5 * time.Second, OnFailure: "warn"},
            "fast": {Provider: fast, Timeout: 5 * time.Second, OnFailure: "warn"},
        },
    })

    findings, errs := o.CheckAll(context.Background(), &CheckRequest{
        Ecosystem: EcosystemNPM,
        Packages:  []PackageRef{{Name: "express", Version: "5.1.0"}},
    })

    if len(findings) != 2 {
        t.Errorf("got %d findings, want 2", len(findings))
    }
    if len(errs) != 0 {
        t.Errorf("unexpected errors: %v", errs)
    }
}

func TestOrchestratorProviderFailure(t *testing.T) {
    failing := &mockProvider{
        name: "failing",
        capabilities: []FindingType{FindingVulnerability},
        err: errors.New("provider down"),
    }
    working := &mockProvider{
        name: "working",
        capabilities: []FindingType{FindingLicense},
        findings: []Finding{{Type: FindingLicense, Provider: "working", Severity: SeverityInfo, Title: "MIT"}},
    }

    o := NewOrchestrator(OrchestratorConfig{
        Providers: map[string]ProviderEntry{
            "failing": {Provider: failing, Timeout: 1 * time.Second, OnFailure: "warn"},
            "working": {Provider: working, Timeout: 1 * time.Second, OnFailure: "warn"},
        },
    })

    findings, errs := o.CheckAll(context.Background(), &CheckRequest{
        Ecosystem: EcosystemNPM,
        Packages:  []PackageRef{{Name: "express", Version: "5.1.0"}},
    })

    // Working provider's findings should still be returned
    if len(findings) != 1 {
        t.Errorf("got %d findings, want 1", len(findings))
    }
    // Failing provider should produce an error
    if len(errs) != 1 {
        t.Errorf("got %d errors, want 1", len(errs))
    }
}

func TestOrchestratorTimeout(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
    defer cancel()

    slow := &slowMockProvider{delay: 200 * time.Millisecond}

    o := NewOrchestrator(OrchestratorConfig{
        Providers: map[string]ProviderEntry{
            "slow": {Provider: slow, Timeout: 100 * time.Millisecond, OnFailure: "warn"},
        },
    })

    _, errs := o.CheckAll(ctx, &CheckRequest{
        Ecosystem: EcosystemNPM,
        Packages:  []PackageRef{{Name: "foo", Version: "1.0.0"}},
    })
    if len(errs) == 0 {
        t.Error("expected timeout error")
    }
}

type slowMockProvider struct {
    delay time.Duration
}

func (p *slowMockProvider) Name() string                  { return "slow" }
func (p *slowMockProvider) Capabilities() []FindingType   { return []FindingType{FindingVulnerability} }
func (p *slowMockProvider) CheckBatch(ctx context.Context, req *CheckRequest) (*CheckResponse, error) {
    select {
    case <-time.After(p.delay):
        return &CheckResponse{Provider: "slow"}, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}
```

**Step 2: Implement**

```go
// internal/pkgcheck/orchestrator.go
package pkgcheck

import (
    "context"
    "fmt"
    "sync"
    "time"
)

type ProviderEntry struct {
    Provider  CheckProvider
    Timeout   time.Duration
    OnFailure string // "warn" | "deny" | "allow" | "approve"
}

type ProviderError struct {
    Provider  string
    Err       error
    OnFailure string
}

func (e ProviderError) Error() string {
    return fmt.Sprintf("provider %s: %v", e.Provider, e.Err)
}

type OrchestratorConfig struct {
    Providers map[string]ProviderEntry
    Cache     CacheGetter // optional
}

// CacheGetter is the interface the orchestrator uses to check the cache.
type CacheGetter interface {
    Get(provider, ecosystem, pkg, version string) ([]Finding, bool)
    Put(provider, ecosystem, pkg, version string, findings []Finding)
}

type Orchestrator struct {
    cfg OrchestratorConfig
}

func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
    return &Orchestrator{cfg: cfg}
}

// CheckAll runs all enabled providers in parallel and returns merged findings.
func (o *Orchestrator) CheckAll(ctx context.Context, req *CheckRequest) ([]Finding, []ProviderError) {
    var (
        mu       sync.Mutex
        findings []Finding
        errs     []ProviderError
        wg       sync.WaitGroup
    )

    for name, entry := range o.cfg.Providers {
        wg.Add(1)
        go func(name string, entry ProviderEntry) {
            defer wg.Done()

            provCtx, cancel := context.WithTimeout(ctx, entry.Timeout)
            defer cancel()

            resp, err := entry.Provider.CheckBatch(provCtx, req)

            mu.Lock()
            defer mu.Unlock()

            if err != nil {
                errs = append(errs, ProviderError{
                    Provider:  name,
                    Err:       err,
                    OnFailure: entry.OnFailure,
                })
                return
            }
            findings = append(findings, resp.Findings...)
        }(name, entry)
    }

    wg.Wait()
    return findings, errs
}
```

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/ -v -run TestOrchestrator
git add internal/pkgcheck/orchestrator.go internal/pkgcheck/orchestrator_test.go
git commit -m "feat(pkgcheck): add check orchestrator with parallel provider execution"
```

---

### Task 17: Policy evaluator

**Files:**
- Create: `internal/pkgcheck/evaluator.go`
- Test: `internal/pkgcheck/evaluator_test.go`

The evaluator applies `PackageRules` to findings and produces a `Verdict`. First-match-wins, strictest per-package verdict bubbles up.

**Step 1: Write the test**

```go
// internal/pkgcheck/evaluator_test.go
package pkgcheck

import (
    "testing"

    "github.com/canyonroad/agentsh/internal/policy"
)

func TestEvaluatorCriticalVulnBlocks(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{FindingType: "vulnerability", Severity: []string{"critical", "high"}}, Action: "deny", Reason: "high severity vuln"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    e := NewEvaluator(rules)
    findings := []Finding{
        {Type: FindingVulnerability, Package: PackageRef{Name: "foo", Version: "1.0"}, Severity: SeverityCritical, Title: "CVE-2024-1234"},
    }

    verdict := e.Evaluate(findings, EcosystemNPM)
    if verdict.Action != VerdictBlock {
        t.Errorf("expected block, got %q", verdict.Action)
    }
}

func TestEvaluatorLicenseDeny(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{
            FindingType: "license",
            LicenseSPDX: &policy.LicenseSPDXMatch{Deny: []string{"AGPL-3.0-only"}},
        }, Action: "deny", Reason: "copyleft"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    e := NewEvaluator(rules)
    findings := []Finding{
        {Type: FindingLicense, Package: PackageRef{Name: "foo", Version: "1.0"}, Severity: SeverityInfo,
            Metadata: map[string]any{"spdx": "AGPL-3.0-only"}},
    }

    verdict := e.Evaluate(findings, EcosystemNPM)
    if verdict.Action != VerdictBlock {
        t.Errorf("expected block, got %q", verdict.Action)
    }
}

func TestEvaluatorPermissiveLicenseAllows(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{
            FindingType: "license",
            LicenseSPDX: &policy.LicenseSPDXMatch{Allow: []string{"MIT", "Apache-2.0"}},
        }, Action: "allow", Reason: "permissive"},
        {Match: policy.PackageMatch{
            FindingType: "license",
        }, Action: "warn", Reason: "unknown license"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    e := NewEvaluator(rules)
    findings := []Finding{
        {Type: FindingLicense, Package: PackageRef{Name: "foo", Version: "1.0"}, Severity: SeverityInfo,
            Metadata: map[string]any{"spdx": "MIT"}},
    }

    verdict := e.Evaluate(findings, EcosystemNPM)
    if verdict.Action != VerdictAllow {
        t.Errorf("expected allow, got %q", verdict.Action)
    }
}

func TestEvaluatorStaticAllowlist(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{Packages: []string{"trusted-pkg"}}, Action: "allow", Reason: "trusted"},
        {Match: policy.PackageMatch{FindingType: "vulnerability", Severity: []string{"critical"}}, Action: "deny", Reason: "vuln"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    e := NewEvaluator(rules)
    // Even with a critical vuln, trusted-pkg should be allowed by static match
    findings := []Finding{
        {Type: FindingVulnerability, Package: PackageRef{Name: "trusted-pkg", Version: "1.0"}, Severity: SeverityCritical},
    }

    verdict := e.Evaluate(findings, EcosystemNPM)
    // Static allowlist is checked first (pre-provider), so trusted-pkg is allowed
    if verdict.Action != VerdictAllow {
        t.Errorf("expected allow for trusted pkg, got %q", verdict.Action)
    }
}

func TestEvaluatorNoFindings(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }
    e := NewEvaluator(rules)
    verdict := e.Evaluate(nil, EcosystemNPM)
    if verdict.Action != VerdictAllow {
        t.Errorf("expected allow, got %q", verdict.Action)
    }
}

func TestEvaluatorEcosystemScope(t *testing.T) {
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{Ecosystem: "npm", FindingType: "reputation", Reasons: []string{"typosquat"}}, Action: "deny", Reason: "npm typosquat"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }
    e := NewEvaluator(rules)

    // npm ecosystem — should match
    f1 := []Finding{{Type: FindingReputation, Package: PackageRef{Name: "foo", Version: "1.0"}, Reasons: []Reason{{Code: "typosquat"}}}}
    v1 := e.Evaluate(f1, EcosystemNPM)
    if v1.Action != VerdictBlock {
        t.Errorf("npm: expected block, got %q", v1.Action)
    }

    // pypi ecosystem — should not match the npm rule
    v2 := e.Evaluate(f1, EcosystemPyPI)
    if v2.Action != VerdictAllow {
        t.Errorf("pypi: expected allow, got %q", v2.Action)
    }
}
```

**Step 2: Implement**

The evaluator iterates rules in order (first-match-wins). For each finding, it finds the first matching rule. The strictest verdict across all findings becomes the overall verdict. Maps `deny` action to `VerdictBlock`, `approve` to `VerdictApprove`, `warn` to `VerdictWarn`, `allow` to `VerdictAllow`.

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/ -v -run TestEvaluator
git add internal/pkgcheck/evaluator.go internal/pkgcheck/evaluator_test.go
git commit -m "feat(pkgcheck): add policy evaluator with first-match-wins rule engine"
```

---

## Phase 6: Network Allowlist

### Task 18: Network allowlist gate

**Files:**
- Create: `internal/pkgcheck/allowlist.go`
- Test: `internal/pkgcheck/allowlist_test.go`

Short-lived in-memory allowlist of approved `(registry, package, version)` tuples.

**Step 1: Write the test**

```go
// internal/pkgcheck/allowlist_test.go
package pkgcheck

import (
    "testing"
    "time"
)

func TestAllowlistAddAndCheck(t *testing.T) {
    al := NewAllowlist(5 * time.Second)

    al.Add("https://registry.npmjs.org", "express", "5.1.0")

    if !al.IsAllowed("https://registry.npmjs.org", "express", "5.1.0") {
        t.Error("expected allowed")
    }
    if al.IsAllowed("https://registry.npmjs.org", "lodash", "4.17.21") {
        t.Error("expected not allowed")
    }
}

func TestAllowlistExpiry(t *testing.T) {
    al := NewAllowlist(10 * time.Millisecond)
    al.Add("https://registry.npmjs.org", "express", "5.1.0")

    time.Sleep(20 * time.Millisecond)

    if al.IsAllowed("https://registry.npmjs.org", "express", "5.1.0") {
        t.Error("expected expired")
    }
}

func TestAllowlistReadOnlyAPIs(t *testing.T) {
    al := NewAllowlist(5 * time.Second)

    // Read-only registry API calls should always be allowed
    if !al.IsReadOnlyRegistryCall("/express") {
        t.Error("npm view should be read-only")
    }
    if al.IsReadOnlyRegistryCall("/express/-/express-5.1.0.tgz") {
        t.Error("tarball download should not be read-only")
    }
}
```

**Step 2: Implement**

```go
// internal/pkgcheck/allowlist.go
package pkgcheck

import (
    "strings"
    "sync"
    "time"
)

type allowEntry struct {
    expiresAt time.Time
}

type Allowlist struct {
    mu      sync.RWMutex
    entries map[string]allowEntry
    ttl     time.Duration
}

func NewAllowlist(ttl time.Duration) *Allowlist {
    return &Allowlist{
        entries: make(map[string]allowEntry),
        ttl:     ttl,
    }
}

func (a *Allowlist) Add(registry, pkg, version string) {
    a.mu.Lock()
    defer a.mu.Unlock()
    key := registry + ":" + pkg + ":" + version
    a.entries[key] = allowEntry{expiresAt: time.Now().Add(a.ttl)}
}

func (a *Allowlist) IsAllowed(registry, pkg, version string) bool {
    a.mu.RLock()
    defer a.mu.RUnlock()
    key := registry + ":" + pkg + ":" + version
    entry, ok := a.entries[key]
    if !ok {
        return false
    }
    return time.Now().Before(entry.expiresAt)
}

// IsReadOnlyRegistryCall returns true for registry metadata requests
// that don't download tarballs (e.g., "npm view", "pip index versions").
func (a *Allowlist) IsReadOnlyRegistryCall(urlPath string) bool {
    // Tarball downloads contain /-/ in the path
    if strings.Contains(urlPath, "/-/") {
        return false
    }
    // PyPI download URLs contain /packages/ in the path
    if strings.Contains(urlPath, "/packages/") {
        return false
    }
    return true
}
```

**Step 3: Run tests and commit**

```bash
go test ./internal/pkgcheck/ -v -run TestAllowlist
git add internal/pkgcheck/allowlist.go internal/pkgcheck/allowlist_test.go
git commit -m "feat(pkgcheck): add network allowlist gate for registry enforcement"
```

---

## Phase 7: Integration

### Task 19: Wire package checks into command interception

**Files:**
- Create: `internal/pkgcheck/checker.go` — top-level `Checker` that ties everything together
- Test: `internal/pkgcheck/checker_test.go`
- Modify: `internal/api/core.go` — call `Checker` in the command pre-check flow
- Modify: `internal/server/server.go` — initialize `Checker` from config

The `Checker` is the single entry point called from the command interception path. It:
1. Classifies the command via `ClassifyInstallCommand`
2. If it's an install, resolves the plan via the resolver registry
3. Checks static PackageRules (pre-provider fast path)
4. Runs the orchestrator
5. Evaluates findings via the policy evaluator
6. Returns a verdict
7. Updates the network allowlist if allowed

**Step 1: Write the test**

```go
// internal/pkgcheck/checker_test.go
package pkgcheck

import (
    "context"
    "testing"
    "time"

    "github.com/canyonroad/agentsh/internal/policy"
)

func TestCheckerEndToEnd(t *testing.T) {
    resolver := &mockResolver{
        name: "npm",
        can:  true,
        plan: &InstallPlan{
            Tool:      "npm",
            Ecosystem: EcosystemNPM,
            Direct:    []PackageRef{{Name: "safe-pkg", Version: "1.0.0", Direct: true}},
        },
    }

    provider := &mockProvider{
        name: "test",
        capabilities: []FindingType{FindingVulnerability},
        findings: []Finding{}, // no findings = clean
    }

    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    checker := NewChecker(CheckerConfig{
        Scope:      "new_packages_only",
        Resolvers:  []Resolver{resolver},
        Providers:  map[string]ProviderEntry{"test": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "warn"}},
        Rules:      rules,
        Allowlist:  NewAllowlist(30 * time.Second),
    })

    verdict, err := checker.Check(context.Background(), "npm", []string{"install", "safe-pkg"}, "/tmp")
    if err != nil {
        t.Fatal(err)
    }
    if verdict == nil {
        t.Fatal("expected verdict for install command")
    }
    if verdict.Action != VerdictAllow {
        t.Errorf("expected allow, got %q", verdict.Action)
    }
}

func TestCheckerNonInstallCommand(t *testing.T) {
    checker := NewChecker(CheckerConfig{Scope: "new_packages_only"})
    verdict, err := checker.Check(context.Background(), "ls", []string{"-la"}, "/tmp")
    if err != nil {
        t.Fatal(err)
    }
    if verdict != nil {
        t.Error("expected nil verdict for non-install command")
    }
}

func TestCheckerBlockedPackage(t *testing.T) {
    resolver := &mockResolver{
        name: "npm",
        can:  true,
        plan: &InstallPlan{
            Tool:      "npm",
            Ecosystem: EcosystemNPM,
            Direct:    []PackageRef{{Name: "evil-pkg", Version: "1.0.0", Direct: true}},
        },
    }
    provider := &mockProvider{
        name: "test",
        capabilities: []FindingType{FindingMalware},
        findings: []Finding{
            {Type: FindingMalware, Provider: "test", Package: PackageRef{Name: "evil-pkg", Version: "1.0.0"}, Severity: SeverityCritical, Title: "Malware detected"},
        },
    }
    rules := []policy.PackageRule{
        {Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny", Reason: "malware"},
        {Match: policy.PackageMatch{}, Action: "allow", Reason: "default"},
    }

    checker := NewChecker(CheckerConfig{
        Scope:     "new_packages_only",
        Resolvers: []Resolver{resolver},
        Providers: map[string]ProviderEntry{"test": {Provider: provider, Timeout: 5 * time.Second, OnFailure: "warn"}},
        Rules:     rules,
        Allowlist: NewAllowlist(30 * time.Second),
    })

    verdict, err := checker.Check(context.Background(), "npm", []string{"install", "evil-pkg"}, "/tmp")
    if err != nil {
        t.Fatal(err)
    }
    if verdict.Action != VerdictBlock {
        t.Errorf("expected block, got %q", verdict.Action)
    }
}
```

**Step 2: Implement `Checker`**

```go
// internal/pkgcheck/checker.go
package pkgcheck

import (
    "context"
    "fmt"
    "strings"

    "github.com/canyonroad/agentsh/internal/policy"
)

type CheckerConfig struct {
    Scope     string // "new_packages_only" | "all_installs"
    Resolvers []Resolver
    Providers map[string]ProviderEntry
    Rules     []policy.PackageRule
    Allowlist *Allowlist
    Cache     CacheGetter // optional
}

type Checker struct {
    cfg       CheckerConfig
    orch      *Orchestrator
    eval      *Evaluator
}

func NewChecker(cfg CheckerConfig) *Checker {
    return &Checker{
        cfg:  cfg,
        orch: NewOrchestrator(OrchestratorConfig{Providers: cfg.Providers, Cache: cfg.Cache}),
        eval: NewEvaluator(cfg.Rules),
    }
}

// Check evaluates a command. Returns nil verdict if the command is not an install.
func (c *Checker) Check(ctx context.Context, command string, args []string, workDir string) (*Verdict, error) {
    // 1. Classify
    intent := ClassifyInstallCommand(command, args, c.cfg.Scope)
    if intent == nil {
        return nil, nil // not an install command
    }

    // 2. Find resolver
    var resolver Resolver
    for _, r := range c.cfg.Resolvers {
        if r.CanResolve(command, args) {
            resolver = r
            break
        }
    }
    if resolver == nil {
        return nil, fmt.Errorf("no resolver for %s", command)
    }

    // 3. Resolve install plan
    plan, err := resolver.Resolve(ctx, command, args, workDir)
    if err != nil {
        return nil, fmt.Errorf("resolution failed: %w", err)
    }

    // 4. Run provider checks
    findings, providerErrs := c.orch.CheckAll(ctx, &CheckRequest{
        Ecosystem: plan.Ecosystem,
        Packages:  plan.AllPackages(),
    })

    // 5. Handle provider errors per on_failure config
    for _, pe := range providerErrs {
        switch pe.OnFailure {
        case "deny":
            return &Verdict{
                Action:  VerdictBlock,
                Summary: fmt.Sprintf("Provider %s unavailable (on_failure=deny): %v", pe.Provider, pe.Err),
            }, nil
        case "approve":
            findings = append(findings, Finding{
                Type:     FindingReputation,
                Provider: pe.Provider,
                Severity: SeverityInfo,
                Title:    fmt.Sprintf("Provider %s unavailable", pe.Provider),
                Reasons:  []Reason{{Code: "provider_unavailable", Message: pe.Err.Error()}},
            })
        }
        // "warn" and "allow" — continue without blocking
    }

    // 6. Evaluate
    verdict := c.eval.Evaluate(findings, plan.Ecosystem)

    // 7. If allowed, populate network allowlist
    if verdict.Action == VerdictAllow || verdict.Action == VerdictWarn {
        if c.cfg.Allowlist != nil {
            for _, pkg := range plan.AllPackages() {
                registry := pkg.Registry
                if registry == "" {
                    registry = plan.Registry
                }
                c.cfg.Allowlist.Add(registry, pkg.Name, pkg.Version)
            }
        }
    }

    // 8. Build summary
    if verdict.Summary == "" {
        verdict.Summary = buildSummary(verdict, plan)
    }

    return &verdict, nil
}

func buildSummary(v Verdict, plan *InstallPlan) string {
    var b strings.Builder
    switch v.Action {
    case VerdictAllow:
        fmt.Fprintf(&b, "Package install allowed (%d direct, %d transitive)", len(plan.Direct), len(plan.Transitive))
    case VerdictWarn:
        fmt.Fprintf(&b, "Package install allowed with %d warning(s)", len(v.Findings))
    case VerdictApprove:
        fmt.Fprintf(&b, "Package install requires approval — %d finding(s)", len(v.Findings))
    case VerdictBlock:
        fmt.Fprintf(&b, "Package install blocked — %d finding(s)", len(v.Findings))
    }
    return b.String()
}
```

**Step 3: Wire into `internal/api/core.go`**

In the `runCommand` function (around line 650 where `CheckCommand` is called), add package check logic:

```go
// After the existing CheckCommand call, before executing the command:
if a.pkgChecker != nil {
    verdict, err := a.pkgChecker.Check(ctx, req.Command, req.Args, req.WorkDir)
    if err != nil {
        // Log error but don't block (resolution failure)
        a.logger.Warn("package check error", "err", err)
    } else if verdict != nil {
        // Emit audit event
        a.emitPackageCheckEvent(ctx, sessionID, commandID, verdict)

        switch verdict.Action {
        case pkgcheck.VerdictBlock:
            return nil, fmt.Errorf("package install blocked: %s", verdict.Summary)
        case pkgcheck.VerdictApprove:
            // Use existing approval flow with extended payload
            approved, err := a.requestPackageApproval(ctx, sessionID, commandID, verdict)
            if err != nil || !approved {
                return nil, fmt.Errorf("package install not approved: %s", verdict.Summary)
            }
        case pkgcheck.VerdictWarn:
            // Log warning, continue
            a.logger.Warn("package install warning", "summary", verdict.Summary)
        }
    }
}
```

**Step 4: Wire initialization in `internal/server/server.go`**

```go
// In the server initialization, after loading config and policy:
if cfg.PackageChecks.Enabled {
    pkgChecker := pkgcheck.NewCheckerFromConfig(cfg.PackageChecks, policyEngine)
    api.SetPackageChecker(pkgChecker)
}
```

**Step 5: Run all tests**

```bash
go test ./internal/pkgcheck/ -v
go test ./internal/api/ -v
go build ./...
GOOS=windows go build ./...
```

**Step 6: Commit**

```bash
git add internal/pkgcheck/checker.go internal/pkgcheck/checker_test.go internal/api/core.go internal/server/server.go
git commit -m "feat(pkgcheck): wire package checks into command interception flow"
```

---

### Task 20: Approval integration with extended payload

**Files:**
- Modify: `internal/api/core.go` — add `requestPackageApproval` method
- Modify: `internal/api/core.go` — add `emitPackageCheckEvent` method

Follow the existing pattern from `approvalRequesterAdapter.RequestExecApproval` in `internal/api/notify_linux.go`:

```go
func (a *API) requestPackageApproval(ctx context.Context, sessionID, commandID string, verdict *pkgcheck.Verdict) (bool, error) {
    req := approvals.Request{
        ID:        "pkg-" + uuid.NewString(),
        SessionID: sessionID,
        CommandID: commandID,
        Kind:      "package",
        Target:    verdict.Summary,
        Message:   formatVerdictMessage(verdict),
        Fields: map[string]any{
            "source":   "package_check",
            "action":   string(verdict.Action),
            "findings": verdict.Findings,
            "packages": verdict.Packages,
        },
    }
    res, err := a.approvalMgr.RequestApproval(ctx, req)
    if err != nil {
        return false, err
    }
    return res.Approved, nil
}
```

Follow the existing event emission pattern for audit events:

```go
func (a *API) emitPackageCheckEvent(ctx context.Context, sessionID, commandID string, verdict *pkgcheck.Verdict) {
    evType := events.EventPackageCheckCompleted
    switch verdict.Action {
    case pkgcheck.VerdictBlock:
        evType = events.EventPackageBlocked
    case pkgcheck.VerdictApprove:
        evType = events.EventPackageApproved
    case pkgcheck.VerdictWarn:
        evType = events.EventPackageWarning
    }

    ev := types.Event{
        ID:        uuid.NewString(),
        Timestamp: time.Now().UTC(),
        Type:      string(evType),
        SessionID: sessionID,
        CommandID: commandID,
        Policy: &types.PolicyInfo{
            Decision:          types.Decision(verdict.Action),
            EffectiveDecision: types.Decision(verdict.Action),
        },
        Fields: map[string]any{
            "findings_count": len(verdict.Findings),
            "summary":        verdict.Summary,
            "packages":       verdict.Packages,
        },
    }
    _ = a.store.AppendEvent(ctx, ev)
    a.broker.Publish(ev)
}
```

**Commit:**

```bash
git add internal/api/core.go
git commit -m "feat(pkgcheck): add approval integration and audit event emission"
```

---

### Task 21: Integration test

**Files:**
- Create: `internal/pkgcheck/integration_test.go`

End-to-end test that simulates the full flow with mock providers:

```go
// internal/pkgcheck/integration_test.go
package pkgcheck_test

import (
    "context"
    "testing"
    "time"

    "github.com/canyonroad/agentsh/internal/pkgcheck"
    "github.com/canyonroad/agentsh/internal/policy"
)

func TestIntegrationBlockCriticalVuln(t *testing.T) {
    // Set up a full checker with mock resolver + mock OSV provider
    // that returns a critical vuln for "bad-pkg@1.0.0"
    // Verify: verdict is Block, findings are correct, allowlist is NOT populated
}

func TestIntegrationAllowCleanPackage(t *testing.T) {
    // Set up checker with mock resolver + providers returning no findings
    // Verify: verdict is Allow, allowlist IS populated
}

func TestIntegrationWarnMediumVuln(t *testing.T) {
    // Verify: verdict is Warn, allowlist IS populated (warn = proceed)
}

func TestIntegrationApproveNewPackage(t *testing.T) {
    // Provider returns package_too_new finding
    // Verify: verdict is Approve
}

func TestIntegrationProviderDown(t *testing.T) {
    // One provider fails with on_failure=warn
    // Other provider returns clean
    // Verify: verdict is Allow (degraded gracefully)
}

func TestIntegrationCacheHit(t *testing.T) {
    // Run check twice for same package
    // Verify: second check is faster (cache hit)
}
```

**Commit:**

```bash
git add internal/pkgcheck/integration_test.go
git commit -m "test(pkgcheck): add integration tests for full check flow"
```

---

### Task 22: Cross-compilation verification

**Step 1:** Verify everything compiles

```bash
go build ./...
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

**Step 2:** Run full test suite

```bash
go test ./internal/pkgcheck/... -v
go test ./internal/config/ -v -run TestPackageChecks
go test ./internal/policy/ -v -run TestPackageRule
go test ./internal/events/ -v -run TestPackageCheck
```

**Step 3:** Commit any fixes

```bash
git commit -m "fix(pkgcheck): cross-compilation fixes"
```

---

## Summary

| Phase | Tasks | What it delivers |
|-------|-------|-----------------|
| 1: Foundation | 1-5 | Types, config, events, policy model |
| 2: Interceptor & Resolvers | 6-9 | Command classification, dry-run resolution for 6 tools |
| 3: Providers | 10-14 | 5 built-in providers + exec protocol |
| 4: Cache | 15 | TTL-based disk cache |
| 5: Orchestrator & Evaluator | 16-17 | Parallel provider execution, policy evaluation |
| 6: Network Allowlist | 18 | Registry enforcement gate |
| 7: Integration | 19-22 | Full wiring, approval, audit events, integration tests |

Total: 22 tasks, each with TDD steps (test → fail → implement → pass → commit).
