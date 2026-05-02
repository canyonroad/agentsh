package config

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

// PackageChecksConfig configures package install security checks.
type PackageChecksConfig struct {
	Enabled    bool                           `yaml:"enabled"`
	Scope      string                         `yaml:"scope"` // "new_packages_only", "all_installs"
	Cache      PackageCacheConfig             `yaml:"cache"`
	Registries map[string]RegistryTrustConfig `yaml:"registries"`
	Providers  map[string]ProviderConfig      `yaml:"providers"`
	Resolvers  map[string]ResolverConfig      `yaml:"resolvers"`
	Privacy    PackagePrivacyConfig           `yaml:"privacy" json:"privacy"`
	// FailMode controls how the orchestrator reacts to provider failures
	// for external providers (Snyk / Socket / etc.). One of:
	//   "open"     — let the install proceed when an external provider fails.
	//   "closed"   — block the install when an external provider fails.
	//   "degraded" — fall back to OSV findings, annotate the verdict.
	// The env var PKGCHECK_FAIL_MODE overrides this at runtime.
	FailMode string `yaml:"fail_mode" json:"fail_mode"`
	// BlockOn is the per-finding-type severity-threshold shorthand that
	// compiles to a list of policy rules via CompileBlockOn.
	BlockOn BlockOnConfig `yaml:"block_on" json:"block_on"`
}

// PackagePrivacyConfig configures the upstream privacy filter applied
// before any external (Snyk / Socket / etc.) provider is invoked.
//
// LIMITATION: registry detection is CLI-flag-only. If your installs
// rely on .npmrc / pip.conf / env-var registry overrides, ALSO list
// those registries in ExternalScanRegistries — otherwise private
// packages may be treated as public and sent to external providers.
type PackagePrivacyConfig struct {
	// ExternalScanRegistries lists registries whose packages may be sent
	// to external providers. An empty list means "no registry filter."
	ExternalScanRegistries []string `yaml:"external_scan_registries" json:"external_scan_registries"`
	// PrivateScopeDenylist lists package name prefixes / glob patterns
	// that should NOT be sent externally even when on an allowed registry.
	PrivateScopeDenylist []string `yaml:"private_scope_denylist" json:"private_scope_denylist"`
}

// Validate checks that all PrivateScopeDenylist entries are valid glob
// patterns.  A malformed pattern would silently match nothing at runtime,
// producing a fail-open privacy hole.  Call this at config-load time so
// operators see a startup error instead of silent misbehaviour.
func (p PackagePrivacyConfig) Validate() error {
	for _, pat := range p.PrivateScopeDenylist {
		if pat == "" {
			continue
		}
		if _, err := path.Match(pat, "test"); err != nil {
			return fmt.Errorf("invalid denylist pattern %q: %w", pat, err)
		}
	}
	return nil
}

// PackageCacheConfig configures the on-disk check result cache.
type PackageCacheConfig struct {
	Dir string          `yaml:"dir"`
	TTL PackageCacheTTL `yaml:"ttl"`
}

// PackageCacheTTL defines per-result-type cache lifetimes.
type PackageCacheTTL struct {
	Vulnerability time.Duration `yaml:"vulnerability"`
	License       time.Duration `yaml:"license"`
	Provenance    time.Duration `yaml:"provenance"`
	Reputation    time.Duration `yaml:"reputation"`
	Malware       time.Duration `yaml:"malware"`
}

// RegistryTrustConfig defines trust settings for a package registry.
type RegistryTrustConfig struct {
	Trust  string   `yaml:"trust"`            // "check_full" | "check_local_only" | "trusted"
	Scopes []string `yaml:"scopes,omitempty"` // e.g., ["@acme"]
}

// ProviderConfig configures a single check provider.
type ProviderConfig struct {
	Enabled   bool           `yaml:"enabled"`
	Type      string         `yaml:"type,omitempty"`    // "" (built-in) | "exec"
	Command   string         `yaml:"command,omitempty"` // for exec providers
	Priority  int            `yaml:"priority"`
	Timeout   time.Duration  `yaml:"timeout"`
	OnFailure string         `yaml:"on_failure"` // "warn" | "deny" | "allow" | "approve"
	APIKeyEnv string         `yaml:"api_key_env,omitempty"`
	Options   map[string]any `yaml:"options,omitempty"`
}

// ResolverConfig configures a single lock-file resolver.
type ResolverConfig struct {
	// DryRunCommand is the path to the resolver binary.
	// For additional args to prepend to the resolver-specific args, use DryRunArgs.
	DryRunCommand string        `yaml:"dry_run_command" json:"dry_run_command"`
	// DryRunArgs contains args to prepend to the resolver-specific args.
	// Each element is a single token (no shell splitting is performed).
	DryRunArgs    []string      `yaml:"dry_run_args" json:"dry_run_args"`
	Timeout       time.Duration `yaml:"timeout"`
}

// Validate returns an error if the configuration is malformed.
//
// DryRunCommand is the binary path. Paths with spaces (e.g. Windows
// `C:\Program Files\nodejs\npm.cmd`) are valid — the resolver preserves
// them verbatim. The validator only rejects values that look like the
// pre-`dry_run_args` command-string form, where additional whitespace-
// separated tokens include a flag-shaped argument (`--foo` or `-x`),
// which the new code can no longer interpret.
func (r ResolverConfig) Validate() error {
	if r.DryRunCommand == "" {
		return nil
	}
	if !strings.ContainsAny(r.DryRunCommand, " \t") {
		return nil
	}
	// Heuristic: a multi-token value with a flag-shaped token after the
	// first whitespace is the legacy command-string form.
	for _, tok := range strings.Fields(r.DryRunCommand)[1:] {
		if strings.HasPrefix(tok, "-") {
			return fmt.Errorf("dry_run_command must be a binary path; "+
				"multi-token command strings are no longer supported — "+
				"split arguments into dry_run_args. Got: %q", r.DryRunCommand)
		}
	}
	return nil
}

// SkillcheckConfig configures the skillcheck daemon that scans Claude Code
// skill installations under ~/.claude/skills and plugin skill directories.
type SkillcheckConfig struct {
	Enabled    bool                                `yaml:"enabled" json:"enabled"`
	WatchRoots []string                            `yaml:"watch_roots" json:"watch_roots"`
	CacheDir   string                              `yaml:"cache_dir" json:"cache_dir"`
	TrashDir   string                              `yaml:"trash_dir" json:"trash_dir"`
	Limits     SkillcheckLimits                    `yaml:"scan_size_limits" json:"scan_size_limits"`
	Thresholds map[string]string                   `yaml:"thresholds" json:"thresholds"`
	Providers  map[string]SkillcheckProviderConfig `yaml:"providers" json:"providers"`
}

// SkillcheckLimits configures per-file and total byte limits for skill scanning.
type SkillcheckLimits struct {
	PerFileBytes int64 `yaml:"per_file_bytes" json:"per_file_bytes"`
	TotalBytes   int64 `yaml:"total_bytes" json:"total_bytes"`
}

// SkillcheckProviderConfig configures a single skillcheck provider.
type SkillcheckProviderConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	OnFailure   string        `yaml:"on_failure" json:"on_failure"`
	BinaryPath  string        `yaml:"binary_path,omitempty" json:"binary_path,omitempty"`   // snyk
	BaseURL     string        `yaml:"base_url,omitempty" json:"base_url,omitempty"`         // skills_sh
	ProbeAudits bool          `yaml:"probe_audits,omitempty" json:"probe_audits,omitempty"` // skills_sh
}

// DefaultPackageChecksConfig returns the default configuration for package checks.
func DefaultPackageChecksConfig() PackageChecksConfig {
	return PackageChecksConfig{
		Enabled: false,
		Scope:   "new_packages_only",
		Cache: PackageCacheConfig{
			Dir: "",
			TTL: PackageCacheTTL{
				Vulnerability: 1 * time.Hour,
				License:       24 * time.Hour,
				Provenance:    24 * time.Hour,
				Reputation:    6 * time.Hour,
				Malware:       1 * time.Hour,
			},
		},
		Registries: nil,
		Providers: map[string]ProviderConfig{
			"osv": {
				Enabled:   true,
				Priority:  1,
				Timeout:   10 * time.Second,
				OnFailure: "warn",
			},
			"depsdev": {
				Enabled:   true,
				Priority:  2,
				Timeout:   10 * time.Second,
				OnFailure: "warn",
			},
			"local": {
				Enabled:   true,
				Priority:  0,
				OnFailure: "warn",
			},
		},
		Resolvers: nil,
		FailMode:  "degraded",
		Privacy: PackagePrivacyConfig{
			ExternalScanRegistries: []string{
				"registry.npmjs.org",
				"pypi.org",
				// pip's default --index-url; users running `pip install
				// --index-url https://pypi.org/simple` should still hit
				// the allowlist. We can't simply strip the path during
				// normalization because that would conflate distinct
				// paths on a shared private host.
				"pypi.org/simple",
			},
			PrivateScopeDenylist: nil,
		},
		BlockOn: BlockOnConfig{
			Malware:       "any",
			Vulnerability: "critical",
			License:       "never",
			Reputation:    "never",
			Provenance:    "never",
		},
	}
}

// BlockOnConfig is the per-finding-type severity-threshold shorthand:
//
//	malware:       any | critical | never
//	vulnerability: critical | high | medium | never
//	license:       any | never
//	reputation:    any | never
//	provenance:    any | never
type BlockOnConfig struct {
	Malware       string `yaml:"malware" json:"malware"`
	Vulnerability string `yaml:"vulnerability" json:"vulnerability"`
	License       string `yaml:"license" json:"license"`
	Reputation    string `yaml:"reputation" json:"reputation"`
	Provenance    string `yaml:"provenance" json:"provenance"`
}

// Validate ensures every field in BlockOnConfig holds an enum value from its
// documented set. Empty strings are permitted (treated as "no rule for this
// finding type"). Unknown values fail loudly so a typo like "critcal" doesn't
// compile to permissive policy.
func (b BlockOnConfig) Validate() error {
	for _, kv := range []struct {
		name  string
		value string
		valid []string
	}{
		{"malware", b.Malware, []string{"", "any", "critical", "never"}},
		{"vulnerability", b.Vulnerability, []string{"", "critical", "high", "medium", "never"}},
		{"license", b.License, []string{"", "any", "never"}},
		{"reputation", b.Reputation, []string{"", "any", "never"}},
		{"provenance", b.Provenance, []string{"", "any", "never"}},
	} {
		if !blockOnContains(kv.valid, kv.value) {
			return fmt.Errorf("block_on.%s=%q invalid (must be one of %v)", kv.name, kv.value, kv.valid)
		}
	}
	return nil
}

// blockOnContains reports whether needle is in haystack.
func blockOnContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// CompileBlockOn translates the BlockOnConfig shorthand into a list of
// policy.PackageRule entries (first-match-wins) ending in a catch-all allow.
//
// For each finding type we emit deny rules for severities at or above the
// threshold, warn rules for severities below the threshold but still
// noteworthy (currently: high vulns become warn even when threshold is
// critical), and rely on the catch-all allow for everything else.
func CompileBlockOn(b BlockOnConfig) []policy.PackageRule {
	var rules []policy.PackageRule

	// Malware: any (deny all severities) or critical (deny only critical).
	switch b.Malware {
	case "any":
		rules = append(rules, policy.PackageRule{
			Match:  policy.PackageMatch{FindingType: "malware"},
			Action: "deny",
			Reason: "block_on.malware=any",
		})
	case "critical":
		rules = append(rules, policy.PackageRule{
			Match:  policy.PackageMatch{FindingType: "malware", Severity: "critical"},
			Action: "deny",
			Reason: "block_on.malware=critical",
		})
	}

	// Vulnerability thresholds.
	switch b.Vulnerability {
	case "medium":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "medium"}, Action: "deny"},
		)
	case "high":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "deny"},
		)
	case "critical":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "warn"},
		)
	}

	// License / reputation / provenance: any → deny; never → no rule (catch-all allows).
	for _, kv := range []struct{ ft, mode string }{
		{"license", b.License}, {"reputation", b.Reputation}, {"provenance", b.Provenance},
	} {
		if kv.mode == "any" {
			rules = append(rules, policy.PackageRule{
				Match:  policy.PackageMatch{FindingType: kv.ft},
				Action: "deny",
				Reason: "block_on." + kv.ft + "=any",
			})
		}
	}

	// Catch-all allow.
	rules = append(rules, policy.PackageRule{
		Match:  policy.PackageMatch{},
		Action: "allow",
		Reason: "block_on default allow",
	})
	return rules
}

// externalProviderNames lists provider names that send package data to a
// third-party API and therefore benefit from privacy filtering and
// scope=all_installs.
var externalProviderNames = []string{"snyk", "socket"}

// ApplyExternalProviderDefaults adjusts cfg in-place when one or more
// external providers are enabled:
//   - if Scope is unset, promote to "all_installs"
//   - if Scope is "new_packages_only", emit a validation warning naming
//     the external provider(s) and recommending "all_installs"
//
// Returns a list of human-readable warnings the caller should surface.
func ApplyExternalProviderDefaults(cfg *PackageChecksConfig) []string {
	var enabledExternal []string
	for _, name := range externalProviderNames {
		p, ok := cfg.Providers[name]
		if ok && p.Enabled {
			enabledExternal = append(enabledExternal, name)
		}
	}
	if len(enabledExternal) == 0 {
		return nil
	}
	switch cfg.Scope {
	case "":
		cfg.Scope = "all_installs"
		return nil
	case "new_packages_only":
		return []string{
			fmt.Sprintf(
				"pkgcheck: %s configured but scope=new_packages_only — bare `npm install` and `npm ci` will not be intercepted, "+
					"so supply-chain attacks via lockfile installs will not be blocked. Set scope: all_installs for full coverage.",
				strings.Join(enabledExternal, ", "),
			),
		}
	}
	return nil
}

// ResolveFailMode returns the effective fail mode, honoring the
// PKGCHECK_FAIL_MODE env var override. Defaults to "degraded".
func ResolveFailMode(cfg *PackageChecksConfig) string {
	if v := os.Getenv("PKGCHECK_FAIL_MODE"); v != "" {
		return v
	}
	if cfg.FailMode != "" {
		return cfg.FailMode
	}
	return "degraded"
}

// ApplyFailMode sets OnFailure on every enabled external provider to match
// the resolved fail mode. Mapping:
//
//	open     → "allow"
//	closed   → "deny"
//	degraded → "warn"
//
// External providers are those listed in externalProviderNames. Other
// providers (osv, depsdev, local) keep whatever OnFailure the user set.
//
// Per-provider explicit `on_failure` always wins: if a provider already
// has a non-empty OnFailure, it is preserved. Fail mode only fills in
// providers that did not configure on_failure themselves, so an operator
// can override the global mode for a single provider.
func ApplyFailMode(cfg *PackageChecksConfig, mode string) {
	target := ""
	switch mode {
	case "open":
		target = "allow"
	case "closed":
		target = "deny"
	case "degraded":
		target = "warn"
	default:
		// unknown mode — caller should have validated via validateConfig;
		// leave config untouched rather than silently mapping to warn.
		return
	}
	for _, name := range externalProviderNames {
		p, ok := cfg.Providers[name]
		if !ok || !p.Enabled {
			continue
		}
		if p.OnFailure != "" {
			// Operator explicitly set on_failure on this provider — keep it.
			continue
		}
		p.OnFailure = target
		cfg.Providers[name] = p
	}
}
