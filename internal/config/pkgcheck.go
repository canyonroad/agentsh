package config

import "time"

// PackageChecksConfig configures package install security checks.
type PackageChecksConfig struct {
	Enabled    bool                           `yaml:"enabled"`
	Scope      string                         `yaml:"scope"` // "new_packages_only", "all_installs"
	Cache      PackageCacheConfig             `yaml:"cache"`
	Registries map[string]RegistryTrustConfig `yaml:"registries"`
	Providers  map[string]ProviderConfig      `yaml:"providers"`
	Resolvers  map[string]ResolverConfig      `yaml:"resolvers"`
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
	DryRunCommand string        `yaml:"dry_run_command"`
	Timeout       time.Duration `yaml:"timeout"`
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
	}
}
