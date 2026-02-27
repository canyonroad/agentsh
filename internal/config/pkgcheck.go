package config

import "time"

// PackageChecksConfig configures package install security checks.
type PackageChecksConfig struct {
	Enabled    bool                         `yaml:"enabled"`
	Scope      string                       `yaml:"scope"`      // "direct", "all"
	Cache      PackageCacheConfig           `yaml:"cache"`
	Registries map[string]RegistryTrustConfig `yaml:"registries"`
	Providers  map[string]ProviderConfig    `yaml:"providers"`
	Resolvers  map[string]ResolverConfig    `yaml:"resolvers"`
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
	Type      string         `yaml:"type,omitempty"`       // "" (built-in) | "exec"
	Command   string         `yaml:"command,omitempty"`    // for exec providers
	Priority  int            `yaml:"priority"`
	Timeout   time.Duration  `yaml:"timeout"`
	OnFailure string         `yaml:"on_failure"`           // "warn" | "deny" | "allow" | "approve"
	APIKeyEnv string         `yaml:"api_key_env,omitempty"`
	Options   map[string]any `yaml:"options,omitempty"`
}

// ResolverConfig configures a single lock-file resolver.
type ResolverConfig struct {
	DryRunCommand string        `yaml:"dry_run_command"`
	Timeout       time.Duration `yaml:"timeout"`
}

// DefaultPackageChecksConfig returns the default configuration for package checks.
func DefaultPackageChecksConfig() PackageChecksConfig {
	return PackageChecksConfig{
		Enabled: false,
		Scope:   "direct",
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
