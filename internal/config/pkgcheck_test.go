package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultPackageChecksConfig(t *testing.T) {
	cfg := DefaultPackageChecksConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "direct", cfg.Scope)
	assert.Equal(t, 1*time.Hour, cfg.Cache.TTL.Vulnerability)
	assert.Equal(t, 24*time.Hour, cfg.Cache.TTL.License)
	assert.Equal(t, 24*time.Hour, cfg.Cache.TTL.Provenance)
	assert.Equal(t, 6*time.Hour, cfg.Cache.TTL.Reputation)
	assert.Equal(t, 1*time.Hour, cfg.Cache.TTL.Malware)
	assert.Nil(t, cfg.Registries)
	assert.Nil(t, cfg.Resolvers)

	// Providers should have defaults
	require.NotNil(t, cfg.Providers)
	require.Len(t, cfg.Providers, 3)

	osv := cfg.Providers["osv"]
	assert.True(t, osv.Enabled)
	assert.Equal(t, 1, osv.Priority)
	assert.Equal(t, 10*time.Second, osv.Timeout)
	assert.Equal(t, "warn", osv.OnFailure)

	depsdev := cfg.Providers["depsdev"]
	assert.True(t, depsdev.Enabled)
	assert.Equal(t, 2, depsdev.Priority)
	assert.Equal(t, 10*time.Second, depsdev.Timeout)
	assert.Equal(t, "warn", depsdev.OnFailure)

	local := cfg.Providers["local"]
	assert.True(t, local.Enabled)
	assert.Equal(t, 0, local.Priority)
	assert.Equal(t, "warn", local.OnFailure)
}

func TestPackageChecksConfig_YAMLRoundTrip(t *testing.T) {
	original := PackageChecksConfig{
		Enabled: true,
		Scope:   "all",
		Cache: PackageCacheConfig{
			Dir: "/tmp/pkgcache",
			TTL: PackageCacheTTL{
				Vulnerability: 30 * time.Minute,
				License:       12 * time.Hour,
				Provenance:    12 * time.Hour,
				Reputation:    3 * time.Hour,
				Malware:       15 * time.Minute,
			},
		},
		Registries: map[string]RegistryTrustConfig{
			"npmjs": {
				Trust:  "check_full",
				Scopes: []string{"@acme", "@internal"},
			},
			"private": {
				Trust: "trusted",
			},
		},
		Providers: map[string]ProviderConfig{
			"osv": {
				Enabled:   true,
				Priority:  1,
				Timeout:   10 * time.Second,
				OnFailure: "warn",
			},
			"custom": {
				Enabled:   true,
				Type:      "exec",
				Command:   "/usr/local/bin/check",
				Priority:  5,
				Timeout:   30 * time.Second,
				OnFailure: "deny",
				APIKeyEnv: "CUSTOM_API_KEY",
				Options:   map[string]any{"verbose": true},
			},
		},
		Resolvers: map[string]ResolverConfig{
			"npm": {DryRunCommand: "npm install --dry-run --json", Timeout: 30 * time.Second},
			"pip": {DryRunCommand: "pip install --dry-run", Timeout: 20 * time.Second},
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded PackageChecksConfig
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Enabled, decoded.Enabled)
	assert.Equal(t, original.Scope, decoded.Scope)
	assert.Equal(t, original.Cache.Dir, decoded.Cache.Dir)
	assert.Equal(t, original.Cache.TTL.Vulnerability, decoded.Cache.TTL.Vulnerability)
	assert.Equal(t, original.Cache.TTL.License, decoded.Cache.TTL.License)
	assert.Equal(t, original.Cache.TTL.Malware, decoded.Cache.TTL.Malware)

	// RegistryTrustConfig fields
	assert.Equal(t, "check_full", decoded.Registries["npmjs"].Trust)
	assert.Equal(t, []string{"@acme", "@internal"}, decoded.Registries["npmjs"].Scopes)
	assert.Equal(t, "trusted", decoded.Registries["private"].Trust)
	assert.Nil(t, decoded.Registries["private"].Scopes)

	// ProviderConfig fields
	osv := decoded.Providers["osv"]
	assert.True(t, osv.Enabled)
	assert.Equal(t, 1, osv.Priority)
	assert.Equal(t, 10*time.Second, osv.Timeout)
	assert.Equal(t, "warn", osv.OnFailure)

	custom := decoded.Providers["custom"]
	assert.True(t, custom.Enabled)
	assert.Equal(t, "exec", custom.Type)
	assert.Equal(t, "/usr/local/bin/check", custom.Command)
	assert.Equal(t, 5, custom.Priority)
	assert.Equal(t, 30*time.Second, custom.Timeout)
	assert.Equal(t, "deny", custom.OnFailure)
	assert.Equal(t, "CUSTOM_API_KEY", custom.APIKeyEnv)

	// ResolverConfig fields
	assert.Equal(t, "npm install --dry-run --json", decoded.Resolvers["npm"].DryRunCommand)
	assert.Equal(t, 30*time.Second, decoded.Resolvers["npm"].Timeout)
	assert.Equal(t, "pip install --dry-run", decoded.Resolvers["pip"].DryRunCommand)
	assert.Equal(t, 20*time.Second, decoded.Resolvers["pip"].Timeout)
}

func TestPackageChecksConfig_InConfig(t *testing.T) {
	yamlInput := `
package_checks:
  enabled: true
  scope: all
  cache:
    dir: /tmp/cache
    ttl:
      vulnerability: 30m0s
      license: 12h0m0s
      provenance: 12h0m0s
      reputation: 3h0m0s
      malware: 15m0s
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlInput), &cfg)
	require.NoError(t, err)

	assert.True(t, cfg.PackageChecks.Enabled)
	assert.Equal(t, "all", cfg.PackageChecks.Scope)
	assert.Equal(t, "/tmp/cache", cfg.PackageChecks.Cache.Dir)
	assert.Equal(t, 30*time.Minute, cfg.PackageChecks.Cache.TTL.Vulnerability)
	assert.Equal(t, 12*time.Hour, cfg.PackageChecks.Cache.TTL.License)
	assert.Equal(t, 15*time.Minute, cfg.PackageChecks.Cache.TTL.Malware)
}
