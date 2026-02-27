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
	assert.Nil(t, cfg.Providers)
	assert.Nil(t, cfg.Resolvers)
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
				URL:     "https://registry.npmjs.org",
				Trusted: true,
			},
		},
		Providers: map[string]ProviderConfig{
			"osv": {
				Enabled: true,
				Config:  map[string]string{"api_url": "https://api.osv.dev"},
			},
		},
		Resolvers: map[string]ResolverConfig{
			"npm": {Enabled: true},
			"pip": {Enabled: false},
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
	assert.True(t, decoded.Registries["npmjs"].Trusted)
	assert.Equal(t, "https://registry.npmjs.org", decoded.Registries["npmjs"].URL)
	assert.True(t, decoded.Providers["osv"].Enabled)
	assert.Equal(t, "https://api.osv.dev", decoded.Providers["osv"].Config["api_url"])
	assert.True(t, decoded.Resolvers["npm"].Enabled)
	assert.False(t, decoded.Resolvers["pip"].Enabled)
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
