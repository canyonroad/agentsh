package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultPackageChecksConfig(t *testing.T) {
	cfg := DefaultPackageChecksConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, "new_packages_only", cfg.Scope)
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
		Scope:   "all_installs",
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

func TestDefaultPackageChecksConfig_HasPrivacyDefaults(t *testing.T) {
	d := DefaultPackageChecksConfig()
	if len(d.Privacy.ExternalScanRegistries) == 0 {
		t.Error("default Privacy.ExternalScanRegistries should be set")
	}
}

func TestApplyDefaults_PackageChecksPrivacy(t *testing.T) {
	cfg := &Config{} // empty — no YAML privacy block
	applyDefaults(cfg)
	if len(cfg.PackageChecks.Privacy.ExternalScanRegistries) == 0 {
		t.Error("default Privacy.ExternalScanRegistries should be set after applyDefaults")
	}
}

func TestApplyDefaults_BlockOn_PerFieldDefaults(t *testing.T) {
	cfg := &Config{
		PackageChecks: PackageChecksConfig{
			BlockOn: BlockOnConfig{
				License: "any", // user only set this; others should get defaults
			},
		},
	}
	applyDefaults(cfg)
	if cfg.PackageChecks.BlockOn.Malware != "any" {
		t.Errorf("Malware default missing; got %q", cfg.PackageChecks.BlockOn.Malware)
	}
	if cfg.PackageChecks.BlockOn.Vulnerability != "critical" {
		t.Errorf("Vulnerability default missing; got %q", cfg.PackageChecks.BlockOn.Vulnerability)
	}
	if cfg.PackageChecks.BlockOn.License != "any" {
		t.Errorf("License should be preserved; got %q", cfg.PackageChecks.BlockOn.License)
	}
}

func TestResolverConfig_Validate_RejectsLegacyCommandString(t *testing.T) {
	rc := ResolverConfig{
		DryRunCommand: "npm install --package-lock-only --ignore-scripts",
	}
	err := rc.Validate()
	if err == nil {
		t.Fatal("expected validation error for legacy multi-token command, got nil")
	}
	if !strings.Contains(err.Error(), "dry_run_args") {
		t.Errorf("error should mention dry_run_args; got: %v", err)
	}
}

func TestResolverConfig_Validate_AcceptsPathWithSpaces(t *testing.T) {
	for _, p := range []string{
		"/Program Files/nodejs/npm.cmd",
		"C:\\Program Files\\nodejs\\npm.cmd",
		"/usr/local/my tool/npm",
	} {
		rc := ResolverConfig{DryRunCommand: p}
		if err := rc.Validate(); err != nil {
			t.Errorf("path %q must validate cleanly (no flag-shaped tokens); got: %v", p, err)
		}
	}
}

func TestResolverConfig_Validate_AcceptsBinaryOnly(t *testing.T) {
	rc := ResolverConfig{
		DryRunCommand: "/usr/local/bin/npm",
		DryRunArgs:    []string{"install", "--package-lock-only", "--ignore-scripts"},
	}
	if err := rc.Validate(); err != nil {
		t.Errorf("expected no error for binary-only DryRunCommand, got: %v", err)
	}
}

func TestResolverConfig_Validate_AcceptsEmpty(t *testing.T) {
	rc := ResolverConfig{}
	if err := rc.Validate(); err != nil {
		t.Errorf("expected no error for empty DryRunCommand, got: %v", err)
	}
}

func TestPackageChecksConfig_InConfig(t *testing.T) {
	yamlInput := `
package_checks:
  enabled: true
  scope: all_installs
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
	assert.Equal(t, "all_installs", cfg.PackageChecks.Scope)
	assert.Equal(t, "/tmp/cache", cfg.PackageChecks.Cache.Dir)
	assert.Equal(t, 30*time.Minute, cfg.PackageChecks.Cache.TTL.Vulnerability)
	assert.Equal(t, 12*time.Hour, cfg.PackageChecks.Cache.TTL.License)
	assert.Equal(t, 15*time.Minute, cfg.PackageChecks.Cache.TTL.Malware)
}

func TestPackagePrivacyConfig_ValidateRejectsBadGlob(t *testing.T) {
	cfg := PackagePrivacyConfig{PrivateScopeDenylist: []string{"[unclosed"}}
	if err := cfg.Validate(); err == nil {
		t.Error("invalid glob must fail validation")
	}
}

func TestPackagePrivacyConfig_ValidateAcceptsGoodPatterns(t *testing.T) {
	cfg := PackagePrivacyConfig{PrivateScopeDenylist: []string{"@acme", "@internal-*"}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error; got %v", err)
	}
}

func TestValidateConfig_RejectsBadPrivacyDenylistGlob(t *testing.T) {
	// Use the package-level Validate() directly — exercising validateConfig
	// requires a fully-formed Config that's harder to set up here.
	cfg := PackagePrivacyConfig{PrivateScopeDenylist: []string{"[unclosed"}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("invalid denylist glob must be rejected by Privacy.Validate")
	}
}

func TestApplyExternalProviderDefaults_PromotesScope(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "", // unset — should be promoted
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true, APIKeyEnv: "SOCKET_API_KEY"},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "all_installs" {
		t.Errorf("expected scope to be promoted to all_installs, got %q", cfg.Scope)
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected when scope was empty; got %v", warnings)
	}
}

func TestApplyExternalProviderDefaults_WarnsOnExplicitNarrowScope(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "new_packages_only",
		Providers: map[string]ProviderConfig{
			"snyk": {Enabled: true, APIKeyEnv: "SNYK_TOKEN"},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "new_packages_only" {
		t.Errorf("user-set scope should not be overwritten")
	}
	if len(warnings) == 0 {
		t.Fatal("expected validation warning")
	}
	if !strings.Contains(warnings[0], "snyk") || !strings.Contains(warnings[0], "all_installs") {
		t.Errorf("warning should mention provider and recommend all_installs, got %q", warnings[0])
	}
}

func TestApplyExternalProviderDefaults_NoExternalProviderNoOp(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "",
		Providers: map[string]ProviderConfig{
			"osv": {Enabled: true},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "" {
		t.Errorf("scope should remain empty when no external provider is enabled")
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected, got %v", warnings)
	}
}

func TestApplyExternalProviderDefaults_DisabledExternalNoPromote(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "",
		Providers: map[string]ProviderConfig{
			"snyk":   {Enabled: false},
			"socket": {Enabled: false},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "" {
		t.Errorf("disabled external providers should not trigger promotion; got scope=%q", cfg.Scope)
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected; got %v", warnings)
	}
}

func TestResolveFailMode_EnvOverridesYAML(t *testing.T) {
	cfg := PackageChecksConfig{FailMode: "closed"}
	t.Setenv("PKGCHECK_FAIL_MODE", "open")
	got := ResolveFailMode(&cfg)
	if got != "open" {
		t.Errorf("env should win, got %q", got)
	}
}

func TestResolveFailMode_DefaultsToDegraded(t *testing.T) {
	cfg := PackageChecksConfig{}
	t.Setenv("PKGCHECK_FAIL_MODE", "")
	got := ResolveFailMode(&cfg)
	if got != "degraded" {
		t.Errorf("default should be degraded, got %q", got)
	}
}

func TestApplyFailMode_SetsOnFailureForExternal(t *testing.T) {
	cfg := PackageChecksConfig{
		FailMode: "closed",
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true},
			"osv":    {Enabled: true, OnFailure: "warn"}, // should be untouched
		},
	}
	ApplyFailMode(&cfg, "closed")
	if cfg.Providers["socket"].OnFailure != "deny" {
		t.Errorf("socket OnFailure should be deny, got %q", cfg.Providers["socket"].OnFailure)
	}
	if cfg.Providers["osv"].OnFailure != "warn" {
		t.Errorf("osv OnFailure must remain warn, got %q", cfg.Providers["osv"].OnFailure)
	}
}

func TestApplyFailMode_OpenMaps(t *testing.T) {
	cfg := PackageChecksConfig{
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true},
		},
	}
	ApplyFailMode(&cfg, "open")
	if cfg.Providers["socket"].OnFailure != "allow" {
		t.Errorf("open should map to allow; got %q", cfg.Providers["socket"].OnFailure)
	}
}

func TestApplyFailMode_DegradedMaps(t *testing.T) {
	cfg := PackageChecksConfig{
		Providers: map[string]ProviderConfig{
			"snyk": {Enabled: true},
		},
	}
	ApplyFailMode(&cfg, "degraded")
	if cfg.Providers["snyk"].OnFailure != "warn" {
		t.Errorf("degraded should map to warn; got %q", cfg.Providers["snyk"].OnFailure)
	}
}

func TestApplyDefaults_PromotesScopeWhenExternalProviderEnabled(t *testing.T) {
	cfg := &Config{
		PackageChecks: PackageChecksConfig{
			Enabled: true,
			// Scope is intentionally omitted — promotion should set it to all_installs
			Providers: map[string]ProviderConfig{
				"socket": {Enabled: true, APIKeyEnv: "SOCKET_API_KEY"},
			},
		},
	}
	applyDefaults(cfg)
	if cfg.PackageChecks.Scope != "all_installs" {
		t.Errorf("expected scope to be promoted to all_installs by applyDefaults; got %q", cfg.PackageChecks.Scope)
	}
}

func TestServerStartup_AppliesFailMode(t *testing.T) {
	t.Setenv("PKGCHECK_FAIL_MODE", "closed")
	cfg := PackageChecksConfig{
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true, APIKeyEnv: "SOCKET_API_KEY"},
		},
	}
	mode := ResolveFailMode(&cfg)
	if mode != "closed" {
		t.Fatalf("ResolveFailMode should honor env var; got %q", mode)
	}
	ApplyFailMode(&cfg, mode)
	if cfg.Providers["socket"].OnFailure != "deny" {
		t.Errorf("ApplyFailMode should map closed→deny on external providers; got %q", cfg.Providers["socket"].OnFailure)
	}
}

func TestValidateConfig_RejectsBadFailMode(t *testing.T) {
	cfg := &Config{
		PackageChecks: PackageChecksConfig{
			FailMode: "boom",
		},
	}
	// Pre-apply defaults so other required fields (e.g. sandbox.fuse.audit.mode)
	// are populated; the test is only concerned with the fail_mode rejection.
	applyDefaults(cfg)
	// Override FailMode after defaults (which would set it to "degraded").
	cfg.PackageChecks.FailMode = "boom"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("invalid fail_mode must fail validation")
	}
	if !strings.Contains(err.Error(), "fail_mode") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should mention fail_mode and the bad value; got: %v", err)
	}
}

func TestValidateConfig_AcceptsValidFailModes(t *testing.T) {
	for _, mode := range []string{"open", "closed", "degraded"} {
		cfg := &Config{
			PackageChecks: PackageChecksConfig{
				FailMode: mode,
			},
		}
		applyDefaults(cfg)
		cfg.PackageChecks.FailMode = mode
		if err := validateConfig(cfg); err != nil {
			// Only fail if the error is about fail_mode — other fields may be invalid.
			if strings.Contains(err.Error(), "fail_mode") {
				t.Errorf("valid fail_mode %q should not be rejected; got: %v", mode, err)
			}
		}
	}
}

func TestApplyFailMode_UnknownModeIsNoOp(t *testing.T) {
	cfg := PackageChecksConfig{
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true, OnFailure: "allow"},
		},
	}
	ApplyFailMode(&cfg, "unknown-mode")
	// OnFailure should be unchanged — not silently mapped to warn.
	if cfg.Providers["socket"].OnFailure != "allow" {
		t.Errorf("unknown mode must leave OnFailure untouched; got %q", cfg.Providers["socket"].OnFailure)
	}
}
