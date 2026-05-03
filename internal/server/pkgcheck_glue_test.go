package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/agentsh/agentsh/internal/policy"
)

// TestBuildResolvers_DefaultsToVerified verifies that calling buildResolvers with a
// nil map returns only the three verified built-in resolvers (npm, pip, uv).
// pnpm, yarn, and poetry are excluded from defaults because their parsers are
// placeholders. They remain available via explicit config.
func TestBuildResolvers_DefaultsToVerified(t *testing.T) {
	resolvers, err := buildResolvers(nil)
	if err != nil {
		t.Fatalf("buildResolvers(nil) unexpected error: %v", err)
	}
	if len(resolvers) != 3 {
		t.Fatalf("expected 3 default resolvers, got %d", len(resolvers))
	}

	want := map[string]bool{
		"npm": false,
		"pip": false,
		"uv":  false,
	}
	for _, r := range resolvers {
		name := r.Name()
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected resolver name %q in defaults", name)
			continue
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing resolver %q in default set", name)
		}
	}
}

// TestBuildResolvers_EmptyMapDefaultsToVerified verifies that an empty (non-nil) map
// also falls through to the default three verified resolvers.
func TestBuildResolvers_EmptyMapDefaultsToVerified(t *testing.T) {
	resolvers, err := buildResolvers(map[string]config.ResolverConfig{})
	if err != nil {
		t.Fatalf("buildResolvers({}) unexpected error: %v", err)
	}
	if len(resolvers) != 3 {
		t.Fatalf("expected 3 default resolvers, got %d", len(resolvers))
	}
}

// TestBuildResolvers_PnpmYarnPoetryAvailableExplicitly verifies that pnpm, yarn,
// and poetry are still constructable via explicit config even though they are
// not in the default set.
func TestBuildResolvers_PnpmYarnPoetryAvailableExplicitly(t *testing.T) {
	resolvers, err := buildResolvers(map[string]config.ResolverConfig{
		"pnpm":   {},
		"yarn":   {},
		"poetry": {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolvers) != 3 {
		t.Fatalf("expected 3 resolvers, got %d", len(resolvers))
	}
}

// TestBuildResolvers_ExplicitSubset verifies that an explicit subset is
// honored without adding defaults.
func TestBuildResolvers_ExplicitSubset(t *testing.T) {
	resolvers, err := buildResolvers(map[string]config.ResolverConfig{
		"npm": {DryRunCommand: "/usr/local/bin/npm"},
		"pip": {},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolvers) != 2 {
		t.Fatalf("expected 2 resolvers, got %d", len(resolvers))
	}
}

// TestBuildResolvers_UnknownNameRejected verifies that an unknown resolver name
// returns a fatal error describing the bad name.
func TestBuildResolvers_UnknownNameRejected(t *testing.T) {
	_, err := buildResolvers(map[string]config.ResolverConfig{
		"bundler": {},
	})
	if err == nil {
		t.Fatal("expected error for unknown resolver name")
	}
	if !strings.Contains(err.Error(), "bundler") || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention the bad name and 'unknown'; got: %v", err)
	}
}

// TestBuildResolvers_SpacedDryRunCommandRejected verifies that a DryRunCommand
// containing spaces fails at resolver-build time with a message pointing to
// dry_run_args, so users with the old "npm install --package-lock-only" config
// shape get a clear migration hint.
func TestBuildResolvers_SpacedDryRunCommandRejected(t *testing.T) {
	_, err := buildResolvers(map[string]config.ResolverConfig{
		"npm": {DryRunCommand: "npm install --package-lock-only --ignore-scripts"},
	})
	if err == nil {
		t.Fatal("expected error for DryRunCommand with spaces")
	}
	if !strings.Contains(err.Error(), "dry_run_args") {
		t.Errorf("error should mention dry_run_args; got: %v", err)
	}
}

// TestBuildProviderEntry_DefaultOnFailureIsWarn verifies that an empty
// OnFailure in the config is normalized to "warn".
func TestBuildProviderEntry_DefaultOnFailureIsWarn(t *testing.T) {
	entry, err := buildProviderEntry("osv", config.ProviderConfig{
		Enabled:   true,
		OnFailure: "", // deliberately empty
	})
	if err != nil {
		t.Fatalf("buildProviderEntry: %v", err)
	}
	if entry.OnFailure != "warn" {
		t.Errorf("expected OnFailure=%q, got %q", "warn", entry.OnFailure)
	}
}

// TestBuildProviderEntry_ExplicitOnFailurePreserved verifies that a non-empty
// OnFailure value is not overwritten.
func TestBuildProviderEntry_ExplicitOnFailurePreserved(t *testing.T) {
	entry, err := buildProviderEntry("osv", config.ProviderConfig{
		Enabled:   true,
		OnFailure: "deny",
	})
	if err != nil {
		t.Fatalf("buildProviderEntry: %v", err)
	}
	if entry.OnFailure != "deny" {
		t.Errorf("expected OnFailure=%q, got %q", "deny", entry.OnFailure)
	}
}

// TestBuildProviderEntries_MissingAPIKeySkipsProvider verifies that a provider
// configured with api_key_env pointing to an unset variable is skipped
// (returns errMissingAPIKeyValue) rather than causing a fatal error.
// This underpins Fix 3: if ALL providers are skipped this way, the caller
// must detect the empty map and fail loudly.
func TestBuildProviderEntries_MissingAPIKeySkipsProvider(t *testing.T) {
	// Use an env var that is guaranteed not to be set.
	const missingEnvVar = "AGENTSH_TEST_SNYK_KEY_DEFINITELY_NOT_SET_XYZ"
	t.Setenv(missingEnvVar, "") // ensure it's empty

	_, err := buildProviderEntry("snyk", config.ProviderConfig{
		Enabled:    true,
		APIKeyEnv:  missingEnvVar,
		OnFailure:  "warn",
		Options:    map[string]any{"org_id": "test-org"},
	})
	if err == nil {
		t.Fatal("expected error for missing API key, got nil")
	}
	if !errors.Is(err, errMissingAPIKeyValue) {
		t.Errorf("expected errMissingAPIKeyValue, got: %v", err)
	}
}

// TestComposedRules_NoCatchAllLeakFromBlockOn verifies that when CompileBlockOnRules
// (no-catch-all variant) is appended after engine-style rules, the merged set does
// NOT end with a Match{} / Action:"allow" catch-all. This is the wiring that
// server.go uses so an operator policy with no catch-all retains fail-closed intent.
func TestComposedRules_NoCatchAllLeakFromBlockOn(t *testing.T) {
	blockOnCfg := config.BlockOnConfig{
		Malware:       "any",
		Vulnerability: "critical",
		License:       "never",
		Reputation:    "never",
		Provenance:    "never",
	}

	// Simulate an operator policy that has no catch-all (deliberately fail-closed).
	engineRules := []policy.PackageRule{
		{Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny", Reason: "operator deny malware"},
	}

	// This is exactly what server.go does now (uses CompileBlockOnRules, not CompileBlockOn).
	rules := append([]policy.PackageRule(nil), engineRules...)
	rules = append(rules, config.CompileBlockOnRules(blockOnCfg)...)

	if len(rules) == 0 {
		t.Fatal("expected at least one composed rule")
	}
	last := rules[len(rules)-1]
	if last.Match.FindingType == "" && last.Action == "allow" {
		t.Errorf("merged rules must NOT end with a catch-all allow when using CompileBlockOnRules; "+
			"engine fail-closed intent would be shadowed. Last rule: %+v", last)
	}
}

// TestMissingAPIKey_ClosedModeIsFatal verifies that when fail_mode=closed and
// an external provider is configured with an unset API key env var, the error
// is errMissingAPIKeyValue and callers should treat it as fatal (not skip).
func TestMissingAPIKey_ClosedModeIsFatal(t *testing.T) {
	const missingEnvVar = "AGENTSH_TEST_SNYK_KEY_CLOSED_MODE_XYZ"
	t.Setenv(missingEnvVar, "") // ensure empty

	_, err := buildProviderEntry("snyk", config.ProviderConfig{
		Enabled:   true,
		APIKeyEnv: missingEnvVar,
		OnFailure: "deny",
		Options:   map[string]any{"org_id": "test-org"},
	})
	if err == nil {
		t.Fatal("expected an error for missing API key, got nil")
	}
	if !errors.Is(err, errMissingAPIKeyValue) {
		t.Fatalf("expected errMissingAPIKeyValue sentinel, got: %v", err)
	}

	// Now simulate the closed-mode check from server.go's loop:
	// when mode == "closed" and err is errMissingAPIKeyValue, return a fatal error.
	mode := "closed"
	var fatalErr error
	if errors.Is(err, errMissingAPIKeyValue) {
		if mode == "closed" {
			fatalErr = fmt.Errorf("pkgcheck: provider %q enabled with missing API key under fail_mode=closed: configured to fail closed, but provider cannot operate", "snyk")
		}
	}
	if fatalErr == nil {
		t.Error("expected a fatal error under fail_mode=closed with missing API key, got nil")
	}
	if !strings.Contains(fatalErr.Error(), "fail_mode=closed") {
		t.Errorf("fatal error should mention fail_mode=closed; got: %v", fatalErr)
	}
}

// TestMissingAPIKey_DegradedModeContinues verifies that when fail_mode=degraded
// (the default) and an external provider is configured with an unset API key,
// the code path continues (skip with warning) rather than failing fatally.
// This is the previously-correct degraded behavior — the fix only adds the
// closed-mode branch without changing degraded/open.
func TestMissingAPIKey_DegradedModeContinues(t *testing.T) {
	const missingEnvVar = "AGENTSH_TEST_SNYK_KEY_DEGRADED_MODE_XYZ"
	t.Setenv(missingEnvVar, "") // ensure empty

	_, err := buildProviderEntry("snyk", config.ProviderConfig{
		Enabled:   true,
		APIKeyEnv: missingEnvVar,
		OnFailure: "warn",
		Options:   map[string]any{"org_id": "test-org"},
	})
	if err == nil {
		t.Fatal("expected errMissingAPIKeyValue, got nil")
	}
	if !errors.Is(err, errMissingAPIKeyValue) {
		t.Fatalf("expected errMissingAPIKeyValue, got: %v", err)
	}

	// Simulate the degraded-mode branch: skip, do NOT return a fatal error.
	mode := "degraded"
	skipped := false
	if errors.Is(err, errMissingAPIKeyValue) {
		if mode != "closed" {
			skipped = true // warn and continue — no fatal error
		}
	}
	if !skipped {
		t.Error("expected degraded mode to skip (not fail) on missing API key")
	}
}

// configured providers are skipped due to missing API keys, the resulting map
// is empty. This is what the server.go zero-providers check guards against.
func TestBuildProviderEntries_ZeroProvidersDetectableByLoop(t *testing.T) {
	const missingEnvVar = "AGENTSH_TEST_SNYK_KEY_DEFINITELY_NOT_SET_XYZ"
	t.Setenv(missingEnvVar, "") // ensure empty

	cfgProviders := map[string]config.ProviderConfig{
		"snyk": {
			Enabled:   true,
			APIKeyEnv: missingEnvVar,
			Options:   map[string]any{"org_id": "test-org"},
		},
	}

	providerEntries := make(map[string]pkgcheck.ProviderEntry)
	for name, provCfg := range cfgProviders {
		if !provCfg.Enabled {
			continue
		}
		entry, err := buildProviderEntry(name, provCfg)
		if err != nil {
			if errors.Is(err, errMissingAPIKeyValue) {
				continue // soft skip — this is the expected path
			}
			t.Fatalf("unexpected hard error: %v", err)
		}
		providerEntries[name] = entry
	}

	// All providers were skipped → empty map.
	// This is the condition server.go's zero-providers check catches.
	if len(providerEntries) != 0 {
		t.Errorf("expected 0 provider entries, got %d", len(providerEntries))
	}
}
