package server

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
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
