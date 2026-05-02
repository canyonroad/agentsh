package server

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

// TestBuildResolvers_DefaultsToSix verifies that calling buildResolvers with a
// nil map returns all six built-in resolvers so that package_checks.enabled:
// true with no explicit resolvers: block still works.
func TestBuildResolvers_DefaultsToSix(t *testing.T) {
	resolvers, err := buildResolvers(nil)
	if err != nil {
		t.Fatalf("buildResolvers(nil) unexpected error: %v", err)
	}
	if len(resolvers) != 6 {
		t.Fatalf("expected 6 default resolvers, got %d", len(resolvers))
	}

	want := map[string]bool{
		"npm":    false,
		"pnpm":   false,
		"yarn":   false,
		"pip":    false,
		"uv":     false,
		"poetry": false,
	}
	for _, r := range resolvers {
		name := r.Name()
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected resolver name %q", name)
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

// TestBuildResolvers_EmptyMapDefaultsToSix verifies that an empty (non-nil) map
// also falls through to the default six resolvers.
func TestBuildResolvers_EmptyMapDefaultsToSix(t *testing.T) {
	resolvers, err := buildResolvers(map[string]config.ResolverConfig{})
	if err != nil {
		t.Fatalf("buildResolvers({}) unexpected error: %v", err)
	}
	if len(resolvers) != 6 {
		t.Fatalf("expected 6 default resolvers, got %d", len(resolvers))
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
