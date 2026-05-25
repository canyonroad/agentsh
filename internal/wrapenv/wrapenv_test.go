package wrapenv

import (
	"slices"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func has(env []string, kv string) bool { return slices.Contains(env, kv) }

func TestFilter_NilWireIsIdentity(t *testing.T) {
	base := []string{"PATH=/bin", "FOO=bar"}
	got := Filter(base, nil)
	if !slices.Equal(got, base) {
		t.Errorf("nil wire must return base unchanged; got %v", got)
	}
}

func TestFilter_DenyStripsMatchKeepsRest(t *testing.T) {
	base := []string{"PATH=/bin", "SECRET_TOKEN=x", "HOME=/h"}
	got := Filter(base, &types.EnvPolicyWire{Deny: []string{"SECRET_*"}})
	if has(got, "SECRET_TOKEN=x") {
		t.Error("denied var must be stripped")
	}
	if !has(got, "PATH=/bin") || !has(got, "HOME=/h") {
		t.Error("non-denied vars must be kept")
	}
}

func TestFilter_DefaultSecretDenyWhenNoAllow(t *testing.T) {
	base := []string{"PATH=/bin", "AWS_SECRET_ACCESS_KEY=zzz"}
	got := Filter(base, &types.EnvPolicyWire{}) // empty policy, no allow
	if has(got, "AWS_SECRET_ACCESS_KEY=zzz") {
		t.Error("default-secret-deny var must be stripped when no allow patterns")
	}
	if !has(got, "PATH=/bin") {
		t.Error("ordinary var must be kept")
	}
}

func TestFilter_AllowIsAllowlist(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/h", "OTHER=1"}
	got := Filter(base, &types.EnvPolicyWire{Allow: []string{"PATH", "HOME"}})
	if has(got, "OTHER=1") {
		t.Error("non-allowed var must be dropped under allowlist")
	}
	if !has(got, "PATH=/bin") || !has(got, "HOME=/h") {
		t.Error("allowed vars must be kept")
	}
}

// max_bytes/max_keys are intentionally NOT carried on the wrap path (#379):
// BuildEnv errors on overflow, which under fail-open would revert to the full
// unfiltered env. EnvPolicyWire therefore has no such fields; a large env is
// filtered by allow/deny only and never rejected.
func TestFilter_NoMaxEnforcementLargeEnvNotRejected(t *testing.T) {
	base := []string{"A=1", "B=2", "C=3", "D=4", "SECRET_TOKEN=x"}
	got := Filter(base, &types.EnvPolicyWire{Deny: []string{"SECRET_*"}})
	if has(got, "SECRET_TOKEN=x") {
		t.Error("denied var must be stripped")
	}
	if len(got) != 4 {
		t.Errorf("large env must pass through (minus denied), not be rejected; got %d entries: %v", len(got), got)
	}
}
