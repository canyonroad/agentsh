package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gobwas/glob"
)

// ResolvedEnvPolicy is the merged env policy (global + rule override).
type ResolvedEnvPolicy struct {
	Allow          []string
	Deny           []string
	MaxBytes       int
	MaxKeys        int
	BlockIteration bool
}

// MergeEnvPolicy merges global policy with rule override (rule wins when set).
func MergeEnvPolicy(global EnvPolicy, rule CommandRule) ResolvedEnvPolicy {
	out := ResolvedEnvPolicy{
		Allow:          append([]string{}, global.Allow...),
		Deny:           append([]string{}, global.Deny...),
		MaxBytes:       global.MaxBytes,
		MaxKeys:        global.MaxKeys,
		BlockIteration: global.BlockIteration,
	}

	if len(rule.EnvAllow) > 0 {
		out.Allow = append([]string{}, rule.EnvAllow...)
	}
	if len(rule.EnvDeny) > 0 {
		out.Deny = append([]string{}, rule.EnvDeny...)
	}
	if rule.EnvMaxBytes > 0 {
		out.MaxBytes = rule.EnvMaxBytes
	}
	if rule.EnvMaxKeys > 0 {
		out.MaxKeys = rule.EnvMaxKeys
	}
	if rule.EnvBlockIteration != nil {
		out.BlockIteration = *rule.EnvBlockIteration
	}

	out.Allow = uniqStrings(out.Allow)
	out.Deny = uniqStrings(out.Deny)
	return out
}

// BuildEnv constructs the child environment per policy.
// baseEnv should already be minimal; addKeys are merged after allow/deny filtering.
// Supports glob patterns in allow/deny lists (e.g., "AWS_*", "*_TOKEN").
func BuildEnv(pol ResolvedEnvPolicy, baseEnv []string, addKeys map[string]string) ([]string, error) {
	// Compile patterns once for this call
	allowGlobs := compilePatterns(pol.Allow)
	denyGlobs := compilePatterns(pol.Deny)

	hasAllowPatterns := len(pol.Allow) > 0

	// Helper to check if var is denied
	isDenied := func(name string) bool {
		if matchesAnyPattern(name, pol.Deny, denyGlobs) {
			return true
		}
		// Check default secrets when no explicit allow patterns
		if !hasAllowPatterns {
			for _, secret := range defaultSecretDeny {
				if name == secret {
					return true
				}
			}
		}
		return false
	}

	// Helper to check if var is allowed
	isAllowed := func(name string) bool {
		if isDenied(name) {
			return false
		}
		if !hasAllowPatterns {
			return true // No allowlist = allow all (except denied)
		}
		return matchesAnyPattern(name, pol.Allow, allowGlobs)
	}

	allowed := map[string]string{}

	// Process base env
	for _, kv := range baseEnv {
		k, v, ok := splitKV(kv)
		if !ok || v == "" {
			continue
		}
		if isAllowed(k) {
			allowed[k] = v
		}
	}

	// Additional explicit keys
	for k, v := range addKeys {
		if isAllowed(k) {
			allowed[k] = v
		}
	}

	pairs := make([]string, 0, len(allowed))
	for k, v := range allowed {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(pairs)

	if pol.MaxKeys > 0 && len(pairs) > pol.MaxKeys {
		return nil, fmt.Errorf("env exceeds max_keys (%d)", pol.MaxKeys)
	}
	total := 0
	for _, p := range pairs {
		total += len(p) + 1
	}
	if pol.MaxBytes > 0 && total > pol.MaxBytes {
		return nil, fmt.Errorf("env exceeds max_bytes (%d)", pol.MaxBytes)
	}
	return pairs, nil
}

func splitKV(kv string) (k, v string, ok bool) {
	idx := strings.IndexByte(kv, '=')
	if idx <= 0 {
		return "", "", false
	}
	return kv[:idx], kv[idx+1:], true
}

func uniqStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func toSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[s] = true
	}
	return m
}

// compilePatterns compiles a list of glob patterns, returning nil on error.
func compilePatterns(patterns []string) []glob.Glob {
	var compiled []glob.Glob
	for _, p := range patterns {
		g, err := glob.Compile(p)
		if err != nil {
			continue // Skip invalid patterns
		}
		compiled = append(compiled, g)
	}
	return compiled
}

// matchesAnyPattern checks if name matches any of the patterns.
// Supports both exact match (via set) and glob patterns.
func matchesAnyPattern(name string, patterns []string, compiledGlobs []glob.Glob) bool {
	// Fast path: exact match
	for _, p := range patterns {
		if p == name {
			return true
		}
	}
	// Glob match
	for _, g := range compiledGlobs {
		if g.Match(name) {
			return true
		}
	}
	return false
}

// ValidateEnvPolicy performs simple sanity checks.
func ValidateEnvPolicy(p EnvPolicy) error {
	if p.MaxBytes < 0 || p.MaxKeys < 0 {
		return errors.New("max_bytes/max_keys must be non-negative")
	}
	return nil
}

var defaultSecretDeny = []string{
	"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "AWS_PROFILE",
	"GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT",
	"AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID",
	"SSH_AUTH_SOCK", "SSH_AGENT_PID", "DOCKER_HOST", "DOCKER_TLS_VERIFY",
	"KUBECONFIG", "GITHUB_TOKEN", "GH_TOKEN",
}
