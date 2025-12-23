package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
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
func BuildEnv(pol ResolvedEnvPolicy, baseEnv []string, addKeys map[string]string) ([]string, error) {
	allowSet := toSet(pol.Allow)
	denySet := toSet(pol.Deny)
	if len(allowSet) == 0 {
		for _, k := range defaultSecretDeny {
			denySet[k] = true
		}
	}

	allowed := map[string]string{}

	// base env (only if allow set defined; otherwise baseEnv expected minimal and added below)
	if len(allowSet) > 0 {
		for _, kv := range baseEnv {
			k, v, ok := splitKV(kv)
			if !ok {
				continue
			}
			if _, ok := allowSet[k]; !ok {
				continue
			}
			if _, denied := denySet[k]; denied {
				continue
			}
			if v != "" {
				allowed[k] = v
			}
		}
	}

	// minimal/defaults (baseEnv entries) always considered when not denied
	for _, kv := range baseEnv {
		k, v, ok := splitKV(kv)
		if !ok || v == "" {
			continue
		}
		if _, denied := denySet[k]; denied {
			continue
		}
		if len(allowSet) == 0 || allowSet[k] {
			allowed[k] = v
		}
	}

	// Additional explicit keys
	for k, v := range addKeys {
		if len(allowSet) > 0 {
			if _, ok := allowSet[k]; !ok {
				continue
			}
		}
		if _, denied := denySet[k]; denied {
			continue
		}
		allowed[k] = v
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
