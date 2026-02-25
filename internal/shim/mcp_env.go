package shim

import (
	"runtime"
	"strings"
)

// standardVars are environment variables that are always passed through to MCP
// server processes, even when an allowlist is configured. These are required
// for basic process operation.
var standardVars = map[string]bool{
	"PATH":            true,
	"HOME":            true,
	"USER":            true,
	"SHELL":           true,
	"TERM":            true,
	"LANG":            true,
	"TMPDIR":          true,
	"XDG_RUNTIME_DIR": true,
}

// sensitivePatterns are suffix patterns that are stripped by default when an
// allowlist is active, to prevent accidental credential leakage.
var sensitivePatterns = []string{
	"_TOKEN",
	"_KEY",
	"_SECRET",
	"_API_KEY",
	"_PASSWORD",
	"_CREDENTIALS",
}

// FilterEnvForMCPServer filters environment variables for an MCP server process.
// If allowedEnv is non-empty, only those vars (plus standard vars) are kept,
// and vars matching sensitive patterns are also stripped unless explicitly allowed.
// If deniedEnv is non-empty, those vars are stripped.
// If both are empty, all vars are passed through (backward compatible).
// The returned stripped slice contains only variable names, never values.
func FilterEnvForMCPServer(environ []string, allowedEnv, deniedEnv []string) (filtered []string, stripped []string) {
	// Both empty: full passthrough for backward compatibility.
	if len(allowedEnv) == 0 && len(deniedEnv) == 0 {
		return environ, nil
	}

	// When allowedEnv is set, it takes precedence (deny is irrelevant).
	if len(allowedEnv) > 0 {
		return filterByAllowlist(environ, allowedEnv)
	}

	// Only deniedEnv is set.
	return filterByDenylist(environ, deniedEnv)
}

// filterByAllowlist keeps only vars in the allowlist or standard vars,
// and strips vars matching sensitive patterns unless explicitly allowed.
func filterByAllowlist(environ []string, allowedEnv []string) (filtered []string, stripped []string) {
	allowed := make(map[string]bool, len(allowedEnv))
	for _, v := range allowedEnv {
		allowed[normalizeEnvKey(v)] = true
	}

	for _, entry := range environ {
		name := envName(entry)
		key := normalizeEnvKey(name)
		if standardVars[key] || allowed[key] {
			if allowed[key] || !matchesSensitivePattern(name) {
				filtered = append(filtered, entry)
			} else {
				stripped = append(stripped, name)
			}
		} else {
			stripped = append(stripped, name)
		}
	}
	return filtered, stripped
}

// filterByDenylist removes vars that appear in the deny list.
func filterByDenylist(environ []string, deniedEnv []string) (filtered []string, stripped []string) {
	denied := make(map[string]bool, len(deniedEnv))
	for _, v := range deniedEnv {
		denied[normalizeEnvKey(v)] = true
	}

	for _, entry := range environ {
		name := envName(entry)
		if denied[normalizeEnvKey(name)] {
			stripped = append(stripped, name)
		} else {
			filtered = append(filtered, entry)
		}
	}
	return filtered, stripped
}

// matchesSensitivePattern returns true if the variable name matches any
// sensitive suffix pattern (e.g. _TOKEN, _SECRET).
func matchesSensitivePattern(name string) bool {
	upper := strings.ToUpper(name)
	for _, pat := range sensitivePatterns {
		if strings.HasSuffix(upper, pat) {
			return true
		}
	}
	return false
}

// envName extracts the variable name from an environ entry of the form "KEY=value".
func envName(entry string) string {
	if i := strings.IndexByte(entry, '='); i >= 0 {
		return entry[:i]
	}
	return entry
}

// normalizeEnvKey returns the canonical form of an env var name for map lookups.
// On Windows, env var names are case-insensitive, so we normalize to uppercase.
func normalizeEnvKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}
