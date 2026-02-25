package shim

import (
	"sort"
	"strings"
	"testing"
)

func TestFilterEnvForMCPServer_EmptyListsFullPassthrough(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"AWS_SECRET_KEY=supersecret",
		"GITHUB_TOKEN=ghp_abc",
		"MY_VAR=hello",
	}

	filtered, stripped := FilterEnvForMCPServer(environ, nil, nil)

	if len(stripped) != 0 {
		t.Errorf("expected no stripped vars, got %v", stripped)
	}
	if len(filtered) != len(environ) {
		t.Errorf("expected %d vars, got %d", len(environ), len(filtered))
	}
	// Verify exact same entries are returned.
	for i, entry := range environ {
		if filtered[i] != entry {
			t.Errorf("filtered[%d] = %q, want %q", i, filtered[i], entry)
		}
	}
}

func TestFilterEnvForMCPServer_AllowlistOnlyPassesSpecifiedAndStandard(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"USER=testuser",
		"SHELL=/bin/bash",
		"TERM=xterm",
		"LANG=en_US.UTF-8",
		"TMPDIR=/tmp",
		"XDG_RUNTIME_DIR=/run/user/1000",
		"MY_APP_CONFIG=/etc/myapp",
		"DATABASE_URL=postgres://localhost/db",
		"EDITOR=vim",
	}

	allowedEnv := []string{"MY_APP_CONFIG", "DATABASE_URL"}

	filtered, stripped := FilterEnvForMCPServer(environ, allowedEnv, nil)

	// Should keep: 8 standard vars + 2 allowed = 10
	if len(filtered) != 10 {
		t.Errorf("expected 10 filtered vars, got %d: %v", len(filtered), envNames(filtered))
	}

	// EDITOR should be stripped.
	if len(stripped) != 1 {
		t.Errorf("expected 1 stripped var, got %d: %v", len(stripped), stripped)
	}
	if len(stripped) > 0 && stripped[0] != "EDITOR" {
		t.Errorf("expected stripped var EDITOR, got %q", stripped[0])
	}

	// Verify allowed vars are present.
	filteredNames := envNameSet(filtered)
	for _, name := range allowedEnv {
		if !filteredNames[name] {
			t.Errorf("expected %q to be in filtered set", name)
		}
	}
}

func TestFilterEnvForMCPServer_DenylistStripsSpecified(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"AWS_ACCESS_KEY_ID=AKIA...",
		"AWS_SECRET_ACCESS_KEY=secret",
		"MY_VAR=hello",
	}

	deniedEnv := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}

	filtered, stripped := FilterEnvForMCPServer(environ, nil, deniedEnv)

	if len(filtered) != 3 {
		t.Errorf("expected 3 filtered vars, got %d: %v", len(filtered), envNames(filtered))
	}

	sort.Strings(stripped)
	expected := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
	sort.Strings(expected)
	if len(stripped) != len(expected) {
		t.Fatalf("expected %d stripped vars, got %d", len(expected), len(stripped))
	}
	for i := range expected {
		if stripped[i] != expected[i] {
			t.Errorf("stripped[%d] = %q, want %q", i, stripped[i], expected[i])
		}
	}
}

func TestFilterEnvForMCPServer_AllowlistStripsSensitiveDefaults(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"AWS_SECRET_KEY=supersecret",
		"GITHUB_TOKEN=ghp_abc",
		"API_KEY=somekey",
		"DB_PASSWORD=dbpass",
		"OAUTH_CREDENTIALS=creds",
		"MY_APP_CONFIG=/etc/myapp",
	}

	// AllowedEnv is set but does NOT include sensitive vars.
	allowedEnv := []string{"MY_APP_CONFIG"}

	filtered, stripped := FilterEnvForMCPServer(environ, allowedEnv, nil)

	// Should keep: PATH, HOME + MY_APP_CONFIG = 3
	if len(filtered) != 3 {
		t.Errorf("expected 3 filtered vars, got %d: %v", len(filtered), envNames(filtered))
	}

	// Sensitive vars and other unlisted vars should be stripped.
	strippedSet := make(map[string]bool)
	for _, name := range stripped {
		strippedSet[name] = true
	}
	for _, sensitive := range []string{"AWS_SECRET_KEY", "GITHUB_TOKEN", "API_KEY", "DB_PASSWORD", "OAUTH_CREDENTIALS"} {
		if !strippedSet[sensitive] {
			t.Errorf("expected %q to be stripped", sensitive)
		}
	}
}

func TestFilterEnvForMCPServer_StandardVarsAlwaysPassedInAllowlistMode(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"USER=testuser",
		"SHELL=/bin/bash",
		"TERM=xterm",
		"LANG=en_US.UTF-8",
		"TMPDIR=/tmp",
		"XDG_RUNTIME_DIR=/run/user/1000",
	}

	// Strict allowlist with nothing extra allowed.
	allowedEnv := []string{"NONEXISTENT_VAR"}

	filtered, stripped := FilterEnvForMCPServer(environ, allowedEnv, nil)

	// All 8 standard vars should pass through.
	if len(filtered) != 8 {
		t.Errorf("expected 8 filtered vars (all standard), got %d: %v", len(filtered), envNames(filtered))
	}
	if len(stripped) != 0 {
		t.Errorf("expected no stripped vars, got %v", stripped)
	}

	filteredNames := envNameSet(filtered)
	for _, std := range []string{"PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "TMPDIR", "XDG_RUNTIME_DIR"} {
		if !filteredNames[std] {
			t.Errorf("standard var %q should be in filtered set", std)
		}
	}
}

func TestFilterEnvForMCPServer_StrippedContainsOnlyNamesNotValues(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"SECRET_TOKEN=super_secret_value_12345",
		"OTHER_VAR=something",
	}

	deniedEnv := []string{"SECRET_TOKEN", "OTHER_VAR"}

	_, stripped := FilterEnvForMCPServer(environ, nil, deniedEnv)

	for _, name := range stripped {
		if strings.Contains(name, "=") {
			t.Errorf("stripped entry %q contains '='; should be name only", name)
		}
		if strings.Contains(name, "super_secret_value") {
			t.Errorf("stripped entry %q contains a value; should be name only", name)
		}
	}
}

func TestFilterEnvForMCPServer_CombinedAllowDeny_AllowlistWins(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"MY_APP_CONFIG=/etc/myapp",
		"DENIED_VAR=should_not_matter",
		"ANOTHER_VAR=hello",
	}

	// Both are set, but allowlist should take precedence.
	allowedEnv := []string{"MY_APP_CONFIG", "DENIED_VAR"}
	deniedEnv := []string{"DENIED_VAR"}

	filtered, stripped := FilterEnvForMCPServer(environ, allowedEnv, deniedEnv)

	// DENIED_VAR should still be included because allowlist wins.
	filteredNames := envNameSet(filtered)
	if !filteredNames["DENIED_VAR"] {
		t.Errorf("DENIED_VAR should be passed through when allowlist is active (allowlist wins)")
	}
	if !filteredNames["MY_APP_CONFIG"] {
		t.Errorf("MY_APP_CONFIG should be in filtered set")
	}
	// ANOTHER_VAR is not in allowed list, so it should be stripped.
	strippedSet := make(map[string]bool)
	for _, name := range stripped {
		strippedSet[name] = true
	}
	if !strippedSet["ANOTHER_VAR"] {
		t.Errorf("ANOTHER_VAR should be stripped (not in allowlist)")
	}
}

func TestFilterEnvForMCPServer_AllowlistExplicitlySensitiveVarPasses(t *testing.T) {
	// When a sensitive-looking var is explicitly in the allowlist, it should pass.
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"GITHUB_TOKEN=ghp_abc",
	}

	allowedEnv := []string{"GITHUB_TOKEN"}

	filtered, stripped := FilterEnvForMCPServer(environ, allowedEnv, nil)

	filteredNames := envNameSet(filtered)
	if !filteredNames["GITHUB_TOKEN"] {
		t.Errorf("GITHUB_TOKEN should pass through when explicitly allowed")
	}
	if len(stripped) != 0 {
		t.Errorf("expected no stripped vars when all are standard or explicitly allowed, got %v", stripped)
	}
}

func TestFilterEnvForMCPServer_EmptyEnviron(t *testing.T) {
	filtered, stripped := FilterEnvForMCPServer(nil, []string{"FOO"}, nil)
	if len(filtered) != 0 {
		t.Errorf("expected empty filtered for nil environ, got %v", filtered)
	}
	if len(stripped) != 0 {
		t.Errorf("expected empty stripped for nil environ, got %v", stripped)
	}
}

func TestMatchesSensitivePattern(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"GITHUB_TOKEN", true},
		{"AWS_SECRET_KEY", true},
		{"MY_API_KEY", true},
		{"DB_PASSWORD", true},
		{"OAUTH_CREDENTIALS", true},
		{"APP_SECRET", true},
		{"PATH", false},
		{"HOME", false},
		{"MY_APP_CONFIG", false},
		{"TOKEN_BUCKET", false}, // _TOKEN must be suffix
	}
	for _, tc := range cases {
		got := matchesSensitivePattern(tc.name)
		if got != tc.expected {
			t.Errorf("matchesSensitivePattern(%q) = %v, want %v", tc.name, got, tc.expected)
		}
	}
}

// Helper: extract env var names from environ-style entries.
func envNames(entries []string) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = envName(e)
	}
	return names
}

// Helper: build a set of env var names from environ-style entries.
func envNameSet(entries []string) map[string]bool {
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		set[envName(e)] = true
	}
	return set
}
