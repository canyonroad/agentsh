package policy

import (
	"testing"
)

func TestEngine_CheckEnv_DenyPatterns(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		EnvPolicy: EnvPolicy{
			Deny: []string{"AWS_*", "*_SECRET", "PASSWORD"},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		allowed bool
		matchBy string
	}{
		{"AWS_ACCESS_KEY_ID", false, "deny"},
		{"AWS_SECRET_ACCESS_KEY", false, "deny"},
		{"MY_SECRET", false, "deny"},
		{"PASSWORD", false, "deny"},
		{"PATH", true, "default-allow"},
		{"HOME", true, "default-allow"},
		{"USER", true, "default-allow"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckEnv(tc.name)
			if dec.Allowed != tc.allowed {
				t.Errorf("expected Allowed=%v, got %v (MatchedBy=%s)", tc.allowed, dec.Allowed, dec.MatchedBy)
			}
			if dec.MatchedBy != tc.matchBy {
				t.Errorf("expected MatchedBy=%q, got %q", tc.matchBy, dec.MatchedBy)
			}
		})
	}
}

func TestEngine_CheckEnv_AllowPatterns(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		EnvPolicy: EnvPolicy{
			Allow: []string{"PATH", "HOME", "USER", "MY_*"},
			Deny:  []string{"MY_SECRET"},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		allowed bool
		matchBy string
	}{
		{"PATH", true, "allow"},
		{"HOME", true, "allow"},
		{"USER", true, "allow"},
		{"MY_VAR", true, "allow"},
		{"MY_APP_DATA", true, "allow"},
		{"MY_SECRET", false, "deny"},           // Deny wins over allow
		{"OTHER_VAR", false, "default-deny"},   // Not in allow list
		{"AWS_ACCESS_KEY_ID", false, "default-deny"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckEnv(tc.name)
			if dec.Allowed != tc.allowed {
				t.Errorf("expected Allowed=%v, got %v (MatchedBy=%s)", tc.allowed, dec.Allowed, dec.MatchedBy)
			}
			if dec.MatchedBy != tc.matchBy {
				t.Errorf("expected MatchedBy=%q, got %q", tc.matchBy, dec.MatchedBy)
			}
		})
	}
}

func TestEngine_CheckEnv_DefaultSecrets(t *testing.T) {
	// No explicit allow/deny patterns - should use defaultSecretDeny
	p := &Policy{
		Version:   1,
		Name:      "test",
		EnvPolicy: EnvPolicy{},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		allowed bool
		matchBy string
	}{
		{"AWS_SECRET_ACCESS_KEY", false, "default-secret-deny"},
		{"AWS_ACCESS_KEY_ID", false, "default-secret-deny"},
		{"GITHUB_TOKEN", false, "default-secret-deny"},
		{"GH_TOKEN", false, "default-secret-deny"},
		{"KUBECONFIG", false, "default-secret-deny"},
		{"PATH", true, "default-allow"},
		{"HOME", true, "default-allow"},
		{"MY_CUSTOM_VAR", true, "default-allow"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckEnv(tc.name)
			if dec.Allowed != tc.allowed {
				t.Errorf("expected Allowed=%v, got %v (MatchedBy=%s)", tc.allowed, dec.Allowed, dec.MatchedBy)
			}
			if dec.MatchedBy != tc.matchBy {
				t.Errorf("expected MatchedBy=%q, got %q", tc.matchBy, dec.MatchedBy)
			}
		})
	}
}

func TestEngine_CheckEnv_NilEngine(t *testing.T) {
	var e *Engine
	dec := e.CheckEnv("PATH")
	if !dec.Allowed || dec.MatchedBy != "default-allow" {
		t.Errorf("nil engine should allow, got Allowed=%v MatchedBy=%s", dec.Allowed, dec.MatchedBy)
	}
}

func TestBuildEnv_GlobPatterns(t *testing.T) {
	pol := ResolvedEnvPolicy{
		Allow: []string{"PATH", "HOME", "MY_*"},
		Deny:  []string{"MY_SECRET_*"},
	}
	baseEnv := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"MY_VAR=value1",
		"MY_SECRET_KEY=secret",
		"OTHER_VAR=other",
	}

	result, err := BuildEnv(pol, baseEnv, nil)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string]bool{
		"PATH=/usr/bin":    true,
		"HOME=/home/user":  true,
		"MY_VAR=value1":    true,
	}

	if len(result) != len(expected) {
		t.Errorf("expected %d vars, got %d: %v", len(expected), len(result), result)
	}

	for _, kv := range result {
		if !expected[kv] {
			t.Errorf("unexpected var in result: %s", kv)
		}
	}
}

func TestBuildEnv_DefaultSecretDeny(t *testing.T) {
	// No allow patterns, should use default secret deny
	pol := ResolvedEnvPolicy{}
	baseEnv := []string{
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=secret",
		"GITHUB_TOKEN=token",
		"MY_VAR=value",
	}

	result, err := BuildEnv(pol, baseEnv, nil)
	if err != nil {
		t.Fatal(err)
	}

	// AWS_SECRET_ACCESS_KEY and GITHUB_TOKEN should be filtered out
	for _, kv := range result {
		if kv == "AWS_SECRET_ACCESS_KEY=secret" || kv == "GITHUB_TOKEN=token" {
			t.Errorf("secret var should have been filtered: %s", kv)
		}
	}

	// PATH and MY_VAR should remain
	found := map[string]bool{}
	for _, kv := range result {
		found[kv] = true
	}
	if !found["PATH=/usr/bin"] {
		t.Error("PATH should be in result")
	}
	if !found["MY_VAR=value"] {
		t.Error("MY_VAR should be in result")
	}
}

func TestBuildEnv_MaxKeys(t *testing.T) {
	pol := ResolvedEnvPolicy{
		MaxKeys: 2,
	}
	baseEnv := []string{
		"A=1",
		"B=2",
		"C=3",
	}

	_, err := BuildEnv(pol, baseEnv, nil)
	if err == nil {
		t.Error("expected error for exceeding max_keys")
	}
}

func TestBuildEnv_MaxBytes(t *testing.T) {
	pol := ResolvedEnvPolicy{
		MaxBytes: 10,
	}
	baseEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}

	_, err := BuildEnv(pol, baseEnv, nil)
	if err == nil {
		t.Error("expected error for exceeding max_bytes")
	}
}

func TestEngine_CheckEnv_DangerousLinkerVars(t *testing.T) {
	// No explicit allow/deny patterns - should block dangerous linker variables
	p := &Policy{
		Version:   1,
		Name:      "test",
		EnvPolicy: EnvPolicy{},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// All of these should be blocked by default
	dangerousVars := []string{
		// Linux dynamic linker
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"LD_AUDIT",
		"LD_DEBUG",
		// macOS dynamic linker
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		// Language code injection
		"PYTHONPATH",
		"PYTHONSTARTUP",
		"RUBYLIB",
		"RUBYOPT",
		"PERL5LIB",
		"PERL5OPT",
		"NODE_PATH",
		"NODE_OPTIONS",
		// Shell modifiers
		"BASH_ENV",
		"ENV",
		"PROMPT_COMMAND",
	}

	for _, name := range dangerousVars {
		t.Run(name, func(t *testing.T) {
			dec := e.CheckEnv(name)
			if dec.Allowed {
				t.Errorf("%s should be denied by default, got Allowed=true (MatchedBy=%s)", name, dec.MatchedBy)
			}
			if dec.MatchedBy != "default-secret-deny" {
				t.Errorf("%s: expected MatchedBy=default-secret-deny, got %q", name, dec.MatchedBy)
			}
		})
	}
}

func TestBuildEnv_BlocksDangerousLinkerVars(t *testing.T) {
	// No allow patterns, should block dangerous vars via default deny
	pol := ResolvedEnvPolicy{}
	baseEnv := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp/libs",
		"PYTHONPATH=/tmp/pycode",
		"NODE_OPTIONS=--require=/tmp/evil.js",
		"MY_SAFE_VAR=value",
	}

	result, err := BuildEnv(pol, baseEnv, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Build a map for easier checking
	resultMap := make(map[string]bool)
	for _, kv := range result {
		resultMap[kv] = true
	}

	// Dangerous vars should be filtered out
	dangerousKVs := []string{
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp/libs",
		"PYTHONPATH=/tmp/pycode",
		"NODE_OPTIONS=--require=/tmp/evil.js",
	}
	for _, kv := range dangerousKVs {
		if resultMap[kv] {
			t.Errorf("dangerous var should have been filtered: %s", kv)
		}
	}

	// Safe vars should remain
	safeKVs := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"MY_SAFE_VAR=value",
	}
	for _, kv := range safeKVs {
		if !resultMap[kv] {
			t.Errorf("safe var should be in result: %s", kv)
		}
	}
}
