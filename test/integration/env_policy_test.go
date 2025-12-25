//go:build integration

package integration

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

// TestEnvPolicyCheckEnv tests the CheckEnv method with glob patterns.
func TestEnvPolicyCheckEnv(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test-env-policy",
		EnvPolicy: policy.EnvPolicy{
			Allow: []string{"PATH", "HOME", "USER", "MY_*"},
			Deny:  []string{"MY_SECRET_*", "*_TOKEN"},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	tests := []struct {
		name    string
		allowed bool
	}{
		// Explicitly allowed
		{"PATH", true},
		{"HOME", true},
		{"USER", true},

		// Allowed by pattern
		{"MY_VAR", true},
		{"MY_APP_DATA", true},

		// Denied by pattern (deny wins over allow)
		{"MY_SECRET_KEY", false},
		{"MY_SECRET_TOKEN", false},
		{"GITHUB_TOKEN", false},
		{"API_TOKEN", false},

		// Not in allow list (default deny when allow patterns defined)
		{"OTHER_VAR", false},
		{"AWS_ACCESS_KEY_ID", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := engine.CheckEnv(tt.name)
			if dec.Allowed != tt.allowed {
				t.Errorf("CheckEnv(%q) = Allowed:%v (MatchedBy:%s), want Allowed:%v",
					tt.name, dec.Allowed, dec.MatchedBy, tt.allowed)
			}
		})
	}
}

// TestEnvPolicyDefaultSecrets tests default secret blocking.
func TestEnvPolicyDefaultSecrets(t *testing.T) {
	// No explicit allow/deny - uses default secret deny list
	p := &policy.Policy{
		Version:   1,
		Name:      "test-default-secrets",
		EnvPolicy: policy.EnvPolicy{},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// These should be blocked by default
	secrets := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"KUBECONFIG",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"AZURE_CLIENT_SECRET",
	}

	for _, secret := range secrets {
		t.Run(secret, func(t *testing.T) {
			dec := engine.CheckEnv(secret)
			if dec.Allowed {
				t.Errorf("CheckEnv(%q) should be denied by default, got Allowed=true (MatchedBy:%s)",
					secret, dec.MatchedBy)
			}
		})
	}

	// These should be allowed
	allowed := []string{"PATH", "HOME", "USER", "MY_VAR", "CUSTOM_VAR"}
	for _, v := range allowed {
		t.Run(v, func(t *testing.T) {
			dec := engine.CheckEnv(v)
			if !dec.Allowed {
				t.Errorf("CheckEnv(%q) should be allowed, got Allowed=false (MatchedBy:%s)",
					v, dec.MatchedBy)
			}
		})
	}
}

// TestBuildEnvGlobPatterns tests BuildEnv with glob patterns.
func TestBuildEnvGlobPatterns(t *testing.T) {
	pol := policy.ResolvedEnvPolicy{
		Allow: []string{"PATH", "HOME", "MY_*"},
		Deny:  []string{"MY_SECRET_*"},
	}

	baseEnv := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"MY_VAR=value1",
		"MY_APP=value2",
		"MY_SECRET_KEY=secret",
		"OTHER_VAR=other",
	}

	result, err := policy.BuildEnv(pol, baseEnv, nil)
	if err != nil {
		t.Fatalf("BuildEnv failed: %v", err)
	}

	// Build a set of expected vars
	expected := map[string]bool{
		"PATH=/usr/bin":   true,
		"HOME=/home/user": true,
		"MY_VAR=value1":   true,
		"MY_APP=value2":   true,
	}

	// MY_SECRET_KEY and OTHER_VAR should NOT be in result
	notExpected := map[string]bool{
		"MY_SECRET_KEY=secret": true,
		"OTHER_VAR=other":      true,
	}

	for _, kv := range result {
		if notExpected[kv] {
			t.Errorf("BuildEnv should not include %q", kv)
		}
		delete(expected, kv)
	}

	for kv := range expected {
		t.Errorf("BuildEnv missing expected var %q", kv)
	}
}

// TestBuildEnvMaxKeys tests max_keys enforcement.
func TestBuildEnvMaxKeys(t *testing.T) {
	pol := policy.ResolvedEnvPolicy{
		MaxKeys: 2,
	}

	baseEnv := []string{
		"A=1",
		"B=2",
		"C=3",
	}

	_, err := policy.BuildEnv(pol, baseEnv, nil)
	if err == nil {
		t.Error("BuildEnv should fail when exceeding max_keys")
	}
}

// TestBuildEnvMaxBytes tests max_bytes enforcement.
func TestBuildEnvMaxBytes(t *testing.T) {
	pol := policy.ResolvedEnvPolicy{
		MaxBytes: 10,
	}

	baseEnv := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}

	_, err := policy.BuildEnv(pol, baseEnv, nil)
	if err == nil {
		t.Error("BuildEnv should fail when exceeding max_bytes")
	}
}

// TestBuildEnvAddKeys tests additional keys merging.
func TestBuildEnvAddKeys(t *testing.T) {
	pol := policy.ResolvedEnvPolicy{
		Allow: []string{"PATH", "HOME", "EXTRA_*"},
	}

	baseEnv := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
	}

	addKeys := map[string]string{
		"EXTRA_VAR": "added",
	}

	result, err := policy.BuildEnv(pol, baseEnv, addKeys)
	if err != nil {
		t.Fatalf("BuildEnv failed: %v", err)
	}

	found := false
	for _, kv := range result {
		if kv == "EXTRA_VAR=added" {
			found = true
			break
		}
	}

	if !found {
		t.Error("BuildEnv should include EXTRA_VAR from addKeys")
	}
}

// TestMergeEnvPolicy tests policy merging.
func TestMergeEnvPolicy(t *testing.T) {
	global := policy.EnvPolicy{
		Allow:          []string{"PATH", "HOME"},
		Deny:           []string{"SECRET_*"},
		MaxBytes:       1000,
		MaxKeys:        10,
		BlockIteration: false,
	}

	rule := policy.CommandRule{
		EnvAllow:          []string{"PATH", "HOME", "EXTRA"},
		EnvDeny:           []string{"SECRET_*", "TOKEN_*"},
		EnvMaxBytes:       500,
		EnvMaxKeys:        5,
		EnvBlockIteration: boolPtr(true),
	}

	merged := policy.MergeEnvPolicy(global, rule)

	// Rule should override global
	if len(merged.Allow) != 3 {
		t.Errorf("expected 3 allow entries, got %d", len(merged.Allow))
	}
	if len(merged.Deny) != 2 {
		t.Errorf("expected 2 deny entries, got %d", len(merged.Deny))
	}
	if merged.MaxBytes != 500 {
		t.Errorf("expected MaxBytes=500, got %d", merged.MaxBytes)
	}
	if merged.MaxKeys != 5 {
		t.Errorf("expected MaxKeys=5, got %d", merged.MaxKeys)
	}
	if !merged.BlockIteration {
		t.Error("expected BlockIteration=true")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// TestValidateEnvPolicy tests policy validation.
func TestValidateEnvPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  policy.EnvPolicy
		wantErr bool
	}{
		{
			name:    "valid empty policy",
			policy:  policy.EnvPolicy{},
			wantErr: false,
		},
		{
			name: "valid policy with limits",
			policy: policy.EnvPolicy{
				MaxBytes: 1000,
				MaxKeys:  10,
			},
			wantErr: false,
		},
		{
			name: "invalid negative max_bytes",
			policy: policy.EnvPolicy{
				MaxBytes: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid negative max_keys",
			policy: policy.EnvPolicy{
				MaxKeys: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.ValidateEnvPolicy(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnvPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
