package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"
	"github.com/agentsh/agentsh/internal/proxy/secrets/vault"
	"gopkg.in/yaml.v3"
)

func mustYAMLNode(t *testing.T, s string) yaml.Node {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(s), &node); err != nil {
		t.Fatal(err)
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return *node.Content[0]
	}
	return node
}

func TestResolveProviderConfigs_Keyring(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustYAMLNode(t, "type: keyring"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["kr"].TypeName() != "keyring" {
		t.Errorf("TypeName = %q, want keyring", configs["kr"].TypeName())
	}
}

func TestResolveProviderConfigs_Vault(t *testing.T) {
	providers := map[string]yaml.Node{
		"v": mustYAMLNode(t, "type: vault\naddress: https://vault.example.com\nauth:\n  method: token\n  token_ref: keyring://agentsh/vt"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vc, ok := configs["v"].(vault.Config)
	if !ok {
		t.Fatalf("expected vault.Config, got %T", configs["v"])
	}
	if vc.Address != "https://vault.example.com" {
		t.Errorf("Address = %q", vc.Address)
	}
	if vc.Auth.TokenRef == nil {
		t.Fatal("TokenRef should be set")
	}
	if vc.Auth.TokenRef.Scheme != "keyring" {
		t.Errorf("TokenRef.Scheme = %q, want keyring", vc.Auth.TokenRef.Scheme)
	}
}

func TestResolveProviderConfigs_Empty(t *testing.T) {
	configs, err := ResolveProviderConfigs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configs != nil {
		t.Errorf("expected nil, got %v", configs)
	}
}

func TestResolveServiceConfigs(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{Header: &policy.ServiceInjectHeaderYAML{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ServiceConfigs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(result.ServiceConfigs))
	}
	if result.ServiceConfigs[0].Name != "github" {
		t.Errorf("Name = %q", result.ServiceConfigs[0].Name)
	}
	if len(result.Patterns) != 1 || result.Patterns[0].Name != "github" {
		t.Error("patterns not populated")
	}
	if len(result.InjectHeaders) != 1 || result.InjectHeaders[0].HeaderName != "Authorization" {
		t.Error("inject headers not populated")
	}
}

func TestResolveServiceConfigs_Empty(t *testing.T) {
	result, err := ResolveServiceConfigs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil")
	}
}

func TestResolveServiceConfigs_InjectEnv(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: "GITHUB_TOKEN"}},
			},
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.EnvVars) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(result.EnvVars))
	}
	if result.EnvVars[0].ServiceName != "github" {
		t.Errorf("ServiceName = %q, want github", result.EnvVars[0].ServiceName)
	}
	if result.EnvVars[0].VarName != "GITHUB_TOKEN" {
		t.Errorf("VarName = %q, want GITHUB_TOKEN", result.EnvVars[0].VarName)
	}
}

func TestResolveServiceConfigs_ScrubResponse_NoneEnabled(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			// ScrubResponse intentionally NOT set (defaults to false)
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ScrubServices must be non-nil (empty map), NOT nil.
	// nil would mean "scrub all" in CredsSubHook.
	if result.ScrubServices == nil {
		t.Fatal("ScrubServices should be non-nil empty map, got nil")
	}
	if len(result.ScrubServices) != 0 {
		t.Errorf("ScrubServices should be empty, got %v", result.ScrubServices)
	}
}

func TestResolveServiceConfigs_ScrubResponse(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:          "github",
			Match:         policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret:        policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:          policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			ScrubResponse: true,
		},
		{
			Name:   "stripe",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   policy.ServiceFakeYAML{Format: "xk_test_{rand:24}"},
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ScrubServices["github"] {
		t.Error("expected github in ScrubServices")
	}
	if result.ScrubServices["stripe"] {
		t.Error("stripe should not be in ScrubServices")
	}
}

func TestResolveProviderConfigs_AWSSM(t *testing.T) {
	providers := map[string]yaml.Node{
		"aws": mustYAMLNode(t, "type: aws-sm\nregion: us-west-2"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["aws"].TypeName() != "aws-sm" {
		t.Errorf("TypeName = %q, want aws-sm", configs["aws"].TypeName())
	}
	ac, ok := configs["aws"].(awssm.Config)
	if !ok {
		t.Fatalf("expected awssm.Config, got %T", configs["aws"])
	}
	if ac.Region != "us-west-2" {
		t.Errorf("Region = %q, want us-west-2", ac.Region)
	}
}
