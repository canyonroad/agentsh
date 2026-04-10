package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
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
