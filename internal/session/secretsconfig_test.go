package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"
	"github.com/agentsh/agentsh/internal/proxy/secrets/azurekv"
	"github.com/agentsh/agentsh/internal/proxy/secrets/gcpsm"
	"github.com/agentsh/agentsh/internal/proxy/secrets/onepassword"
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

func TestResolveServiceConfigs_FromHTTPService(t *testing.T) {
	scrubTrue := true
	svcs := []policy.HTTPService{
		{
			Name:     "github",
			Upstream: "https://api.github.com",
			Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/github_token", Format: "ghp_{rand:36}"},
			Inject:   &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Authorization", Template: "Bearer {{secret}}"}},
			ScrubResponse: &scrubTrue,
		},
		{
			Name:     "stripe",
			Upstream: "https://api.stripe.com",
			Default:  "deny",
			Rules:    []policy.HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
			// No secret — filtering-only.
		},
	}
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only github has a secret; stripe should be skipped.
	if len(resolved.ServiceConfigs) != 1 {
		t.Fatalf("want 1 ServiceConfig, got %d", len(resolved.ServiceConfigs))
	}
	if resolved.ServiceConfigs[0].Name != "github" {
		t.Errorf("want github, got %q", resolved.ServiceConfigs[0].Name)
	}
	if len(resolved.InjectHeaders) != 1 {
		t.Fatalf("want 1 InjectHeader, got %d", len(resolved.InjectHeaders))
	}
	if resolved.InjectHeaders[0].HeaderName != "Authorization" {
		t.Errorf("want Authorization, got %q", resolved.InjectHeaders[0].HeaderName)
	}
	if !resolved.ScrubServices["github"] {
		t.Error("github should have scrub_response=true")
	}
}

func TestResolveServiceConfigs_EmptyList(t *testing.T) {
	resolved, err := ResolveServiceConfigs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != nil {
		t.Error("nil input should return nil")
	}
}

func TestResolveServiceConfigs_ScrubResponseDefault(t *testing.T) {
	// Secret present, no explicit scrub_response → should default to true.
	svcs := []policy.HTTPService{{
		Name:     "svc",
		Upstream: "https://api.example.com",
		Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
	}}
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved.ScrubServices["svc"] {
		t.Error("secret present with no explicit scrub_response should default to true")
	}
}

func TestResolveServiceConfigs_ScrubResponseExplicitFalse(t *testing.T) {
	scrubFalse := false
	svcs := []policy.HTTPService{{
		Name:          "svc",
		Upstream:      "https://api.example.com",
		Secret:        &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
		ScrubResponse: &scrubFalse,
	}}
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved.ScrubServices["svc"] {
		t.Error("explicit scrub_response=false should be honored")
	}
}

func TestResolveServiceConfigs_AllFilteringOnly(t *testing.T) {
	// No service has a secret → nil result.
	svcs := []policy.HTTPService{{
		Name:     "filter",
		Upstream: "https://api.example.com",
		Default:  "deny",
		Rules:    []policy.HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
	}}
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != nil {
		t.Error("all-filtering services should return nil")
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

func TestResolveProviderConfigs_GCPSM(t *testing.T) {
	providers := map[string]yaml.Node{
		"gcp": mustYAMLNode(t, "type: gcp-sm\nproject_id: my-gcp-project-123"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["gcp"].TypeName() != "gcp-sm" {
		t.Errorf("TypeName = %q, want gcp-sm", configs["gcp"].TypeName())
	}
	gc, ok := configs["gcp"].(gcpsm.Config)
	if !ok {
		t.Fatalf("expected gcpsm.Config, got %T", configs["gcp"])
	}
	if gc.ProjectID != "my-gcp-project-123" {
		t.Errorf("ProjectID = %q, want my-gcp-project-123", gc.ProjectID)
	}
}

func TestResolveProviderConfigs_AzureKV(t *testing.T) {
	providers := map[string]yaml.Node{
		"azure": mustYAMLNode(t, "type: azure-kv\nvault_url: https://myvault.vault.azure.net/"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["azure"].TypeName() != "azure-kv" {
		t.Errorf("TypeName = %q, want azure-kv", configs["azure"].TypeName())
	}
	ac, ok := configs["azure"].(azurekv.Config)
	if !ok {
		t.Fatalf("expected azurekv.Config, got %T", configs["azure"])
	}
	if ac.VaultURL != "https://myvault.vault.azure.net/" {
		t.Errorf("VaultURL = %q, want https://myvault.vault.azure.net/", ac.VaultURL)
	}
}

func TestResolveProviderConfigs_OP_LiteralKey(t *testing.T) {
	providers := map[string]yaml.Node{
		"op": mustYAMLNode(t, "type: op\nserver_url: https://op.internal\napi_key: eyJhbGciOiJFUz"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	if configs["op"].TypeName() != "op" {
		t.Errorf("TypeName = %q, want op", configs["op"].TypeName())
	}
	oc, ok := configs["op"].(onepassword.Config)
	if !ok {
		t.Fatalf("expected onepassword.Config, got %T", configs["op"])
	}
	if oc.ServerURL != "https://op.internal" {
		t.Errorf("ServerURL = %q", oc.ServerURL)
	}
	if oc.APIKey != "eyJhbGciOiJFUz" {
		t.Errorf("APIKey = %q", oc.APIKey)
	}
	if oc.APIKeyRef != nil {
		t.Error("APIKeyRef should be nil")
	}
}

func TestResolveProviderConfigs_OP_RefKey(t *testing.T) {
	providers := map[string]yaml.Node{
		"op": mustYAMLNode(t, "type: op\nserver_url: https://op.internal\napi_key_ref: keyring://agentsh/op_key"),
	}
	configs, err := ResolveProviderConfigs(providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oc, ok := configs["op"].(onepassword.Config)
	if !ok {
		t.Fatalf("expected onepassword.Config, got %T", configs["op"])
	}
	if oc.APIKey != "" {
		t.Error("APIKey should be empty")
	}
	if oc.APIKeyRef == nil {
		t.Fatal("APIKeyRef should be set")
	}
	if oc.APIKeyRef.Scheme != "keyring" {
		t.Errorf("APIKeyRef.Scheme = %q, want keyring", oc.APIKeyRef.Scheme)
	}
}
