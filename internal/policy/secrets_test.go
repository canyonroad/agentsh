package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustNode(t *testing.T, yamlStr string) yaml.Node {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(yamlStr), &node); err != nil {
		t.Fatal(err)
	}
	// yaml.Unmarshal wraps in a document node; return the content.
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return *node.Content[0]
	}
	return node
}

func TestValidateSecrets_Valid(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
		"vault":   mustNode(t, "type: vault\naddress: https://vault.example.com\nauth:\n  method: token\n  token: test"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com", "*.github.com"}},
			Secret: ServiceSecretYAML{Ref: "vault://kv/data/github#token"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{Header: &ServiceInjectHeaderYAML{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
		{
			Name:   "anthropic",
			Match:  ServiceMatchYAML{Hosts: []string{"api.anthropic.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/anthropic_key"},
			Fake:   ServiceFakeYAML{Format: "sk-ant-{rand:93}"},
			Inject: ServiceInjectYAML{Header: &ServiceInjectHeaderYAML{
				Name: "x-api-key", Template: "{{secret}}",
			}},
		},
	}

	warnings, err := ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestValidateSecrets_UnknownProviderType(t *testing.T) {
	providers := map[string]yaml.Node{
		"foo": mustNode(t, "type: unknown"),
	}
	_, err := ValidateSecrets(providers, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("expected unknown type error, got: %v", err)
	}
}

func TestValidateSecrets_DuplicateServiceName(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "github", Match: ServiceMatchYAML{Hosts: []string{"a.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
		{Name: "github", Match: ServiceMatchYAML{Hosts: []string{"b.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/c"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "duplicate service name") {
		t.Errorf("expected duplicate error, got: %v", err)
	}
}

func TestValidateSecrets_InvalidFakeFormat(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "bad", Match: ServiceMatchYAML{Hosts: []string{"a.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "no-rand-here"}},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "fake.format") {
		t.Errorf("expected fake.format error, got: %v", err)
	}
}

func TestValidateSecrets_MissingSecretTemplate(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name: "bad", Match: ServiceMatchYAML{Hosts: []string{"a.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{Header: &ServiceInjectHeaderYAML{Name: "Auth", Template: "Bearer no-placeholder"}},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "{{secret}}") {
		t.Errorf("expected template error, got: %v", err)
	}
}

func TestValidateSecrets_UndeclaredProviderScheme(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "bad", Match: ServiceMatchYAML{Hosts: []string{"a.com"}}, Secret: ServiceSecretYAML{Ref: "vault://kv/data/x#y"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "no matching provider") {
		t.Errorf("expected no matching provider error, got: %v", err)
	}
}

func TestValidateSecrets_InvalidOnMissing(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "bad", Match: ServiceMatchYAML{Hosts: []string{"a.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/b", OnMissing: "skip"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected on_missing error, got: %v", err)
	}
}

func TestValidateSecrets_OverlappingHosts_Warning(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "svc1", Match: ServiceMatchYAML{Hosts: []string{"api.example.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
		{Name: "svc2", Match: ServiceMatchYAML{Hosts: []string{"api.example.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/c"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	warnings, err := ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected overlap warning")
	}
}

func TestValidateSecrets_EmptyPolicy_BackwardCompatible(t *testing.T) {
	warnings, err := ValidateSecrets(nil, nil)
	if err != nil {
		t.Fatalf("empty should be valid: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestValidateSecrets_EmptyHosts(t *testing.T) {
	providers := map[string]yaml.Node{
		"keyring": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{Name: "bad", Match: ServiceMatchYAML{Hosts: nil}, Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil || !strings.Contains(err.Error(), "hosts must not be empty") {
		t.Errorf("expected empty hosts error, got: %v", err)
	}
}

func TestValidateSecrets_NoProviders_ServiceNeedsProvider(t *testing.T) {
	services := []ServiceYAML{
		{Name: "github", Match: ServiceMatchYAML{Hosts: []string{"a.com"}}, Secret: ServiceSecretYAML{Ref: "keyring://a/b"}, Fake: ServiceFakeYAML{Format: "ghp_{rand:36}"}},
	}
	_, err := ValidateSecrets(nil, services)
	if err == nil || !strings.Contains(err.Error(), "no matching provider") {
		t.Errorf("expected no matching provider error, got: %v", err)
	}
}

func TestValidateSecrets_InjectEnvEmptyName(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: ""}},
			},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for empty inject.env name")
	}
}

func TestValidateSecrets_InjectEnvInvalidChar(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: "PATH=/tmp"}},
			},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for name containing =")
	}
}

func TestValidateSecrets_InjectEnvDuplicateAcrossServices(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: "MY_TOKEN"}},
			},
		},
		{
			Name:   "stripe",
			Match:  ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   ServiceFakeYAML{Format: "xk_test_{rand:24}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: "MY_TOKEN"}},
			},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for duplicate env var name across services")
	}
}

func TestValidateSecrets_InjectEnvValid(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: "GITHUB_TOKEN"}},
			},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSecrets_InjectEnvReservedPrefixCaseInsensitive(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	for _, name := range []string{"agentsh_foo", "Agentsh_Bar", "AGENTSH_BAZ"} {
		services := []ServiceYAML{
			{
				Name:   "github",
				Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
				Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
				Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
				Inject: ServiceInjectYAML{
					Env: []ServiceInjectEnvYAML{{Name: name}},
				},
			},
		}
		_, err := ValidateSecrets(providers, services)
		if err == nil {
			t.Errorf("expected error for reserved prefix in name %q", name)
		}
	}
}

func TestValidateSecrets_InjectEnvReservedPrefix(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []ServiceYAML{
		{
			Name:   "github",
			Match:  ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: ServiceInjectYAML{
				Env: []ServiceInjectEnvYAML{{Name: "AGENTSH_SESSION_ID"}},
			},
		},
	}
	_, err := ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for reserved AGENTSH_ prefix")
	}
	if !strings.Contains(err.Error(), "reserved AGENTSH_ prefix") {
		t.Errorf("error should mention reserved prefix, got: %v", err)
	}
}

func TestValidateSecrets_AWSProvider(t *testing.T) {
	providers := map[string]yaml.Node{
		"aws_sm": mustNode(t, "type: aws-sm\nregion: us-east-1"),
	}
	services := []ServiceYAML{
		{
			Name:   "myservice",
			Match:  ServiceMatchYAML{Hosts: []string{"api.example.com"}},
			Secret: ServiceSecretYAML{Ref: "aws-sm://prod/my-secret#token"},
			Fake:   ServiceFakeYAML{Format: "tok_{rand:36}"},
			Inject: ServiceInjectYAML{Header: &ServiceInjectHeaderYAML{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
	}
	warnings, err := ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("ValidateSecrets error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
