package session

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/awssm"
	"github.com/agentsh/agentsh/internal/proxy/secrets/azurekv"
	"github.com/agentsh/agentsh/internal/proxy/secrets/gcpsm"
	"github.com/agentsh/agentsh/internal/proxy/secrets/keyring"
	"github.com/agentsh/agentsh/internal/proxy/secrets/onepassword"
	"github.com/agentsh/agentsh/internal/proxy/secrets/vault"
	"gopkg.in/yaml.v3"
)

// InjectHeaderConfig holds header injection config for one service.
type InjectHeaderConfig struct {
	ServiceName string
	HeaderName  string
	Template    string
}

// ServiceEnvVar maps a service name to an env var that should receive
// the service's fake credential.
type ServiceEnvVar struct {
	ServiceName string
	VarName     string
}

// ResolvedServices holds the parsed outputs needed by the bootstrap flow.
type ResolvedServices struct {
	ServiceConfigs []ServiceConfig
	InjectHeaders  []InjectHeaderConfig
	ScrubServices  map[string]bool // service name -> scrub_response flag
}

// ResolveProviderConfigs decodes policy YAML provider nodes into
// typed ProviderConfig values suitable for secrets.NewRegistry.
func ResolveProviderConfigs(providers map[string]yaml.Node) (map[string]secrets.ProviderConfig, error) {
	if len(providers) == 0 {
		return nil, nil
	}
	configs := make(map[string]secrets.ProviderConfig, len(providers))
	for name, node := range providers {
		cfg, err := decodeProviderConfig(name, node)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		configs[name] = cfg
	}
	return configs, nil
}

// ResolveServiceConfigs converts HTTPService declarations into
// ServiceConfigs for BootstrapCredentials, InjectHeaderConfigs for hook
// registration, and ScrubServices for response scrubbing.
// Returns nil when no service carries a secret (filtering-only).
func ResolveServiceConfigs(svcs []policy.HTTPService) (*ResolvedServices, error) {
	if len(svcs) == 0 {
		return nil, nil
	}

	// Filter to services with credentials.
	var hasSecret bool
	for _, svc := range svcs {
		if svc.Secret != nil {
			hasSecret = true
			break
		}
	}
	if !hasSecret {
		return nil, nil
	}

	result := &ResolvedServices{
		ScrubServices: make(map[string]bool),
	}
	for _, svc := range svcs {
		if svc.Secret == nil {
			continue
		}
		ref, err := secrets.ParseRef(svc.Secret.Ref)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		result.ServiceConfigs = append(result.ServiceConfigs, ServiceConfig{
			Name:       svc.Name,
			SecretRef:  ref,
			FakeFormat: svc.Secret.Format,
		})
		if svc.Inject != nil && svc.Inject.Header != nil {
			result.InjectHeaders = append(result.InjectHeaders, InjectHeaderConfig{
				ServiceName: svc.Name,
				HeaderName:  svc.Inject.Header.Name,
				Template:    svc.Inject.Header.Template,
			})
		}
		// Resolve scrub_response default: nil → true when secret present.
		if svc.ScrubResponse != nil {
			result.ScrubServices[svc.Name] = *svc.ScrubResponse
		} else {
			result.ScrubServices[svc.Name] = true
		}
	}
	return result, nil
}

// DefaultConstructors returns the constructor map for all known
// provider types. Used by secrets.NewRegistry.
func DefaultConstructors() map[string]secrets.ConstructorFunc {
	return map[string]secrets.ConstructorFunc{
		"keyring": func(_ context.Context, cfg secrets.ProviderConfig, _ secrets.RefResolver) (secrets.SecretProvider, error) {
			kc, ok := cfg.(keyring.Config)
			if !ok {
				return nil, fmt.Errorf("expected keyring.Config, got %T", cfg)
			}
			return keyring.New(kc)
		},
		"vault": func(ctx context.Context, cfg secrets.ProviderConfig, resolver secrets.RefResolver) (secrets.SecretProvider, error) {
			vc, ok := cfg.(vault.Config)
			if !ok {
				return nil, fmt.Errorf("expected vault.Config, got %T", cfg)
			}
			return vault.New(ctx, vc, resolver)
		},
		"aws-sm": func(ctx context.Context, cfg secrets.ProviderConfig, _ secrets.RefResolver) (secrets.SecretProvider, error) {
			ac, ok := cfg.(awssm.Config)
			if !ok {
				return nil, fmt.Errorf("expected awssm.Config, got %T", cfg)
			}
			return awssm.New(ctx, ac, nil)
		},
		"gcp-sm": func(ctx context.Context, cfg secrets.ProviderConfig, _ secrets.RefResolver) (secrets.SecretProvider, error) {
			gc, ok := cfg.(gcpsm.Config)
			if !ok {
				return nil, fmt.Errorf("expected gcpsm.Config, got %T", cfg)
			}
			return gcpsm.New(ctx, gc, nil)
		},
		"azure-kv": func(ctx context.Context, cfg secrets.ProviderConfig, _ secrets.RefResolver) (secrets.SecretProvider, error) {
			ac, ok := cfg.(azurekv.Config)
			if !ok {
				return nil, fmt.Errorf("expected azurekv.Config, got %T", cfg)
			}
			return azurekv.New(ctx, ac, nil)
		},
		"op": func(ctx context.Context, cfg secrets.ProviderConfig, resolver secrets.RefResolver) (secrets.SecretProvider, error) {
			oc, ok := cfg.(onepassword.Config)
			if !ok {
				return nil, fmt.Errorf("expected onepassword.Config, got %T", cfg)
			}
			return onepassword.New(ctx, oc, resolver)
		},
	}
}

// decodeProviderConfig decodes a yaml.Node into the appropriate
// typed ProviderConfig based on the "type" field.
func decodeProviderConfig(_ string, node yaml.Node) (secrets.ProviderConfig, error) {
	var base struct {
		Type string `yaml:"type"`
	}
	if err := node.Decode(&base); err != nil {
		return nil, fmt.Errorf("decode type: %w", err)
	}
	switch base.Type {
	case "keyring":
		return keyring.Config{}, nil
	case "vault":
		return decodeVaultConfig(node)
	case "aws-sm":
		return decodeAWSConfig(node)
	case "gcp-sm":
		return decodeGCPSMConfig(node)
	case "azure-kv":
		return decodeAzureKVConfig(node)
	case "op":
		return decodeOPConfig(node)
	default:
		return nil, fmt.Errorf("unknown provider type %q", base.Type)
	}
}

// vaultYAML is the YAML representation of a vault provider config.
type vaultYAML struct {
	Type      string        `yaml:"type"`
	Address   string        `yaml:"address"`
	Namespace string        `yaml:"namespace,omitempty"`
	Auth      vaultAuthYAML `yaml:"auth"`
}

type vaultAuthYAML struct {
	Method        string `yaml:"method"`
	Token         string `yaml:"token,omitempty"`
	TokenRef      string `yaml:"token_ref,omitempty"`
	RoleID        string `yaml:"role_id,omitempty"`
	RoleIDRef     string `yaml:"role_id_ref,omitempty"`
	SecretID      string `yaml:"secret_id,omitempty"`
	SecretIDRef   string `yaml:"secret_id_ref,omitempty"`
	KubeRole      string `yaml:"kube_role,omitempty"`
	KubeMountPath string `yaml:"kube_mount_path,omitempty"`
	KubeTokenPath string `yaml:"kube_token_path,omitempty"`
}

func decodeVaultConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw vaultYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode vault config: %w", err)
	}
	cfg := vault.Config{
		Address:   raw.Address,
		Namespace: raw.Namespace,
		Auth: vault.AuthConfig{
			Method:        raw.Auth.Method,
			Token:         raw.Auth.Token,
			RoleID:        raw.Auth.RoleID,
			SecretID:      raw.Auth.SecretID,
			KubeRole:      raw.Auth.KubeRole,
			KubeMountPath: raw.Auth.KubeMountPath,
			KubeTokenPath: raw.Auth.KubeTokenPath,
		},
	}
	// Parse chained refs.
	if raw.Auth.TokenRef != "" {
		ref, err := secrets.ParseRef(raw.Auth.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("auth.token_ref: %w", err)
		}
		cfg.Auth.TokenRef = &ref
	}
	if raw.Auth.RoleIDRef != "" {
		ref, err := secrets.ParseRef(raw.Auth.RoleIDRef)
		if err != nil {
			return nil, fmt.Errorf("auth.role_id_ref: %w", err)
		}
		cfg.Auth.RoleIDRef = &ref
	}
	if raw.Auth.SecretIDRef != "" {
		ref, err := secrets.ParseRef(raw.Auth.SecretIDRef)
		if err != nil {
			return nil, fmt.Errorf("auth.secret_id_ref: %w", err)
		}
		cfg.Auth.SecretIDRef = &ref
	}
	return cfg, nil
}

// awssmYAML is the YAML representation of an AWS SM provider config.
type awssmYAML struct {
	Type   string `yaml:"type"`
	Region string `yaml:"region"`
}

func decodeAWSConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw awssmYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode aws-sm config: %w", err)
	}
	return awssm.Config{
		Region: raw.Region,
	}, nil
}

// gcpsmYAML is the YAML representation of a GCP SM provider config.
type gcpsmYAML struct {
	Type      string `yaml:"type"`
	ProjectID string `yaml:"project_id"`
}

func decodeGCPSMConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw gcpsmYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode gcp-sm config: %w", err)
	}
	return gcpsm.Config{
		ProjectID: raw.ProjectID,
	}, nil
}

// azurekvYAML is the YAML representation of an Azure KV provider config.
type azurekvYAML struct {
	Type     string `yaml:"type"`
	VaultURL string `yaml:"vault_url"`
}

func decodeAzureKVConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw azurekvYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode azure-kv config: %w", err)
	}
	return azurekv.Config{
		VaultURL: raw.VaultURL,
	}, nil
}

// opYAML is the YAML representation of a 1Password provider config.
type opYAML struct {
	Type      string `yaml:"type"`
	ServerURL string `yaml:"server_url"`
	APIKey    string `yaml:"api_key,omitempty"`
	APIKeyRef string `yaml:"api_key_ref,omitempty"`
}

func decodeOPConfig(node yaml.Node) (secrets.ProviderConfig, error) {
	var raw opYAML
	if err := node.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode op config: %w", err)
	}
	cfg := onepassword.Config{
		ServerURL: raw.ServerURL,
		APIKey:    raw.APIKey,
	}
	if raw.APIKeyRef != "" {
		ref, err := secrets.ParseRef(raw.APIKeyRef)
		if err != nil {
			return nil, fmt.Errorf("api_key_ref: %w", err)
		}
		cfg.APIKeyRef = &ref
	}
	return cfg, nil
}

// BuildSecretsRegistry creates a provider registry from the resolved
// config and returns a SecretFetcher. Convenience wrapper around
// secrets.NewRegistry.
func BuildSecretsRegistry(ctx context.Context, configs map[string]secrets.ProviderConfig) (*secrets.Registry, error) {
	return secrets.NewRegistry(ctx, configs, DefaultConstructors())
}
