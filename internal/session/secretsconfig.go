package session

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/keyring"
	"github.com/agentsh/agentsh/internal/proxy/secrets/vault"
	"github.com/agentsh/agentsh/internal/proxy/services"
	"gopkg.in/yaml.v3"
)

// InjectHeaderConfig holds header injection config for one service.
type InjectHeaderConfig struct {
	ServiceName string
	HeaderName  string
	Template    string
}

// ResolvedServices holds the parsed outputs needed by the bootstrap flow.
type ResolvedServices struct {
	ServiceConfigs []ServiceConfig
	Patterns       []services.ServicePattern
	InjectHeaders  []InjectHeaderConfig
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

// ResolveServiceConfigs converts policy YAML service declarations into
// ServiceConfigs for BootstrapCredentials plus ServicePatterns for the
// matcher and InjectHeaderConfigs for hook registration.
func ResolveServiceConfigs(svcs []policy.ServiceYAML) (*ResolvedServices, error) {
	if len(svcs) == 0 {
		return nil, nil
	}
	result := &ResolvedServices{
		ServiceConfigs: make([]ServiceConfig, 0, len(svcs)),
		Patterns:       make([]services.ServicePattern, 0, len(svcs)),
	}
	for _, svc := range svcs {
		ref, err := secrets.ParseRef(svc.Secret.Ref)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		result.ServiceConfigs = append(result.ServiceConfigs, ServiceConfig{
			Name:       svc.Name,
			SecretRef:  ref,
			FakeFormat: svc.Fake.Format,
		})
		result.Patterns = append(result.Patterns, services.ServicePattern{
			Name:  svc.Name,
			Hosts: svc.Match.Hosts,
		})
		if svc.Inject.Header != nil {
			result.InjectHeaders = append(result.InjectHeaders, InjectHeaderConfig{
				ServiceName: svc.Name,
				HeaderName:  svc.Inject.Header.Name,
				Template:    svc.Inject.Header.Template,
			})
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

// BuildSecretsRegistry creates a provider registry from the resolved
// config and returns a SecretFetcher. Convenience wrapper around
// secrets.NewRegistry.
func BuildSecretsRegistry(ctx context.Context, configs map[string]secrets.ProviderConfig) (*secrets.Registry, error) {
	return secrets.NewRegistry(ctx, configs, DefaultConstructors())
}
