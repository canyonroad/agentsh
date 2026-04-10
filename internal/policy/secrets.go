// internal/policy/secrets.go
package policy

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"gopkg.in/yaml.v3"
)

// ServiceYAML represents a service declaration in policy YAML.
type ServiceYAML struct {
	Name          string            `yaml:"name"`
	Match         ServiceMatchYAML  `yaml:"match"`
	Secret        ServiceSecretYAML `yaml:"secret"`
	Fake          ServiceFakeYAML   `yaml:"fake"`
	Inject        ServiceInjectYAML `yaml:"inject,omitempty"`
	ScrubResponse bool              `yaml:"scrub_response,omitempty"`
	Hooks         []string          `yaml:"hooks,omitempty"`
}

// ServiceMatchYAML defines which hosts a service matches.
type ServiceMatchYAML struct {
	Hosts []string `yaml:"hosts"`
}

// ServiceSecretYAML defines how to fetch the real credential.
type ServiceSecretYAML struct {
	Ref       string `yaml:"ref"`
	OnMissing string `yaml:"on_missing,omitempty"`
}

// ServiceFakeYAML defines how to generate the fake credential.
type ServiceFakeYAML struct {
	Format string `yaml:"format"`
}

// ServiceInjectYAML defines how the credential is injected.
type ServiceInjectYAML struct {
	Header *ServiceInjectHeaderYAML `yaml:"header,omitempty"`
	Env    []ServiceInjectEnvYAML   `yaml:"env,omitempty"`
}

// ServiceInjectHeaderYAML defines header injection config.
type ServiceInjectHeaderYAML struct {
	Name     string `yaml:"name"`
	Template string `yaml:"template"`
}

// ServiceInjectEnvYAML defines env var injection config (parsed, not wired in Plan 6).
type ServiceInjectEnvYAML struct {
	Name string `yaml:"name"`
}

// knownProviderTypes lists the provider type names (URI schemes) that
// Plan 6 supports. Extended as new providers land.
var knownProviderTypes = map[string]bool{
	"keyring": true,
	"vault":   true,
}

// ValidateSecrets validates the providers and services sections of a Policy.
// It checks structural rules only -- provider constructability and secret
// existence are validated at bootstrap time.
func ValidateSecrets(providers map[string]yaml.Node, services []ServiceYAML) (warnings []string, err error) {
	// Collect declared provider schemes for cross-referencing.
	providerSchemes := make(map[string]string) // scheme -> provider name
	for name, node := range providers {
		ptype, typeErr := extractProviderType(node)
		if typeErr != nil {
			return nil, fmt.Errorf("providers.%s: %w", name, typeErr)
		}
		if !knownProviderTypes[ptype] {
			return nil, fmt.Errorf("providers.%s: unknown type %q", name, ptype)
		}
		if prev, dup := providerSchemes[ptype]; dup {
			return nil, fmt.Errorf("providers.%s: duplicate type %q (already declared by %q)", name, ptype, prev)
		}
		providerSchemes[ptype] = name
	}

	// Validate services.
	seen := make(map[string]bool)
	hostOwner := make(map[string]string) // host pattern -> first service name (for overlap warnings)
	envOwner := make(map[string]string)  // env var name -> first service name
	for i, svc := range services {
		if svc.Name == "" {
			return nil, fmt.Errorf("services[%d]: name is required", i)
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("services[%d]: duplicate service name %q", i, svc.Name)
		}
		seen[svc.Name] = true

		// match.hosts
		if len(svc.Match.Hosts) == 0 {
			return nil, fmt.Errorf("services[%d] %q: match.hosts must not be empty", i, svc.Name)
		}
		for _, h := range svc.Match.Hosts {
			if err := validateHostPattern(h); err != nil {
				return nil, fmt.Errorf("services[%d] %q: match.hosts: %w", i, svc.Name, err)
			}
			if prev, overlap := hostOwner[strings.ToLower(h)]; overlap {
				warnings = append(warnings, fmt.Sprintf(
					"services: host pattern %q in %q overlaps with %q (first match wins)", h, svc.Name, prev))
			}
			hostOwner[strings.ToLower(h)] = svc.Name
		}

		// secret.ref -- must parse and reference a declared provider
		ref, parseErr := secrets.ParseRef(svc.Secret.Ref)
		if parseErr != nil {
			return nil, fmt.Errorf("services[%d] %q: secret.ref: %w", i, svc.Name, parseErr)
		}
		if _, ok := providerSchemes[ref.Scheme]; !ok {
			return nil, fmt.Errorf("services[%d] %q: secret.ref scheme %q has no matching provider", i, svc.Name, ref.Scheme)
		}

		// fake.format
		if _, _, fmtErr := secrets.ParseFormat(svc.Fake.Format); fmtErr != nil {
			return nil, fmt.Errorf("services[%d] %q: fake.format: %w", i, svc.Name, fmtErr)
		}

		// on_missing
		switch svc.Secret.OnMissing {
		case "", "fail":
			// ok
		default:
			return nil, fmt.Errorf("services[%d] %q: on_missing %q not supported (only \"fail\" in Plan 6)", i, svc.Name, svc.Secret.OnMissing)
		}

		// inject.header.template
		if svc.Inject.Header != nil {
			if svc.Inject.Header.Name == "" {
				return nil, fmt.Errorf("services[%d] %q: inject.header.name is required", i, svc.Name)
			}
			if !strings.Contains(svc.Inject.Header.Template, "{{secret}}") {
				return nil, fmt.Errorf("services[%d] %q: inject.header.template must contain {{secret}}", i, svc.Name)
			}
		}

		// inject.env validation
		for j, ev := range svc.Inject.Env {
			if ev.Name == "" {
				return nil, fmt.Errorf("services[%d] %q: inject.env[%d].name is required", i, svc.Name, j)
			}
			if strings.ContainsAny(ev.Name, "=\x00") {
				return nil, fmt.Errorf("services[%d] %q: inject.env[%d].name %q contains invalid character", i, svc.Name, j, ev.Name)
			}
			if strings.HasPrefix(strings.ToUpper(ev.Name), "AGENTSH_") {
				return nil, fmt.Errorf("services[%d] %q: inject.env[%d].name %q uses reserved AGENTSH_ prefix", i, svc.Name, j, ev.Name)
			}
			if prev, dup := envOwner[envVarNormalizedKey(ev.Name)]; dup {
				return nil, fmt.Errorf("services[%d] %q: inject.env name %q already declared by service %q", i, svc.Name, ev.Name, prev)
			}
			envOwner[envVarNormalizedKey(ev.Name)] = svc.Name
		}
	}

	return warnings, nil
}

// envVarNormalizedKey returns the env var name normalized for duplicate
// detection. On Windows env vars are case-insensitive, so fold to upper.
func envVarNormalizedKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

// extractProviderType decodes just the "type" field from a provider yaml.Node.
func extractProviderType(node yaml.Node) (string, error) {
	var base struct {
		Type string `yaml:"type"`
	}
	if err := node.Decode(&base); err != nil {
		return "", fmt.Errorf("decode type: %w", err)
	}
	if base.Type == "" {
		return "", fmt.Errorf("type is required")
	}
	return base.Type, nil
}

// validateHostPattern checks that a host pattern is a valid literal or
// a single-level wildcard ("*.example.com").
func validateHostPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty host pattern")
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if suffix == "" || strings.Contains(suffix, "*") {
			return fmt.Errorf("invalid wildcard pattern %q", pattern)
		}
		return nil
	}
	if strings.Contains(pattern, "*") {
		return fmt.Errorf("wildcard must be at start: %q", pattern)
	}
	return nil
}
