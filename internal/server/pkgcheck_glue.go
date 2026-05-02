package server

import (
	"errors"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/agentsh/agentsh/internal/pkgcheck/provider"
	"github.com/agentsh/agentsh/internal/pkgcheck/resolver"
)

// errMissingAPIKeyValue is returned by requireAPIKey when the env var name is
// configured (api_key_env is set) but the variable is currently unset or empty.
// This is a "soft" error: the operator has wired the key name correctly but the
// key is absent from the environment, which is acceptable in CI / local dev
// scenarios where the provider is intentionally left key-less. The caller
// treats it as a skip-with-warning rather than a fatal startup failure.
var errMissingAPIKeyValue = errors.New("env var is unset or empty")

// buildProviderEntry constructs a pkgcheck.ProviderEntry from a single
// ProviderConfig. It returns an error if:
//   - the name is not a known built-in and provCfg.Type != "exec"
//   - the provider requires an API key but provCfg.APIKeyEnv is empty
//   - the provider requires an API key but the env var is unset
func buildProviderEntry(name string, provCfg config.ProviderConfig) (pkgcheck.ProviderEntry, error) {
	prov, err := buildProvider(name, provCfg)
	if err != nil {
		return pkgcheck.ProviderEntry{}, err
	}
	onFailure := provCfg.OnFailure
	if onFailure == "" {
		onFailure = "warn"
	}
	return pkgcheck.ProviderEntry{
		Provider:  prov,
		Timeout:   provCfg.Timeout,
		OnFailure: onFailure,
	}, nil
}

// buildProvider constructs the concrete CheckProvider for the given name.
func buildProvider(name string, provCfg config.ProviderConfig) (pkgcheck.CheckProvider, error) {
	// exec providers are identified by their Type field rather than name.
	if provCfg.Type == "exec" {
		if provCfg.Command == "" {
			return nil, fmt.Errorf("pkgcheck provider %q: type=exec requires a non-empty command", name)
		}
		return provider.NewExecProvider(name, provider.ExecProviderConfig{
			Command: provCfg.Command,
			Timeout: provCfg.Timeout,
			Config:  provCfg.Options,
		}), nil
	}

	switch name {
	case "osv":
		return provider.NewOSVProvider(provider.OSVConfig{
			BaseURL: optString(provCfg.Options, "base_url"),
			Timeout: provCfg.Timeout,
		}), nil

	case "depsdev":
		return provider.NewDepsDevProvider(provider.DepsDevConfig{
			BaseURL: optString(provCfg.Options, "base_url"),
			Timeout: provCfg.Timeout,
		}), nil

	case "local":
		return provider.NewLocalProvider(), nil

	case "snyk":
		apiKey, err := requireAPIKey(name, provCfg.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		orgID := optString(provCfg.Options, "org_id")
		if orgID == "" {
			return nil, fmt.Errorf("pkgcheck provider %q: options.org_id is required", name)
		}
		concurrency := optInt(provCfg.Options, "concurrency", 16)
		return provider.NewSnykProvider(provider.SnykConfig{
			BaseURL:     optString(provCfg.Options, "base_url"),
			APIKey:      apiKey,
			OrgID:       orgID,
			Timeout:     provCfg.Timeout,
			Concurrency: concurrency,
		}), nil

	case "socket":
		apiKey, err := requireAPIKey(name, provCfg.APIKeyEnv)
		if err != nil {
			return nil, err
		}
		return provider.NewSocketProvider(provider.SocketConfig{
			BaseURL: optString(provCfg.Options, "base_url"),
			APIKey:  apiKey,
			Timeout: provCfg.Timeout,
		}), nil

	default:
		return nil, fmt.Errorf("pkgcheck provider %q: unknown provider name (known: osv, depsdev, local, snyk, socket, exec)", name)
	}
}

// requireAPIKey validates that an API key env var is configured and set.
// It returns errMissingAPIKeyValue (a sentinel) when the env var name is
// configured but the variable is currently empty — callers can test for that
// specific error to decide whether to skip (soft) or fail hard.
func requireAPIKey(providerName, apiKeyEnv string) (string, error) {
	if apiKeyEnv == "" {
		return "", fmt.Errorf("pkgcheck provider %q: api_key_env is required", providerName)
	}
	val := os.Getenv(apiKeyEnv)
	if val == "" {
		return "", fmt.Errorf("pkgcheck provider %q: %w: %s", providerName, errMissingAPIKeyValue, apiKeyEnv)
	}
	return val, nil
}

// optString retrieves a string value from an options map, returning "" if absent.
func optString(opts map[string]any, key string) string {
	if opts == nil {
		return ""
	}
	v, ok := opts[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// optInt retrieves an int value from an options map, returning defaultVal if absent or wrong type.
func optInt(opts map[string]any, key string, defaultVal int) int {
	if opts == nil {
		return defaultVal
	}
	v, ok := opts[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return defaultVal
}

// defaultResolverNames is the ordered list of verified built-in resolver names.
// pnpm, yarn, and poetry are excluded from defaults because their parsers
// have not been verified against real CLI output (parsers are placeholder JSON
// formats that do not match actual tool output). Enable them explicitly via
// package_checks.resolvers.pnpm: {}, .yarn: {}, or .poetry: {}.
var defaultResolverNames = []string{"npm", "pip", "uv"}

// buildResolvers constructs pkgcheck.Resolver instances from the resolved
// configuration map. If cfgMap is nil or empty, only verified resolvers
// (npm, pip, uv) are returned with their internal defaults. Unknown resolver
// names are fatal.
func buildResolvers(cfgMap map[string]config.ResolverConfig) ([]pkgcheck.Resolver, error) {
	if len(cfgMap) == 0 {
		// Default: verified resolvers only with zero-value config (each uses its
		// own internal defaults for DryRunCommand and Timeout). pnpm, yarn, and
		// poetry are omitted because their output parsers are placeholders.
		return []pkgcheck.Resolver{
			resolver.NewNPMResolver(resolver.NPMResolverConfig{}),
			resolver.NewPipResolver(resolver.PipResolverConfig{}),
			resolver.NewUVResolver(resolver.UVResolverConfig{}),
		}, nil
	}

	out := make([]pkgcheck.Resolver, 0, len(cfgMap))
	for name, rc := range cfgMap {
		r, err := buildResolver(name, rc)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// buildResolver constructs a single resolver by name.
func buildResolver(name string, rc config.ResolverConfig) (pkgcheck.Resolver, error) {
	switch name {
	case "npm":
		return resolver.NewNPMResolver(resolver.NPMResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	case "pnpm":
		return resolver.NewPNPMResolver(resolver.PNPMResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	case "yarn":
		return resolver.NewYarnResolver(resolver.YarnResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	case "pip":
		return resolver.NewPipResolver(resolver.PipResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	case "uv":
		return resolver.NewUVResolver(resolver.UVResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	case "poetry":
		return resolver.NewPoetryResolver(resolver.PoetryResolverConfig{
			DryRunCommand: rc.DryRunCommand,
			Timeout:       rc.Timeout,
		}), nil
	default:
		return nil, fmt.Errorf("pkgcheck resolver %q: unknown resolver name (known: npm, pnpm, yarn, pip, uv, poetry)", name)
	}
}
