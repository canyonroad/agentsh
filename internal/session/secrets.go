package session

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
)

// envVarKey returns the map key for duplicate env-var detection.
// On Windows, environment variable names are case-insensitive,
// so we fold to upper-case. On POSIX systems, names are
// case-sensitive and used as-is.
func envVarKey(name string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

// ServiceConfig describes one secret-backed service for credential
// substitution. Plan 5 uses this struct directly; future plans will
// parse it from YAML policy files.
type ServiceConfig struct {
	Name      string            // logical service name (e.g. "github")
	SecretRef secrets.SecretRef  // where to fetch the real credential
	FakeFormat string           // fake template (e.g. "ghp_{rand:36}")
}

// SecretFetcher is the subset of secrets.SecretProvider that
// BootstrapCredentials needs. Both *secrets.Registry and individual
// providers satisfy this interface.
type SecretFetcher interface {
	Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error)
}

// BootstrapCredentials fetches secrets, generates fakes, and populates
// a credsub.Table. Returns the table and a cleanup function that zeros
// the table.
//
// If any fetch or fake generation fails, all already-fetched secrets
// are zeroed before returning the error. The agent never starts with
// a partially populated table.
func BootstrapCredentials(
	ctx context.Context,
	fetcher SecretFetcher,
	services []ServiceConfig,
) (*credsub.Table, func(), error) {
	table := credsub.New()

	for _, svc := range services {
		sv, err := fetcher.Fetch(ctx, svc.SecretRef)
		if err != nil {
			table.Zero()
			return nil, nil, fmt.Errorf("fetch secret for %q: %w", svc.Name, err)
		}

		fake, err := secrets.GenerateFake(svc.FakeFormat, len(sv.Value))
		if err != nil {
			sv.Zero()
			table.Zero()
			return nil, nil, fmt.Errorf("generate fake for %q: %w", svc.Name, err)
		}

		if addErr := table.Add(svc.Name, fake, sv.Value); addErr != nil {
			// Collision — retry once.
			fake2, err2 := secrets.GenerateFake(svc.FakeFormat, len(sv.Value))
			if err2 != nil {
				sv.Zero()
				table.Zero()
				return nil, nil, fmt.Errorf("regenerate fake for %q: %w", svc.Name, err2)
			}
			if addErr2 := table.Add(svc.Name, fake2, sv.Value); addErr2 != nil {
				sv.Zero()
				table.Zero()
				return nil, nil, fmt.Errorf("add entry for %q after retry: %w", svc.Name, addErr2)
			}
		}

		// Wipe fetched secret from memory — table has its own copy.
		sv.Zero()
	}

	cleanup := func() {
		table.Zero()
	}

	return table, cleanup, nil
}

// LogSecretsInitialized emits the secrets_initialized audit event.
func LogSecretsInitialized(logger *slog.Logger, sessionID string, serviceCount int) {
	logger.Info("secrets_initialized",
		"session_id", sessionID,
		"service_count", serviceCount,
	)
}

// BuildServiceEnvVars builds a map of env var name -> fake credential
// for services that declare inject.env. Looks up each service's fake
// from the table; services not found in the table are silently skipped.
// Returns an error if two different services declare the same env var name.
func BuildServiceEnvVars(envVars []ServiceEnvVar, table *credsub.Table) (map[string]string, error) {
	if len(envVars) == 0 {
		return nil, nil
	}

	// Validate names and detect duplicates first (no table access needed).
	owner := make(map[string]string, len(envVars))
	for _, ev := range envVars {
		if ev.VarName == "" || strings.ContainsAny(ev.VarName, "=\x00") {
			return nil, fmt.Errorf("invalid service env var name %q for service %q", ev.VarName, ev.ServiceName)
		}
		key := envVarKey(ev.VarName)
		if prev, dup := owner[key]; dup {
			return nil, fmt.Errorf("duplicate service env var %q (services %q and %q)", ev.VarName, prev, ev.ServiceName)
		}
		owner[key] = ev.ServiceName
	}

	if table == nil {
		return nil, nil
	}

	// Build the env var map from table lookups.
	result := make(map[string]string, len(envVars))
	for _, ev := range envVars {
		fake, ok := table.FakeForService(ev.ServiceName)
		if !ok {
			continue
		}
		result[ev.VarName] = string(fake)
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}
