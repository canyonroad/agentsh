package session

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
)

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
