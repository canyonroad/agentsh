package secretstest

import (
	"context"
	"errors"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// ProviderContract runs a baseline set of behavioral assertions
// against any SecretProvider. Every provider implementation should
// call ProviderContract from its own test file to verify it honors
// the interface contract.
//
// The helper takes a freshly constructed provider and takes
// ownership of it: it calls Close on the provider via t.Cleanup.
// Callers must not call Close themselves after passing the
// provider to ProviderContract.
//
// probeRef must be a valid SecretRef whose scheme the provider
// accepts and that is guaranteed NOT to exist in the backend.
// Each provider test supplies its own probe ref so the contract
// helper is scheme-agnostic and avoids collisions with real
// secrets. For example, the keyring tests pass a per-run unique
// service name via testServiceName(t).
func ProviderContract(t *testing.T, name string, p secrets.SecretProvider, probeRef secrets.SecretRef) {
	t.Helper()

	t.Cleanup(func() { _ = p.Close() })

	t.Run(name+"/Name", func(t *testing.T) {
		if got := p.Name(); got == "" {
			t.Error("Name() returned empty string")
		}
	})

	t.Run(name+"/FetchNotFound", func(t *testing.T) {
		_, err := p.Fetch(context.Background(), probeRef)
		if err == nil {
			t.Fatal("Fetch of unset ref returned nil error")
		}
		if !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("Fetch of unset ref = %v, want wrapping secrets.ErrNotFound", err)
		}
	})

	t.Run(name+"/CloseIdempotent", func(t *testing.T) {
		if err := p.Close(); err != nil {
			t.Errorf("first Close: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	})

	t.Run(name+"/FetchAfterClose", func(t *testing.T) {
		// Close was called above; provider should be in a closed
		// state here because t.Run subtests run sequentially.
		_, err := p.Fetch(context.Background(), probeRef)
		if err == nil {
			t.Fatal("Fetch after Close returned nil error")
		}
	})
}
