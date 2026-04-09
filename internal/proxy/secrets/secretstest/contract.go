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
// The URI used to exercise Fetch (a well-known "never-exists"
// keyring URI) is chosen to be valid per ParseRef but extremely
// unlikely to hit any real secret: `keyring://agentsh-contract-probe/unset`.
// A real keyring provider that happened to have this entry set
// would fail the NotFound assertion — which is acceptable because
// the service name is obviously test-only. The keyring provider's
// test suite avoids this by scoping tests to a per-run unique
// service name.
func ProviderContract(t *testing.T, name string, p secrets.SecretProvider) {
	t.Helper()

	t.Cleanup(func() { _ = p.Close() })

	t.Run(name+"/Name", func(t *testing.T) {
		if got := p.Name(); got == "" {
			t.Error("Name() returned empty string")
		}
	})

	t.Run(name+"/FetchNotFound", func(t *testing.T) {
		ref := secrets.SecretRef{
			Scheme: "keyring",
			Host:   "agentsh-contract-probe",
			Path:   "unset",
		}
		_, err := p.Fetch(context.Background(), ref)
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
		ref := secrets.SecretRef{
			Scheme: "keyring",
			Host:   "agentsh-contract-probe",
			Path:   "unset",
		}
		_, err := p.Fetch(context.Background(), ref)
		if err == nil {
			t.Fatal("Fetch after Close returned nil error")
		}
	})
}
