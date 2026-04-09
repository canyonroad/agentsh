package keyring

import (
	"context"
	"errors"
	"fmt"
	"sync"

	keyringlib "github.com/zalando/go-keyring"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is an OS-keyring-backed secrets.SecretProvider.
//
// On macOS this uses the system Keychain (via cgo against the
// Security framework). On Linux it uses the Secret Service D-Bus
// API. On Windows it uses Credential Manager.
//
// Provider is safe for concurrent Fetch and Close.
type Provider struct {
	mu     sync.Mutex
	closed bool
}

// probeService is the keyring service name used by New's
// availability probe. Operators will never see this in a real
// keyring — it exists only to verify that keyring.Get can reach
// the backend at all.
const (
	probeService = "agentsh-probe"
	probeAccount = "agentsh-keyring-availability-probe"
)

// New constructs a keyring Provider.
//
// New verifies the OS keyring backend is reachable by issuing one
// probe Get. A probe that returns nil or keyringlib.ErrNotFound
// counts as success (the backend is reachable, the probe key just
// doesn't exist). Any other error means the backend itself is
// unreachable, and New returns a wrapped secrets.ErrKeyringUnavailable.
func New(_ Config) (*Provider, error) {
	_, err := keyringlib.Get(probeService, probeAccount)
	if err != nil && !errors.Is(err, keyringlib.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyringUnavailable, err)
	}
	return &Provider{}, nil
}

// Name returns "keyring". Used in audit events.
func (p *Provider) Name() string { return "keyring" }

// Close marks the provider closed. Subsequent Fetch calls return a
// non-nil error. Idempotent. The OS keyring has no per-connection
// state to release.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// Fetch is the stub implementation — Task 6 replaces the body with
// the real validation and round-trip logic. The signature matches
// secrets.SecretProvider so the compile-time assertion in
// config.go (var _ secrets.SecretProvider = (*Provider)(nil))
// passes from this task onward.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	return secrets.SecretValue{}, errors.New("keyring: Fetch not yet implemented")
}
