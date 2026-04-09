package keyring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	keyringlib "github.com/zalando/go-keyring"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is an OS-keyring-backed secrets.SecretProvider.
//
// On macOS this shells out to /usr/bin/security. On Linux it
// uses the Secret Service D-Bus API. On Windows it uses the
// Credential Manager syscalls. All three backends are pure Go —
// no cgo linkage.
//
// Provider is safe for concurrent Fetch and Close.
type Provider struct {
	mu     sync.Mutex
	closed bool
}

// probeService and probeAccount name the sentinel entry the
// availability probe looks up. Operators will never see this in a
// real keyring — it exists only to verify that keyring.Get can
// reach the backend at all.
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

// Fetch retrieves a secret from the OS keyring.
//
// The SecretRef must have:
//   - Scheme == "keyring"
//   - Host    (the OS keyring service name)
//   - Path    (the OS keyring account name)
//   - Field   empty (keyring entries are scalar)
//
// Wrong-scheme, missing-host, and missing-path each return a
// wrapped secrets.ErrInvalidURI. A non-empty Field returns a
// wrapped secrets.ErrFieldNotSupported. A missing entry returns
// a wrapped secrets.ErrNotFound. Any other library error is
// treated as a transport failure and wrapped verbatim.
//
// Fetch honors ctx only as a pre-call check. The zalando library
// does not accept a context, and spawning a goroutine to race the
// call against ctx would leak on cancel.
//
// A Fetch on a closed Provider returns a wrapped
// secrets.ErrKeyringUnavailable.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return secrets.SecretValue{}, fmt.Errorf("%w: provider closed", secrets.ErrKeyringUnavailable)
	}

	if ref.Scheme != "keyring" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: keyring URI missing service (host)", secrets.ErrInvalidURI)
	}
	if ref.Path == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: keyring URI missing user (path)", secrets.ErrInvalidURI)
	}
	if ref.Field != "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: keyring entries are scalar", secrets.ErrFieldNotSupported)
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	val, err := keyringlib.Get(ref.Host, ref.Path)
	if err != nil {
		if errors.Is(err, keyringlib.ErrNotFound) {
			return secrets.SecretValue{}, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref.String())
		}
		// We cannot distinguish "auth rejected" from "backend
		// disappeared mid-session" from the zalando API, so we
		// do not synthesize ErrUnauthorized here. Wrap the raw
		// error so callers can see the original cause.
		return secrets.SecretValue{}, fmt.Errorf("keyring fetch %s: %w", ref.String(), err)
	}

	return secrets.SecretValue{
		Value:     []byte(val),
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider closed. Subsequent Fetch calls return a
// wrapped secrets.ErrKeyringUnavailable. Idempotent. The OS keyring
// has no per-connection state to release.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
