package keyring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
// Provider is safe for concurrent Fetch and Close. Close waits
// for any in-flight Fetch to finish before returning, so the
// contract "after Close returns, Fetch returns an error" holds
// even under concurrent access.
//
// Concurrency design:
//   - closed is an atomic flag checked lock-free on the Fetch
//     fast path. This preserves closed-provider error precedence
//     over context cancellation even while Close is queued behind
//     an in-flight Fetch on the RWMutex.
//   - mu is an RWMutex held for read by Fetch for its entire
//     duration (including the backend call) and for write by
//     Close. The write lock ensures Close waits for any in-flight
//     Fetch to finish before returning.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
}

// probeService and probeAccount name the sentinel entry the
// availability probe looks up. Operators will never see this in a
// real keyring — it exists only to verify that keyring.Get can
// reach the backend at all.
const (
	probeService = "agentsh-probe"
	probeAccount = "agentsh-keyring-availability-probe"
)

// testFetchPreLockHook is a test-only seam invoked (when non-nil)
// between Fetch's fast-path closed check and its RLock acquisition.
// Tests use it to deterministically simulate the Load()-to-RLock()
// race by closing the provider at that precise instant. It has no
// production callers and adds one nil check to the hot path.
var testFetchPreLockHook func()

// testFetchPostRLockHook is a test-only seam invoked (when non-nil)
// immediately after Fetch has acquired its RLock and re-verified
// closed. Tests use it to hold a Fetch in the mutex's read critical
// section so another goroutine can race Close against a
// guaranteed-in-flight reader. It has no production callers and
// adds one nil check to the hot path.
var testFetchPostRLockHook func()

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
// secrets.ErrKeyringUnavailable. Close waits for any in-flight
// Fetch to complete before returning, so a Fetch that began
// before Close can still succeed — what is guaranteed is that
// any Fetch attempted AFTER Close returns will see the closed
// flag and return the error.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	// Lock-free closed check first, so a closed provider always
	// reports ErrKeyringUnavailable regardless of the caller's
	// context state. This preserves the documented precedence:
	// closed beats canceled.
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("%w: provider closed", secrets.ErrKeyringUnavailable)
	}

	// Honor an already-canceled context before we try to acquire
	// the mutex. If Close is pending behind a slow keyringlib.Get,
	// waiters for RLock may queue behind the exclusive writer; a
	// canceled caller should fail fast rather than block on that.
	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Test seam: see testFetchPreLockHook. Nil in production.
	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Re-check closed AFTER acquiring RLock to close the
	// Load()-to-RLock() TOCTOU: a Fetch can see closed=false,
	// be preempted while Close stores true and runs to completion
	// (including releasing its exclusive Lock), and then resume
	// and acquire RLock cleanly. Without this re-check, Close
	// could return while a stalled Fetch later proceeds to call
	// the backend. The atomic load after RLock sees the Store,
	// so we reject the stale Fetch here instead.
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("%w: provider closed", secrets.ErrKeyringUnavailable)
	}

	// Test seam: see testFetchPostRLockHook. Nil in production.
	if hook := testFetchPostRLockHook; hook != nil {
		hook()
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

	// Re-check ctx in case cancellation happened while we were
	// waiting for RLock — don't start an uncancellable backend call
	// for a caller that has already given up.
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
//
// Close sets the atomic closed flag before acquiring the exclusive
// write lock. The flag makes new fast-path Fetch calls fail
// immediately; the write lock then blocks until every in-flight
// Fetch (holding an RLock) has finished, so the caller of Close
// sees a fully quiesced provider on return.
func (p *Provider) Close() error {
	p.closed.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	return nil
}
