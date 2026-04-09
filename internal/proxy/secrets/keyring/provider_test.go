package keyring

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	keyringlib "github.com/zalando/go-keyring"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// skipIfUnavailable constructs a Provider and skips the test if
// the OS keyring backend is unreachable on this host. Used by
// every test that touches the real keyring.
func skipIfUnavailable(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{})
	if err != nil {
		if errors.Is(err, secrets.ErrKeyringUnavailable) {
			t.Skip("OS keyring not available on this host: " + err.Error())
		}
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestNew_HappyPath(t *testing.T) {
	p := skipIfUnavailable(t)
	if p == nil {
		t.Fatal("New returned nil Provider")
	}
}

func TestName_ReturnsKeyring(t *testing.T) {
	// Name is pure and does not touch the OS keyring. Construct
	// a zero-value Provider directly so this test is NOT skipped
	// on headless hosts.
	p := &Provider{}
	if got := p.Name(); got != "keyring" {
		t.Errorf("Name() = %q, want %q", got, "keyring")
	}
}

func TestFetch_WrongScheme(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "vault", Host: "kv", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch with wrong scheme returned nil error")
	}
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch wrong scheme = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MissingHost(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch with empty host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MissingPath(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: ""}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch with empty path = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_WithField(t *testing.T) {
	p := &Provider{}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x", Field: "token"}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrFieldNotSupported) {
		t.Errorf("Fetch with field = %v, want wrapping ErrFieldNotSupported", err)
	}
}

func TestFetch_ContextCanceled(t *testing.T) {
	p := &Provider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Fetch
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(ctx, ref)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fetch with canceled ctx = %v, want context.Canceled", err)
	}
}

// testServiceName returns a unique keyring service name per test
// run. Using a unique name per run prevents any one test from
// polluting a developer's real keyring or leaking entries between
// runs. The "agentsh-test" prefix makes the intent obvious if an
// entry does survive a crash.
func testServiceName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("agentsh-test-%s-%d", t.Name(), time.Now().UnixNano())
}

func TestFetch_RoundTrip(t *testing.T) {
	p := skipIfUnavailable(t)

	service := testServiceName(t)
	const account = "round-trip-user"
	const want = "super-secret-value"

	if err := keyringlib.Set(service, account, want); err != nil {
		t.Fatalf("keyringlib.Set: %v", err)
	}
	t.Cleanup(func() { _ = keyringlib.Delete(service, account) })

	ref := secrets.SecretRef{Scheme: "keyring", Host: service, Path: account}
	sv, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch(%+v) error: %v", ref, err)
	}
	if string(sv.Value) != want {
		t.Errorf("Fetch returned Value %q, want %q", sv.Value, want)
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set by Fetch")
	}
	// Caller owns the buffer — test ownership by mutating and
	// re-fetching. The second Fetch must return the original
	// bytes, not the mutation.
	sv.Value[0] = 'X'
	sv2, err := p.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Fetch error: %v", err)
	}
	if string(sv2.Value) != want {
		t.Errorf("mutating returned buffer affected provider state: got %q, want %q", sv2.Value, want)
	}
}

func TestFetch_NotFound(t *testing.T) {
	p := skipIfUnavailable(t)

	ref := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "definitely-does-not-exist",
	}
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch of missing key = %v, want wrapping ErrNotFound", err)
	}
}

// TestFetch_AfterCloseReturnsError is the regression test for
// the close-vs-fetch race. It does NOT attempt to prove timing
// of an in-flight race — that would be flaky and platform-
// dependent. Instead it verifies the stable behavioral contract:
// after Close returns, any subsequent Fetch returns a wrapped
// ErrKeyringUnavailable. RWMutex guarantees the invariant
// regardless of goroutine scheduling.
func TestFetch_AfterCloseReturnsError(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
	if !errors.Is(err, secrets.ErrKeyringUnavailable) {
		t.Errorf("Fetch after Close = %v, want wrapping ErrKeyringUnavailable", err)
	}
}

// TestFetch_ClosedBetweenLoadAndRLock is the deterministic
// regression test for the Load()-to-RLock() TOCTOU race. Fetch's
// fast-path closed check happens before RLock, so a Fetch could
// see closed=false, be preempted while Close ran to completion
// (store=true, exclusive Lock/Unlock, return), then resume and
// acquire RLock cleanly. Without the post-RLock re-check, that
// stalled Fetch would proceed to the backend while Close had
// already returned.
//
// This test drives the race window directly with testFetchPreLockHook:
// between the fast-path Load and RLock, the hook calls Close,
// which runs to completion because no reader holds the mutex.
// Fetch then proceeds, acquires RLock, and must see closed=true
// in the re-check and fail with ErrKeyringUnavailable.
func TestFetch_ClosedBetweenLoadAndRLock(t *testing.T) {
	p := &Provider{}

	hookRan := false
	t.Cleanup(func() { testFetchPreLockHook = nil })
	testFetchPreLockHook = func() {
		hookRan = true
		if err := p.Close(); err != nil {
			t.Errorf("hook Close: %v", err)
		}
	}

	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)

	if !hookRan {
		t.Fatal("testFetchPreLockHook never fired")
	}
	if err == nil {
		t.Fatal("Fetch succeeded despite Close between Load and RLock")
	}
	if !errors.Is(err, secrets.ErrKeyringUnavailable) {
		t.Errorf("Fetch = %v, want wrapping ErrKeyringUnavailable", err)
	}
}
