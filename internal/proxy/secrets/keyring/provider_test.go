package keyring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	keyringlib "github.com/zalando/go-keyring"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/secretstest"
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

func TestClose_Idempotent(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Errorf("first Close error: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestFetch_AfterClose(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "x"}
	_, err := p.Fetch(context.Background(), ref)
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

func TestProvider_ConcurrentFetch_NoRaces(t *testing.T) {
	// This test skips on headless hosts. Without a reachable OS
	// keyring, each Fetch would block on the D-Bus timeout and
	// 800 sequential timeouts would take many minutes. On a host
	// with a keyring, each Get returns in milliseconds.
	p := skipIfUnavailable(t)
	// Use an intentionally absent key so Fetch always exercises
	// the "ErrNotFound" path. We care about the race detector,
	// not about the result.
	ref := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "nonexistent-user",
	}

	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 100
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = p.Fetch(context.Background(), ref)
			}
		}()
	}
	wg.Wait()
}

// TestProvider_CloseWaitsForInFlightFetch drives the
// Fetch-vs-Close contention path deterministically. The post-
// RLock test seam holds one Fetch inside the mutex's read
// critical section; a second goroutine then calls Close, which
// must block on the exclusive Lock until the in-flight Fetch
// releases its RLock.
//
// The test uses two test seams to get true determinism:
//
//   - testFetchPostRLockHook fires inside Fetch AFTER it has
//     acquired RLock, so we know exactly when a reader is in
//     the critical section.
//   - testClosePreLockHook fires inside Close AFTER the closed
//     flag store and BEFORE the exclusive Lock, so we know
//     exactly when Close is about to wait for that reader.
//
// With both signals in hand the test can assert without timing
// heuristics:
//
//  1. Wait for Fetch to enter the hook → reader is holding RLock.
//  2. Start Close goroutine.
//  3. Wait for Close hook → Close has stored closed=true and is
//     about to call Lock.
//  4. Assert closeDone is not yet closed (non-blocking select).
//     Close cannot have returned at this point because RWMutex
//     guarantees Lock waits for all existing RLockers to RUnlock.
//  5. Release the Fetch hook.
//  6. Assert closeDone closes (Close returned).
//  7. Assert post-Close Fetch reports wrapped ErrKeyringUnavailable.
//
// The release channel is closed through a t.Cleanup-registered
// idempotent helper so a t.Fatal mid-test never leaves the Fetch
// goroutine blocked in the hook (which would deadlock the
// skipIfUnavailable cleanup's own p.Close call).
func TestProvider_CloseWaitsForInFlightFetch(t *testing.T) {
	p := skipIfUnavailable(t)

	inFlight := make(chan struct{})
	release := make(chan struct{})
	var fetchHookOnce sync.Once
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	// Register release BEFORE the hook so a mid-test t.Fatal
	// unblocks the Fetch goroutine before skipIfUnavailable's
	// own cleanup tries to Close the provider.
	t.Cleanup(releaseHook)

	t.Cleanup(func() { testFetchPostRLockHook = nil })
	testFetchPostRLockHook = func() {
		fetchHookOnce.Do(func() {
			close(inFlight)
			<-release
		})
	}

	closeAtLock := make(chan struct{})
	t.Cleanup(func() { testClosePreLockHook = nil })
	testClosePreLockHook = func() { close(closeAtLock) }

	ref := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "nonexistent-user",
	}

	fetchDone := make(chan struct{})
	go func() {
		defer close(fetchDone)
		_, _ = p.Fetch(context.Background(), ref)
	}()

	// Wait until the Fetch goroutine is guaranteed to hold RLock.
	<-inFlight

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = p.Close()
	}()

	// Wait until the Close goroutine has stored closed=true and
	// is about to call Lock. After this point, Close cannot have
	// returned: RWMutex.Lock blocks until every existing RLocker
	// has RUnlocked, and the Fetch goroutine still holds RLock.
	<-closeAtLock

	// Non-blocking assertion that Close has not returned. This
	// is true by construction — RWMutex guarantees it — so no
	// timing heuristic is needed.
	select {
	case <-closeDone:
		t.Fatal("Close returned while an in-flight Fetch still held the read lock")
	default:
		// expected: Close is blocked on Lock
	}

	// Release the in-flight Fetch; it will finish and drop RLock,
	// which lets Close acquire the exclusive Lock.
	releaseHook()

	select {
	case <-closeDone:
		// expected
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the in-flight Fetch was released")
	}
	<-fetchDone

	// After Close returns, any subsequent Fetch must report the
	// closed sentinel. This goes through the fast path and never
	// reaches testFetchPostRLockHook, so it does not re-trigger
	// the fetchHookOnce gate.
	_, err := p.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrKeyringUnavailable) {
		t.Errorf("post-Close Fetch = %v, want wrapping ErrKeyringUnavailable", err)
	}
}

func TestProviderContract_AppliedToKeyringProvider(t *testing.T) {
	p := skipIfUnavailable(t)

	// Use a per-run unique service name to avoid collisions with
	// real keyring entries.
	probeRef := secrets.SecretRef{
		Scheme: "keyring",
		Host:   testServiceName(t),
		Path:   "contract-probe-unset",
	}

	// skipIfUnavailable already registered a Cleanup to Close p.
	// ProviderContract also Closes p inside its own Cleanup.
	// Close is idempotent, so both cleanups run safely.
	secretstest.ProviderContract(t, "keyring", p, probeRef)
}
