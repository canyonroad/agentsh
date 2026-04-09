package keyring

import (
	"context"
	"errors"
	"testing"

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

func TestFetch_StubReturnsWrappedSentinel(t *testing.T) {
	p := &Provider{}
	_, err := p.Fetch(context.Background(), secrets.SecretRef{})
	if err == nil {
		t.Fatal("Fetch stub returned nil error; expected a sentinel-wrapped error")
	}
	if !errors.Is(err, secrets.ErrKeyringUnavailable) {
		t.Errorf("Fetch stub error not wrappable to ErrKeyringUnavailable: %v", err)
	}
}
