package secretstest

import (
	"context"
	"errors"
	"sync"
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestNewMemoryProvider_CopiesSeed(t *testing.T) {
	seed := map[string][]byte{
		"keyring://agentsh/token": []byte("original"),
	}
	mp := NewMemoryProvider("test", seed)

	// Mutate the caller's seed map after construction.
	seed["keyring://agentsh/token"] = []byte("mutated")

	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "token",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "original" {
		t.Errorf("Fetch returned %q, want %q (seed was copied at construction)", sv.Value, "original")
	}
}

func TestFetch_HappyPath(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/token": []byte("foo"),
	})
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "token"}
	sv, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "foo" {
		t.Errorf("Value = %q, want %q", sv.Value, "foo")
	}
	if sv.FetchedAt.IsZero() {
		t.Error("FetchedAt not set")
	}
}

func TestFetch_NotFound(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "missing"}
	_, err := mp.Fetch(context.Background(), ref)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch of missing = %v, want wrapping ErrNotFound", err)
	}
}

func TestFetch_ReturnsCopy(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/token": []byte("immutable"),
	})
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "token"}

	sv1, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	// Mutate the returned value.
	sv1.Value[0] = 'X'

	sv2, err := mp.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if string(sv2.Value) != "immutable" {
		t.Errorf("second Fetch = %q, want %q (first Fetch's mutation should not persist)", sv2.Value, "immutable")
	}
}

func TestFetch_AfterClose(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "a", Path: "b",
	})
	if err == nil {
		t.Fatal("Fetch after Close returned nil error")
	}
}

// TestFetch_MalformedRef verifies that a hand-built SecretRef the
// real providers would reject up front (empty host, unsupported
// scheme) surfaces a URI error from the fake rather than silently
// falling through as ErrNotFound. Without this, a test using the
// fake could pass while the same code would fail against a real
// provider.
func TestFetch_MalformedRef_MissingHost(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "", Path: "token",
	})
	if !errors.Is(err, secrets.ErrInvalidURI) {
		t.Errorf("Fetch missing host = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestFetch_MalformedRef_UnsupportedScheme(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "bogus", Host: "agentsh", Path: "token",
	})
	if !errors.Is(err, secrets.ErrUnsupportedScheme) {
		t.Errorf("Fetch bogus scheme = %v, want wrapping ErrUnsupportedScheme", err)
	}
}

func TestAdd_ThenFetch(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Add("keyring://agentsh/added", []byte("value")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "added",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "value" {
		t.Errorf("Value = %q, want %q", sv.Value, "value")
	}
}

func TestAdd_InvalidURI(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	err := mp.Add("not a valid uri", []byte("x"))
	if !errors.Is(err, secrets.ErrInvalidURI) && !errors.Is(err, secrets.ErrUnsupportedScheme) {
		t.Errorf("Add invalid URI = %v, want wrapping ErrInvalidURI or ErrUnsupportedScheme", err)
	}
}

func TestAdd_Replace(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	const uri = "keyring://agentsh/replaceable"
	if err := mp.Add(uri, []byte("first")); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := mp.Add(uri, []byte("second")); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	sv, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "replaceable",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(sv.Value) != "second" {
		t.Errorf("Value = %q, want %q", sv.Value, "second")
	}
}

func TestRemove(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/removeme": []byte("present"),
	})
	mp.Remove("keyring://agentsh/removeme")
	_, err := mp.Fetch(context.Background(), secrets.SecretRef{
		Scheme: "keyring", Host: "agentsh", Path: "removeme",
	})
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Fetch after Remove = %v, want wrapping ErrNotFound", err)
	}
}

func TestName(t *testing.T) {
	mp := NewMemoryProvider("my-fake", nil)
	if got := mp.Name(); got != "my-fake" {
		t.Errorf("Name() = %q, want %q", got, "my-fake")
	}
}

func TestClose_Idempotent(t *testing.T) {
	mp := NewMemoryProvider("test", nil)
	if err := mp.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := mp.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestConcurrentAccess_NoRaces(t *testing.T) {
	mp := NewMemoryProvider("test", map[string][]byte{
		"keyring://agentsh/seed": []byte("initial"),
	})

	var wg sync.WaitGroup
	const readers = 8
	const iterations = 200

	// Writer: continuously adds and removes its own URI.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = mp.Add("keyring://agentsh/writer", []byte("w"))
			mp.Remove("keyring://agentsh/writer")
		}
	}()

	// Readers: fetch the seeded URI.
	ref := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "seed"}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = mp.Fetch(context.Background(), ref)
			}
		}()
	}
	wg.Wait()
}

// Compile-time check: MemoryProvider implements SecretProvider.
var _ secrets.SecretProvider = (*MemoryProvider)(nil)
