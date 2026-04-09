package secrets

import (
	"bytes"
	"testing"
	"time"
)

func TestSecretValue_Zero_OverwritesAndClears(t *testing.T) {
	sv := SecretValue{
		Value:     []byte("hunter2"),
		TTL:       5 * time.Minute,
		LeaseID:   "lease-123",
		Version:   "v4",
		FetchedAt: time.Now(),
	}

	// Capture the underlying array so we can verify it's zeroed
	// even after sv.Value is cleared.
	original := sv.Value
	sv.Zero()

	// Underlying bytes must be zeroed.
	if !bytes.Equal(original, []byte{0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Zero did not wipe underlying bytes: %v", original)
	}
	// Value slice must be nil.
	if sv.Value != nil {
		t.Errorf("Value slice not nil after Zero: %v", sv.Value)
	}
	// LeaseID and Version must be cleared.
	if sv.LeaseID != "" {
		t.Errorf("LeaseID not cleared: %q", sv.LeaseID)
	}
	if sv.Version != "" {
		t.Errorf("Version not cleared: %q", sv.Version)
	}
}

func TestSecretValue_Zero_Idempotent(t *testing.T) {
	sv := SecretValue{Value: []byte("abc")}
	sv.Zero()
	sv.Zero() // must not panic
	if sv.Value != nil {
		t.Errorf("second Zero modified Value: %v", sv.Value)
	}
}

func TestSecretValue_Zero_OnZeroValue(t *testing.T) {
	var sv SecretValue
	sv.Zero() // must not panic on zero-value SecretValue
}

// Compile-time check: ProviderConfig is a sealed interface. Any
// struct intended as a provider config must implement it by having
// a providerConfig() method. This test does not exercise runtime
// behavior — the compiler enforces it.
type testConfig struct{}

func (testConfig) providerConfig() {}

var _ ProviderConfig = testConfig{}
