package store

import (
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
)

func TestIntegrityStore_Wrap(t *testing.T) {
	key := []byte("test-key-32-bytes-for-hmac-sha!!")
	chain, err := audit.NewIntegrityChain(key)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	// Test that chain state advances
	state1 := chain.State()
	if state1.Sequence != 0 {
		t.Errorf("initial sequence should be 0, got %d", state1.Sequence)
	}

	_, err = chain.Wrap([]byte(`{"test": true}`))
	if err != nil {
		t.Fatalf("failed to wrap: %v", err)
	}

	state2 := chain.State()
	if state2.Sequence != 1 {
		t.Errorf("sequence should be 1, got %d", state2.Sequence)
	}
	if state1.PrevHash == state2.PrevHash {
		t.Error("hash should have changed")
	}
}

func TestNewIntegrityStore(t *testing.T) {
	key := []byte("test-key-32-bytes-for-hmac-sha!!")
	chain, err := audit.NewIntegrityChain(key)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	// Create wrapper with nil inner store (just testing construction)
	wrapper := NewIntegrityStore(nil, chain)
	if wrapper == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if wrapper.Chain() != chain {
		t.Error("Chain() should return the same chain")
	}
}
