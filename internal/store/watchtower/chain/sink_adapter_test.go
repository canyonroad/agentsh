package chain_test

import (
	"bytes"
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
)

func testKey() []byte { return bytes.Repeat([]byte("a"), 32) }

func TestWatchtowerSink_PeekPrevHashEmptyAtGenesis(t *testing.T) {
	inner, err := audit.NewSinkChain(testKey(), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	s := chain.NewWatchtowerSink(inner)
	if got := s.PeekPrevHash(); got != "" {
		t.Errorf("genesis PeekPrevHash should be empty, got %q", got)
	}
}

func TestWatchtowerSink_ComputeCommitAdvancesPrevHash(t *testing.T) {
	inner, err := audit.NewSinkChain(testKey(), "hmac-sha256")
	if err != nil {
		t.Fatalf("audit.NewSinkChain: %v", err)
	}
	s := chain.NewWatchtowerSink(inner)
	res, err := s.Compute(2, 1, 1, []byte(`{"sequence":1}`))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if err := s.Commit(res); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := s.PeekPrevHash(); got == "" {
		t.Error("PeekPrevHash should be non-empty after a successful Commit")
	}
	if got := s.PeekPrevHash(); got != res.EntryHash() {
		t.Errorf("PeekPrevHash should equal the committed EntryHash; got %q want %q", got, res.EntryHash())
	}
}
