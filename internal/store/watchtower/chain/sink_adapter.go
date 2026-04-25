package chain

import "github.com/agentsh/agentsh/internal/audit"

// WatchtowerSink adapts *audit.SinkChain to the watchtower-local
// SinkChainAPI. The adapter is a pure pass-through for Compute, Commit,
// and Fatal (the audit phase-0 contract is untouched) and adds a single
// new accessor: PeekPrevHash, a read-only test seam that returns the
// prev_hash component of audit.SinkChain.State().
//
// This is the only added surface area on top of audit.SinkChain — the
// adapter lives in the watchtower package rather than the audit package
// so audit's API stays minimal for non-watchtower consumers.
type WatchtowerSink struct {
	inner *audit.SinkChain
}

// NewWatchtowerSink wraps inner so it satisfies SinkChainAPI. Callers
// keep ownership of inner; the adapter does not copy or mutate it
// outside Compute/Commit/Fatal (which are forwarded verbatim).
func NewWatchtowerSink(inner *audit.SinkChain) *WatchtowerSink {
	return &WatchtowerSink{inner: inner}
}

// Compute delegates to audit.SinkChain.Compute. Pure — no chain mutation.
func (s *WatchtowerSink) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*audit.ComputeResult, error) {
	return s.inner.Compute(formatVersion, sequence, generation, payload)
}

// Commit delegates to audit.SinkChain.Commit. The error return covers
// the latched-fatal cases (audit.ErrFatalIntegrity), stale tokens
// (audit.ErrStaleResult), cross-chain misuse (audit.ErrCrossChainResult),
// and backwards-generation commits — AppendEvent treats all of them as
// terminal.
func (s *WatchtowerSink) Commit(result *audit.ComputeResult) error {
	return s.inner.Commit(result)
}

// Fatal delegates to audit.SinkChain.Fatal. AppendEvent invokes this on
// ambiguous WAL failures: subsequent Compute calls return
// audit.ErrFatalIntegrity, stopping further appends safely.
func (s *WatchtowerSink) Fatal(reason error) {
	s.inner.Fatal(reason)
}

// PeekPrevHash returns the current chain prev_hash without advancing
// the chain. Used by Store.PeekPrevHash (test-only accessor) so
// drop-path tests can assert "chain did not advance" after a dropped
// append.
func (s *WatchtowerSink) PeekPrevHash() string {
	return s.inner.State().PrevHash
}

// State returns the chain's current (Generation, PrevHash, Fatal)
// snapshot. AppendEvent reads this to populate
// IntegrityRecord.PrevHash with the value Compute will internally
// use — matching the rollover rule where prev_hash resets to "" on
// a generation change. Direct pass-through to audit.SinkChain.State.
func (s *WatchtowerSink) State() audit.SinkChainState {
	return s.inner.State()
}
