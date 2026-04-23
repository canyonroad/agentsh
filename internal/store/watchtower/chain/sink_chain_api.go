package chain

import "github.com/agentsh/agentsh/internal/audit"

// SinkChainAPI is the test-substitutable surface that watchtower.Store
// consumes. Production callers wire *WatchtowerSink (which wraps
// *audit.SinkChain); tests substitute via Options.SinkChainOverrideForTests
// (gated behind Options.AllowSinkChainOverrideForTests so accidental
// production wiring is a startup error rather than a silent behavior
// change).
//
// Method signatures mirror the real audit.SinkChain contract exactly:
//   - Compute takes the positional (formatVersion, sequence, generation,
//     payload) args from audit.SinkChain.Compute.
//   - Commit returns error so AppendEvent can treat
//     audit.ErrFatalIntegrity, audit.ErrStaleResult, and
//     audit.ErrCrossChainResult as terminal.
//   - Fatal latches the chain into the fatal state on ambiguous WAL
//     failures so subsequent Compute calls return ErrFatalIntegrity.
//   - PeekPrevHash is the watchtower-only convenience accessor that
//     reads the prev_hash component of audit.SinkChainState. It is
//     implemented in the adapter, NOT on audit.SinkChain itself —
//     watchtower's drop-path tests need to assert "chain did not
//     advance" without poking at the full state triple.
//
// Any method the Store touches MUST appear here; silently downgrading
// the interface (e.g. dropping Commit's error return) would lose the
// integrity guarantees the chain is meant to provide.
type SinkChainAPI interface {
	Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*audit.ComputeResult, error)
	Commit(result *audit.ComputeResult) error
	Fatal(reason error)
	PeekPrevHash() string
}
