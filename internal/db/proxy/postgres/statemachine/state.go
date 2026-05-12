//go:build linux

// Package statemachine implements the PostgreSQL proxy's Extended Query and
// transaction state machine per docs/agentsh-db-access-spec.md §14 and the
// design doc 2026-05-11-db-plan-05-pg-extended-tx-design.md §4.
//
// Transition is a pure function: it consumes (state, frame, cache, rules,
// service) and returns (nextState, []Action). It mutates the CacheView
// directly (for Put/Delete/Clear) so the Action stream is I/O-only.
package statemachine

import "time"

// Phase enumerates the per-connection lifecycle phases. The state machine
// tracks both Phase (for human-readable invariants) and LastUpstreamRFQ
// (the on-wire 'Z' status byte) because the two convey slightly different
// information — Phase encodes COPY-in/COPY-out which RFQ cannot represent.
type Phase uint8

const (
	PhasePreAuth Phase = iota
	PhaseIdle
	PhaseInQuery
	PhaseInTx
	PhaseInTxError
	PhaseInCopyIn
	PhaseInCopyOut
)

func (p Phase) String() string {
	switch p {
	case PhasePreAuth:
		return "pre_auth"
	case PhaseIdle:
		return "idle"
	case PhaseInQuery:
		return "in_query"
	case PhaseInTx:
		return "in_tx"
	case PhaseInTxError:
		return "in_tx_error"
	case PhaseInCopyIn:
		return "in_copy_in"
	case PhaseInCopyOut:
		return "in_copy_out"
	default:
		return "phase_unknown"
	}
}

// ConnState is the per-connection state the Extended Query and transaction
// state machine carries. All fields are exported so the dispatcher can read
// them after Transition returns; mutations happen only through Transition
// (or through the dispatcher updating LastUpstreamRFQ + Phase when an
// upstream 'Z' arrives during forwarding).
type ConnState struct {
	// Phase reflects the per-connection lifecycle position.
	Phase Phase

	// LastUpstreamRFQ is the most recent ReadyForQuery status byte observed
	// from upstream. Zero (0x00) means pre-auth. Otherwise 'I', 'T', or 'E'.
	LastUpstreamRFQ byte

	// Absorbing is true when a previous Parse/Bind/Execute denied within
	// the current Sync window. Subsequent non-Sync frames are suppressed
	// until the next Sync resolves the window.
	Absorbing bool

	// UpstreamDirtySinceSync is true once any Parse/Bind/Execute/Describe/
	// Close has been forwarded upstream in the current Sync window. Reset
	// on the next observed upstream RFQ.
	UpstreamDirtySinceSync bool

	// TxStartedAt is the local timestamp the proxy observed transitioning
	// into 'T' (in-tx) state on a fresh transaction. Cleared when the next
	// observed upstream RFQ is 'I'. Used by the DBEvent tx_context schema.
	TxStartedAt time.Time
}
