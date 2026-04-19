package transport

import (
	"context"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// RunReplayingForTest is the external test seam for runReplaying. The
// production runReplaying is unexported (see state_replaying.go header)
// because it is missing the recv multiplexer the spec requires for
// stateReplaying (design.md:565); shipping it as an exported method
// would let production callers outside the transport package wire it
// into a run loop without realising it would silently drop inbound
// BatchAck/ServerHeartbeat/SessionUpdate/Goaway frames during long
// replays. Task 17 (Live state Batcher) and Task 18 (heartbeat) add
// the shared recv goroutine; Task 22 (Store integration) wires
// runReplaying through a RunOnce dispatch table that gates on those
// landing first. Until then, only tests reach runReplaying — via this
// helper, which lives in *_test.go and is compiled out of the
// production binary.
//
// Tests using this seam MUST also override buildEventBatchFn via
// SetBuildEventBatchFnForTest (the default stub returns an empty
// ClientMessage that would put invalid frames on the wire if a Send
// went through to a real server).
func (t *Transport) RunReplayingForTest(ctx context.Context, r *Replayer) (State, error) {
	return t.runReplaying(ctx, r)
}

// setBuildEventBatchFnForTest swaps the package-level buildEventBatchFn
// for the duration of a test so external (transport_test) tests can
// drive runReplaying with a non-stub builder. Returns a restore func the
// caller MUST defer to put the production stub back; without the
// restore, leaking a test override into another test would corrupt the
// global function variable.
//
// Internal-only seam: keeps the production var unexported so callers
// outside the transport package cannot mutate it without going through
// this guarded helper.
func setBuildEventBatchFnForTest(fn func([]wal.Record) (*wtpv1.ClientMessage, error)) func() {
	prev := buildEventBatchFn
	buildEventBatchFn = fn
	return func() { buildEventBatchFn = prev }
}

// SetBuildEventBatchFnForTest is the external test helper for
// setBuildEventBatchFnForTest. transport_test (external package) callers
// can invoke this to swap the stub for a deterministic builder; the
// returned restore func MUST be deferred to avoid leaking the override.
//
// Lives in *_test.go so the helper is compiled out of the production
// binary.
func SetBuildEventBatchFnForTest(fn func([]wal.Record) (*wtpv1.ClientMessage, error)) func() {
	return setBuildEventBatchFnForTest(fn)
}

// SetConnForTest attaches a Conn to the Transport so external tests can
// drive per-state handlers (RunReplayingForTest, future RunLive) without
// going through runConnecting. Mirrors the field assignment runConnecting
// does on a successful dial.
//
// Test-only seam: production code MUST go through runConnecting so the
// SessionInit/SessionAck handshake establishes the conn under the same
// invariants the live state machine relies on.
func SetConnForTest(t *Transport, c Conn) {
	t.conn = c
}

// HasConnForTest reports whether the Transport currently retains a Conn
// reference. External tests use this to assert the lifecycle invariant
// that error paths clear t.conn (so the next dial replaces it cleanly)
// and the happy path retains it (so the Live handler can reuse it).
func HasConnForTest(t *Transport) bool {
	return t.conn != nil
}

