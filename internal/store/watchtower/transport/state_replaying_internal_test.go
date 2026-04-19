package transport

import (
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

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
// drive per-state handlers (RunReplaying, future RunLive) without going
// through runConnecting. Mirrors the field assignment runConnecting does
// on a successful dial.
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

