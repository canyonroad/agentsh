package transport

import (
	"context"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport/compress"
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
// replays.
//
// The unexport is an EXTERNAL-CALL-SITE GUARD, not a compile-time
// guarantee: callers inside the transport package can still call
// runReplaying directly. Production wiring inside the package (Task 22's
// Run loop) MUST gate the call behind the recv-multiplexer plumbing
// Tasks 17/18 introduce. See the Task 22 Run-loop snippet in
// docs/superpowers/plans/2026-04-18-wtp-client.md "Task 16 — Deferred
// to Task 17/18" for the structural dependency. Until then, only tests
// reach runReplaying — via this helper, which lives in *_test.go and is
// compiled out of the production binary.
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
// The supplied fn receives only the WAL records; the emitExtended bool is
// ignored by test stubs that return a fixed ClientMessage regardless of
// reason gating. Production tests that need to verify reason-gating
// behavior should use the full store-level component tests
// (component_inflight_loss_test.go) instead of this low-level seam.
//
// Internal-only seam: keeps the production var unexported so callers
// outside the transport package cannot mutate it without going through
// this guarded helper.
func setBuildEventBatchFnForTest(fn func([]wal.Record) ([]*wtpv1.ClientMessage, error)) func() {
	wrapped := func(records []wal.Record, _ bool, _ compress.Encoder, _ compressMetrics) ([]*wtpv1.ClientMessage, error) {
		return fn(records)
	}
	prev := buildEventBatchFn
	buildEventBatchFn = wrapped
	return func() { buildEventBatchFn = prev }
}

// SetBuildEventBatchFnForTest is the external test helper for
// setBuildEventBatchFnForTest. transport_test (external package) callers
// can invoke this to swap the Replaying-state encoder for a deterministic
// builder; the returned restore func MUST be deferred to avoid leaking
// the override.
//
// Lives in *_test.go so the helper is compiled out of the production
// binary.
func SetBuildEventBatchFnForTest(fn func([]wal.Record) ([]*wtpv1.ClientMessage, error)) func() {
	return setBuildEventBatchFnForTest(fn)
}

// SetEncodeBatchMessageFnForTest swaps the Live-state's package-level
// encodeBatchMessageFn for the duration of a test. Tests that drive the
// Live state with raw (non-CompactEvent) WAL payloads use this to avoid
// proto.Unmarshal failures in the production encoder. Returns a restore
// func the caller MUST defer so the global var reverts after the test.
//
// The supplied fn receives only the WAL records; the emitExtended bool is
// discarded — test stubs that need to exercise reason-gating should use
// the store-level component tests instead.
//
// Internal-only seam mirroring SetBuildEventBatchFnForTest; both exist
// because the Live and Replaying states historically diverged on
// encoder plumbing and keeping two knobs is less invasive than
// unifying them in a test-driven refactor.
func SetEncodeBatchMessageFnForTest(fn func([]wal.Record) ([]*wtpv1.ClientMessage, error)) func() {
	wrapped := func(records []wal.Record, _ bool, _ compress.Encoder, _ compressMetrics) ([]*wtpv1.ClientMessage, error) {
		return fn(records)
	}
	prev := encodeBatchMessageFn
	encodeBatchMessageFn = wrapped
	return func() { encodeBatchMessageFn = prev }
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
