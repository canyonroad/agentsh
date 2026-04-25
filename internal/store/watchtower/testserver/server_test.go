package testserver_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// sendSessionInit fires a minimal SessionInit on conn. Fails the test
// on Send error (the bufconn transport should never fail Send under
// the scenarios we exercise here).
func sendSessionInit(t *testing.T, conn testserver.Conn) {
	t.Helper()
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId:   "test",
				SessionId: "s1",
				Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256,
			},
		},
	}); err != nil {
		t.Fatalf("send SessionInit: %v", err)
	}
}

// sendEmptyBatch fires a minimal but valid EventBatch (Compression=NONE
// with an empty Uncompressed body) on conn. The drop/goaway scenarios
// trigger on frame COUNT, not content, so an empty batch is sufficient
// to advance the per-stream counter. The batch MUST pass
// wtpv1.ValidateEventBatch — the testserver's receiver-side validation
// is unconditional (spec compliance is not gated on observability),
// so a bare &EventBatch{} would be rejected with
// event_batch_compression_unspecified.
func sendEmptyBatch(t *testing.T, conn testserver.Conn) {
	t.Helper()
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_NONE,
				Body:        &wtpv1.EventBatch_Uncompressed{Uncompressed: &wtpv1.UncompressedEvents{}},
			},
		},
	}); err != nil {
		t.Fatalf("send EventBatch: %v", err)
	}
}

// recvWithDeadline reads from conn with a bounded wait; fails the
// test if nothing arrives in time. Kept as a helper because every
// scenario test needs the same timeout discipline.
func recvWithDeadline(t *testing.T, conn testserver.Conn, d time.Duration) (*wtpv1.ServerMessage, error) {
	t.Helper()
	type result struct {
		msg *wtpv1.ServerMessage
		err error
	}
	ch := make(chan result, 1)
	go func() {
		m, err := conn.Recv()
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-time.After(d):
		t.Fatalf("recv timed out after %v", d)
		return nil, nil
	}
}

func dialOrFatal(t *testing.T, srv *testserver.Server) testserver.Conn {
	t.Helper()
	// Background ctx — this ctx becomes the stream's lifetime ctx
	// inside Dial (grpc.DialContext + Stream share it). A test-
	// scoped deadline here would cancel the stream the moment this
	// helper returns, which defeats the test. bufconn dials are
	// effectively instantaneous so no deadline is needed.
	conn, err := srv.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// TestServer_AcksSessionInit verifies the default scenario: server
// replies to SessionInit with SessionAck at watermark (0, 0, accepted).
func TestServer_AcksSessionInit(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ack := got.GetSessionAck()
	if ack == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if !ack.GetAccepted() {
		t.Fatalf("SessionAck.Accepted=false")
	}
	if ack.GetAckHighWatermarkSeq() != 0 || ack.GetGeneration() != 0 {
		t.Fatalf("SessionAck tuple=(%d, %d), want (0, 0)",
			ack.GetAckHighWatermarkSeq(), ack.GetGeneration())
	}
}

// TestServer_RejectSession verifies that RejectSession produces a
// SessionAck with Accepted=false and the configured RejectReason.
// This exercises the terminal-error path used by Transport tests.
func TestServer_RejectSession(t *testing.T) {
	srv := testserver.New(testserver.Options{
		RejectSession: true,
		RejectReason:  "permission denied",
	})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ack := got.GetSessionAck()
	if ack == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if ack.GetAccepted() {
		t.Fatalf("SessionAck.Accepted=true; want false")
	}
	if ack.GetRejectReason() != "permission denied" {
		t.Fatalf("RejectReason=%q, want %q", ack.GetRejectReason(), "permission denied")
	}
}

// TestServer_SessionAckSeqAndGenerationLiteral verifies that
// SessionAckSeq and SessionAckGeneration are sent as literal values on
// the SessionAck. Zero is zero — the server does not mirror the
// client's SessionInit watermark.
func TestServer_SessionAckSeqAndGenerationLiteral(t *testing.T) {
	srv := testserver.New(testserver.Options{
		SessionAckSeq:        42,
		SessionAckGeneration: 7,
	})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ack := got.GetSessionAck()
	if ack == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if ack.GetAckHighWatermarkSeq() != 42 || ack.GetGeneration() != 7 {
		t.Fatalf("SessionAck tuple=(%d, %d), want (42, 7)",
			ack.GetAckHighWatermarkSeq(), ack.GetGeneration())
	}
}

// TestServer_SessionAckZeroIsLiteralNotMirror verifies the renamed
// contract: when SessionAckSeq / SessionAckGeneration are unset
// (zero), the server replies with literal (0, 0) regardless of what
// the client advertised in SessionInit. Regression guard against a
// future "mirror the client's watermark on zero" reinterpretation
// of the option semantics — the prior naming (StaleWatermark) hinted
// at that, and the rename's contract is only enforceable if a test
// proves zero stays zero under a non-zero client watermark.
func TestServer_SessionAckZeroIsLiteralNotMirror(t *testing.T) {
	srv := testserver.New(testserver.Options{}) // both ack fields zero
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	// Send a SessionInit with NON-ZERO wal_high_watermark_seq +
	// generation. If the server "mirrors the client", the SessionAck
	// would echo (12345, 9). With literal-zero semantics, the
	// SessionAck must be (0, 0).
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				AgentId:             "test",
				SessionId:           "s1",
				Algorithm:           wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256,
				WalHighWatermarkSeq: 12345,
				Generation:          9,
			},
		},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	got, err := recvWithDeadline(t, conn, 2*time.Second)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	ack := got.GetSessionAck()
	if ack == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if ack.GetAckHighWatermarkSeq() != 0 || ack.GetGeneration() != 0 {
		t.Fatalf("SessionAck tuple=(%d, %d) — server appears to be mirroring the client's SessionInit watermark; want literal (0, 0) per Options doc",
			ack.GetAckHighWatermarkSeq(), ack.GetGeneration())
	}
}

// TestServer_AckDelayDelaysSessionAck verifies AckDelay is honoured
// on the SessionAck path. The timer starts BEFORE Send so the
// measured elapsed time bounds the entire client.Send → server
// receive → server delay → server.Send → client.Recv cycle. Under
// bufconn the non-delay components are sub-millisecond, so the
// elapsed time cleanly strictly exceeds the configured delay.
// Starting the timer after Send (a prior version of this test)
// would have been flaky: the server can start its delay countdown
// before the test goroutine resumes to capture the start.
func TestServer_AckDelayDelaysSessionAck(t *testing.T) {
	const delay = 80 * time.Millisecond
	srv := testserver.New(testserver.Options{AckDelay: delay})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	start := time.Now()
	sendSessionInit(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if got.GetSessionAck() == nil {
		t.Fatalf("got %T, want SessionAck", got.Msg)
	}
	if elapsed < delay {
		t.Fatalf("SessionAck arrived after %v, want >= %v", elapsed, delay)
	}
}

// TestServer_AckDelayDelaysBatchAck verifies AckDelay also applies
// on the BatchAck path (the server's Stream handler has a separate
// delay block for the EventBatch branch). Without a dedicated test,
// a future refactor that drops the BatchAck delay site while
// leaving the SessionAck site intact would pass the suite but
// silently regress the documented contract.
func TestServer_AckDelayDelaysBatchAck(t *testing.T) {
	const delay = 80 * time.Millisecond
	srv := testserver.New(testserver.Options{AckDelay: delay})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	// Establish the session first. SessionAck is also delayed, but
	// we only care about measuring the BatchAck delay separately.
	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Now time the EventBatch → BatchAck cycle. Start BEFORE Send
	// for the same reason documented on the SessionAck test.
	start := time.Now()
	sendEmptyBatch(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("recv BatchAck: %v", err)
	}
	if got.GetBatchAck() == nil {
		t.Fatalf("got %T, want BatchAck", got.Msg)
	}
	if elapsed < delay {
		t.Fatalf("BatchAck arrived after %v, want >= %v", elapsed, delay)
	}
}

// TestServer_DropAfterBatchN verifies the server returns an error from
// the Stream handler after observing the configured number of
// EventBatch messages on the CURRENT stream. The client observes the
// resulting stream termination via Recv returning a non-nil error.
func TestServer_DropAfterBatchN(t *testing.T) {
	srv := testserver.New(testserver.Options{DropAfterBatchN: 2})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Batch 1: acked normally.
	sendEmptyBatch(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck 1: %v", err)
	}

	// Batch 2: threshold reached; server returns from Stream, stream
	// ends. Recv observes EOF / stream-closed.
	sendEmptyBatch(t, conn)
	_, err := recvWithDeadline(t, conn, 2*time.Second)
	if err == nil {
		t.Fatalf("recv returned nil; want stream-closed error")
	}

	// Two batches were recorded server-side.
	if got := len(srv.Batches()); got != 2 {
		t.Fatalf("server.Batches len=%d, want 2", got)
	}
}

// TestServer_GoawayAfterBatchN verifies the server emits a Goaway
// ServerMessage after the configured threshold, then ends the stream.
// Recv on the client observes the Goaway followed by EOF.
func TestServer_GoawayAfterBatchN(t *testing.T) {
	srv := testserver.New(testserver.Options{GoawayAfterBatchN: 1})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Single batch hits the threshold; server emits Goaway then ends.
	sendEmptyBatch(t, conn)
	got, err := recvWithDeadline(t, conn, 2*time.Second)
	if err != nil {
		t.Fatalf("recv Goaway: %v", err)
	}
	if got.GetGoaway() == nil {
		t.Fatalf("got %T, want Goaway", got.Msg)
	}

	// Next Recv observes stream closure (EOF or equivalent).
	_, err = recvWithDeadline(t, conn, 2*time.Second)
	if err == nil {
		t.Fatalf("recv returned nil; want stream-closed after Goaway")
	}
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "closed") {
		// gRPC may surface the end as io.EOF, "rpc error ... code =
		// Unavailable", or a plain "closed" string depending on
		// version. Accept any of them.
		t.Logf("post-Goaway recv err = %v (not EOF-shaped; accepting)", err)
	}
}

// TestServer_PerStreamCountersResetOnReconnect verifies that
// DropAfterBatchN / GoawayAfterBatchN operate per-stream: a second
// Dial against the same Server sees the counter start at 0 again.
// Regression guard for the server-global-counter bug.
func TestServer_PerStreamCountersResetOnReconnect(t *testing.T) {
	srv := testserver.New(testserver.Options{DropAfterBatchN: 2})
	defer srv.Close()

	// --- Stream 1: send SessionInit + two batches; the second drops.
	conn1 := dialOrFatal(t, srv)
	sendSessionInit(t, conn1)
	if _, err := recvWithDeadline(t, conn1, 2*time.Second); err != nil {
		t.Fatalf("stream 1 SessionAck: %v", err)
	}
	sendEmptyBatch(t, conn1)
	if _, err := recvWithDeadline(t, conn1, 2*time.Second); err != nil {
		t.Fatalf("stream 1 BatchAck: %v", err)
	}
	sendEmptyBatch(t, conn1)
	if _, err := recvWithDeadline(t, conn1, 2*time.Second); err == nil {
		t.Fatal("stream 1: expected drop after 2nd batch")
	}
	_ = conn1.Close()

	// --- Stream 2: fresh counter. Send SessionInit + one batch, expect
	// a clean BatchAck (NOT an immediate drop). If the counter were
	// server-global, stream 2's first batch would hit the threshold
	// (global count = 3) and drop immediately.
	conn2 := dialOrFatal(t, srv)
	defer conn2.Close()
	sendSessionInit(t, conn2)
	if _, err := recvWithDeadline(t, conn2, 2*time.Second); err != nil {
		t.Fatalf("stream 2 SessionAck: %v", err)
	}
	sendEmptyBatch(t, conn2)
	got, err := recvWithDeadline(t, conn2, 2*time.Second)
	if err != nil {
		t.Fatalf("stream 2 BatchAck: %v (regression: drop counter is not per-stream)", err)
	}
	if got.GetBatchAck() == nil {
		t.Fatalf("stream 2 got %T, want BatchAck", got.Msg)
	}

	// Server-global tally still counts both streams' batches (3 total:
	// stream 1 had 2, stream 2 had 1).
	if got := len(srv.Batches()); got != 3 {
		t.Fatalf("Batches len=%d across both streams, want 3", got)
	}
}


// TestServer_InvalidEventBatchClassifiedAndStreamDropped is the live-
// path acceptance for transport.ClassifyAndIncInvalidFrame (Task 22b
// follow-up). The test wires a real *metrics.WTPMetrics into the
// testserver and sends an EventBatch that fails wtpv1.ValidateEventBatch
// (Compression=UNSPECIFIED). Expected: (1) the per-reason
// wtp_dropped_invalid_frame_total counter increments under the typed
// ReasonEventBatchCompressionUnspecified label, (2) the stream is
// dropped (next Recv observes a non-nil error), (3) no WARN fires on
// the typed path (only the defense-in-depth classifier_bypass path
// WARNs, and the validator emitted a typed *ValidationError).
func TestServer_InvalidEventBatchClassifiedAndStreamDropped(t *testing.T) {
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	c := metrics.New()
	m := c.WTP()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	srv := testserver.New(testserver.Options{
		Metrics: m,
		Logger:  logger,
	})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Fails ValidateEventBatch: Compression is UNSPECIFIED.
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: &wtpv1.EventBatch{
			Compression: wtpv1.Compression_COMPRESSION_UNSPECIFIED,
		}},
	}); err != nil {
		t.Fatalf("send invalid EventBatch: %v", err)
	}

	// Server drops the stream on validation failure — next Recv sees
	// a non-nil error instead of a BatchAck.
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err == nil {
		t.Fatal("Recv returned nil error; stream should have been dropped on invalid EventBatch")
	}

	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonEventBatchCompressionUnspec); got != 1 {
		t.Errorf("DroppedInvalidFrame(event_batch_compression_unspecified) = %d, want 1", got)
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 0 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 0 (validator emitted typed *ValidationError — no bypass)", got)
	}
	if logBuf.Len() != 0 {
		t.Errorf("expected no WARN on typed validator path, got:\n%s", logBuf.String())
	}

	// The server-side tally MUST skip the invalid batch (the validator
	// returns before addBatch is called).
	if got := len(srv.Batches()); got != 0 {
		t.Errorf("Batches len=%d, want 0 (invalid batch must not be tallied)", got)
	}
}

// TestServer_InvalidSessionInitClassifiedAndStreamDropped is the
// SessionInit sibling of TestServer_InvalidEventBatchClassifiedAndStreamDropped
// (Task 22b / roborev #5916 Low). The test sends a SessionInit with
// Algorithm=HASH_ALGORITHM_UNSPECIFIED and asserts: (1) the per-reason
// counter increments under ReasonSessionInitAlgorithmUnspecified,
// (2) the stream is dropped before SessionAck is sent, (3) no
// defense-in-depth WARN fires on the typed path.
func TestServer_InvalidSessionInitClassifiedAndStreamDropped(t *testing.T) {
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	c := metrics.New()
	m := c.WTP()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	srv := testserver.New(testserver.Options{Metrics: m, Logger: logger})
	defer srv.Close()

	conn := dialOrFatal(t, srv)
	defer conn.Close()

	// SessionInit with Algorithm=UNSPECIFIED fails ValidateSessionInit.
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{SessionInit: &wtpv1.SessionInit{
			AgentId:   "test",
			SessionId: "s-invalid",
			Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		}},
	}); err != nil {
		t.Fatalf("send invalid SessionInit: %v", err)
	}

	// Server drops the stream on validation failure — no SessionAck
	// arrives; next Recv observes a non-nil error.
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err == nil {
		t.Fatal("Recv returned nil error; invalid SessionInit should have dropped the stream")
	}

	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonSessionInitAlgorithmUnspec); got != 1 {
		t.Errorf("DroppedInvalidFrame(session_init_algorithm_unspecified) = %d, want 1", got)
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 0 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 0 (validator emitted typed *ValidationError)", got)
	}
	if logBuf.Len() != 0 {
		t.Errorf("expected no defense-in-depth WARN on typed path, got:\n%s", logBuf.String())
	}
}
