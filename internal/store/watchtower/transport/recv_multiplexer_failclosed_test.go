package transport_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// recordingHandler is the handler-agnostic test capture surface for
// the Task 22d fail-closed WARN log assertions. It stores each
// emitted slog.Record under a mutex so the test goroutine can assert
// on Record.Level, Record.Message, and per-attr key/value pairs
// without depending on any specific stdlib handler's rendering. The
// production transport accepts any *slog.Logger, and the sanitizer's
// handler-agnostic invariant guarantees the WARN payload is safe
// regardless of which handler the operator wires up — these tests
// inherit the same property by reading the structured attrs
// directly.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(_ string) slog.Handler      { return h }

// snapshot returns a copy of the recorded slog.Records so the test
// can inspect them without holding the handler mutex.
func (h *recordingHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

// attrMap walks all attrs of a slog.Record and returns them as a
// map keyed by attr key. Useful for table-driven assertions on the
// WARN field schema.
func attrMap(r slog.Record) map[string]slog.Value {
	out := make(map[string]slog.Value)
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value
		return true
	})
	return out
}

// findOneWarn returns the single WARN-level record matching the
// expected reason; fails the test if zero or more than one match.
// Centralised so the per-branch tests don't repeat the find-and-
// assert-count boilerplate.
func findOneWarn(t *testing.T, h *recordingHandler, reason string) slog.Record {
	t.Helper()
	var matches []slog.Record
	for _, r := range h.snapshot() {
		if r.Level != slog.LevelWarn {
			continue
		}
		got, ok := attrMap(r)["reason"]
		if !ok || got.String() != reason {
			continue
		}
		matches = append(matches, r)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one WARN record with reason=%q; got %d", reason, len(matches))
	}
	return matches[0]
}

// newFailClosedTransport mirrors newIntegrationTransport but injects
// a recordingHandler-backed logger and lets the caller set
// LogGoawayMessage. Returns the Transport plus the handler so tests
// can assert on captured records.
func newFailClosedTransport(t *testing.T, fc *recvFakeConn, logGoaway bool) (*transport.Transport, *recordingHandler) {
	t.Helper()
	h := &recordingHandler{}
	logger := slog.New(h)
	tr, err := transport.New(transport.Options{
		Dialer: transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
			return fc, nil
		}),
		AgentID:          "test-agent",
		SessionID:        "sess-failclosed",
		Logger:           logger,
		LogGoawayMessage: logGoaway,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transport.SetConnForTest(tr, fc)
	return tr, h
}

// driveFailClosed pushes the supplied ServerMessage onto the recv
// fake conn, starts the recv goroutine, waits for it to return
// (fail-closed branches return after pushing the errCh sentinel),
// and tears down. The errCh sentinel is read so the caller can
// assert on the state-machine-signal contract too.
func driveFailClosed(t *testing.T, tr *transport.Transport, fc *recvFakeConn, msg *wtpv1.ServerMessage) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h := transport.StartRecvForTest(tr, ctx)
	defer transport.TeardownRecvForTest(tr)
	defer fc.Close()

	fc.Push(msg)

	// Drain the errCh sentinel — the WARN log is additive, the
	// errCh is the state-machine signal.
	var recvErr error
	select {
	case recvErr = <-h.ErrCh():
	case <-time.After(2 * time.Second):
		t.Fatal("driveFailClosed: errCh did not receive within 2s")
	}

	// Wait for the recv goroutine to fully exit so the WARN record
	// is guaranteed visible by the time we assert.
	select {
	case <-h.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("driveFailClosed: recv goroutine did not return within 2s")
	}
	return recvErr
}

// TestRecvMultiplexer_FailClosedWarnLogGoawayDefault verifies the
// conservative-default Goaway WARN: standard fields plus
// goaway_code, goaway_retry_immediately, goaway_message_present
// (all with NON-DEFAULT proto3 values — see Step 1 sub-cases for
// why Code=DRAINING, RetryImmediately=true, Message="..." are
// mandatory in the positive-path test). The goaway_message key is
// ABSENT under the default; opt-in mode is covered separately.
func TestRecvMultiplexer_FailClosedWarnLogGoawayDefault(t *testing.T) {
	fc := newRecvFakeConn()
	tr, h := newFailClosedTransport(t, fc, false /* LogGoawayMessage */)

	msg := &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_Goaway{
			Goaway: &wtpv1.Goaway{
				Code:             wtpv1.GoawayCode_GOAWAY_CODE_DRAINING,
				Message:          "graceful shutdown",
				RetryImmediately: true,
			},
		},
	}
	if err := driveFailClosed(t, tr, fc, msg); err == nil {
		t.Fatal("expected errCh sentinel after fail-closed Goaway")
	}

	rec := findOneWarn(t, h, "goaway_received")
	attrs := attrMap(rec)
	checkAttrEq(t, attrs, "frame", "recv_control")
	checkAttrEq(t, attrs, "reason", "goaway_received")
	checkAttrEq(t, attrs, "session_id", "sess-failclosed")
	checkAttrEq(t, attrs, "goaway_code", "GOAWAY_CODE_DRAINING")
	checkAttrBool(t, attrs, "goaway_retry_immediately", true)
	checkAttrBool(t, attrs, "goaway_message_present", true)
	if _, present := attrs["goaway_message"]; present {
		t.Fatalf("goaway_message must be ABSENT under conservative default; got %v", attrs["goaway_message"])
	}
}

// TestRecvMultiplexer_FailClosedWarnLogGoawayOptIn verifies the
// opt-in Goaway WARN: standard fields plus the same three Goaway-
// payload fields AND the sanitized goaway_message verbatim.
func TestRecvMultiplexer_FailClosedWarnLogGoawayOptIn(t *testing.T) {
	fc := newRecvFakeConn()
	tr, h := newFailClosedTransport(t, fc, true /* LogGoawayMessage */)

	msg := &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_Goaway{
			Goaway: &wtpv1.Goaway{
				Code:             wtpv1.GoawayCode_GOAWAY_CODE_DRAINING,
				Message:          "graceful shutdown",
				RetryImmediately: true,
			},
		},
	}
	if err := driveFailClosed(t, tr, fc, msg); err == nil {
		t.Fatal("expected errCh sentinel after fail-closed Goaway")
	}

	rec := findOneWarn(t, h, "goaway_received")
	attrs := attrMap(rec)
	checkAttrEq(t, attrs, "goaway_message", "graceful shutdown")
	checkAttrBool(t, attrs, "goaway_message_present", true)
}

// TestRecvMultiplexer_FailClosedWarnLogGoawayZeroValues exercises the
// "field emitted at zero" contract for the Goaway branch — a
// Code=UNSPECIFIED, RetryImmediately=false, Message="" goaway must
// still emit goaway_code (with the enum's String() form for the
// zero), goaway_retry_immediately=false (NOT absent), and
// goaway_message_present=false. Under the opt-in mode, goaway_message
// must be present with value "" (NOT absent).
func TestRecvMultiplexer_FailClosedWarnLogGoawayZeroValues(t *testing.T) {
	t.Run("default_mode", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, false)
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{}, // all zero
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		attrs := attrMap(rec)
		checkAttrEq(t, attrs, "goaway_code", "GOAWAY_CODE_UNSPECIFIED")
		checkAttrBool(t, attrs, "goaway_retry_immediately", false)
		checkAttrBool(t, attrs, "goaway_message_present", false)
		if _, present := attrs["goaway_message"]; present {
			t.Fatalf("goaway_message must be ABSENT under default mode")
		}
	})
	t.Run("opt_in_mode", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		attrs := attrMap(rec)
		checkAttrEq(t, attrs, "goaway_message", "") // explicit empty
		checkAttrBool(t, attrs, "goaway_message_present", false)
	})
}

// TestRecvMultiplexer_FailClosedWarnLogGoawaySanitization covers the
// sanitizer log-safety contract: invalid UTF-8 → U+FFFD, control
// bytes → U+FFFD, oversized payloads truncated to <=512 bytes with
// `...[truncated]` marker at a rune boundary, plus the all-at-once
// regression for sanitize-THEN-truncate ordering.
func TestRecvMultiplexer_FailClosedWarnLogGoawaySanitization(t *testing.T) {
	t.Run("control_bytes", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{Message: "hello\x00\x01world\x7f"},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		got := attrMap(rec)["goaway_message"].String()
		want := "hello��world�"
		if got != want {
			t.Fatalf("control-byte sanitization: got %q, want %q", got, want)
		}
	})
	t.Run("tabs_and_newlines_replaced", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{Message: "foo\tbar\nbaz"},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		got := attrMap(rec)["goaway_message"].String()
		want := "foo�bar�baz"
		if got != want {
			t.Fatalf("tab/newline sanitization: got %q, want %q", got, want)
		}
	})
	t.Run("invalid_utf8_including_multibyte_surrogate", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		// 0xff/0xfe/0xfd are lone bytes; 0xed 0xa0 0x80 is a 3-byte
		// UTF-8 encoding of a UTF-16 high surrogate (invalid in
		// UTF-8). strings.ToValidUTF8 must reject all of them.
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{Message: "prefix\xff\xfe\xfd\xed\xa0\x80suffix"},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		got := attrMap(rec)["goaway_message"].String()
		if !utf8.ValidString(got) {
			t.Fatalf("sanitized output is not valid UTF-8: %q", got)
		}
		if !strings.HasPrefix(got, "prefix") || !strings.HasSuffix(got, "suffix") {
			t.Fatalf("prefix/suffix not preserved: %q", got)
		}
	})
	t.Run("overlength_truncation", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{Message: strings.Repeat("a", 1024)},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		got := attrMap(rec)["goaway_message"].String()
		if len(got) > 512 {
			t.Fatalf("output exceeds 512-byte budget: len=%d", len(got))
		}
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Fatalf("missing truncation marker: %q (last bytes=%q)", got, got[max(0, len(got)-32):])
		}
	})
	t.Run("combined_overlength_invalid_control_multibyte_boundary", func(t *testing.T) {
		fc := newRecvFakeConn()
		tr, h := newFailClosedTransport(t, fc, true)
		// Construct a 600-byte input mixing all hazards.
		var b strings.Builder
		// 100 bytes of plain ASCII prefix
		b.WriteString(strings.Repeat("a", 100))
		// invalid UTF-8 sequences mid-input
		b.WriteString("\xff\xfe")
		b.WriteString("\xc3\x28") // invalid 2-byte
		// control bytes
		b.WriteString("\x00\x01\x7f")
		// padding to push the multibyte char near the 500-byte mark
		b.WriteString(strings.Repeat("b", 390))
		// multibyte char near the truncation boundary
		b.WriteString("中") // 3 bytes
		// trailing padding
		b.WriteString(strings.Repeat("c", 100))

		msg := &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{Message: b.String()},
			},
		}
		_ = driveFailClosed(t, tr, fc, msg)
		rec := findOneWarn(t, h, "goaway_received")
		got := attrMap(rec)["goaway_message"].String()

		if !utf8.ValidString(got) {
			t.Fatalf("sanitized + truncated output is not valid UTF-8: %q", got)
		}
		if len(got) > 512 {
			t.Fatalf("output exceeds 512-byte budget: len=%d", len(got))
		}
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Fatalf("missing truncation marker (sanitization+truncation broken): %q", got[max(0, len(got)-32):])
		}
		if !strings.HasPrefix(got, strings.Repeat("a", 100)) {
			t.Fatalf("ASCII prefix not preserved verbatim")
		}
	})
}

// TestRecvMultiplexer_FailClosedWarnLogServerUpdate verifies the
// ServerUpdate branch: standard fields only (no payload — Phase 4
// has no SessionUpdate handler so any extra payload would be churn).
func TestRecvMultiplexer_FailClosedWarnLogServerUpdate(t *testing.T) {
	fc := newRecvFakeConn()
	tr, h := newFailClosedTransport(t, fc, false)
	msg := &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_ServerUpdate{
			ServerUpdate: &wtpv1.SessionUpdate{},
		},
	}
	if err := driveFailClosed(t, tr, fc, msg); err == nil {
		t.Fatal("expected errCh sentinel after fail-closed ServerUpdate")
	}
	rec := findOneWarn(t, h, "server_update_unsupported_in_phase_4")
	attrs := attrMap(rec)
	checkAttrEq(t, attrs, "frame", "recv_control")
	checkAttrEq(t, attrs, "session_id", "sess-failclosed")
}

// TestRecvMultiplexer_FailClosedWarnLogUnknownFrame verifies the
// unknown-frame branch: standard fields plus frame_type carrying
// the Go reflect type so operators can identify the proto variant
// the local switch did not recognise. We can't easily inject an
// "unknown" frame variant from the test (the proto enum is
// closed); the current default branch fires when a future server
// adds a new oneof discriminator. To exercise it without modifying
// proto, we use a SessionAck-shaped message — wait, that's
// recognised by the recv switch (BatchAck/Heartbeat/Goaway/SessionUpdate
// are the only handled cases). Actually, looking at recv_multiplexer.go,
// SessionAck IS handled via a different code path (not in runRecv).
// runRecv's default branch fires for any ServerMessage variant not
// in {BatchAck, ServerHeartbeat, Goaway, ServerUpdate}.
// SessionAck IS one of those unhandled-by-runRecv variants — it's
// processed by runConnecting's direct conn.Recv, not by the recv
// goroutine.
func TestRecvMultiplexer_FailClosedWarnLogUnknownFrame(t *testing.T) {
	fc := newRecvFakeConn()
	tr, h := newFailClosedTransport(t, fc, false)
	// SessionAck is not in the runRecv switch's enumerated cases
	// — it falls into the default branch.
	msg := &wtpv1.ServerMessage{
		Msg: &wtpv1.ServerMessage_SessionAck{
			SessionAck: &wtpv1.SessionAck{Accepted: true},
		},
	}
	if err := driveFailClosed(t, tr, fc, msg); err == nil {
		t.Fatal("expected errCh sentinel after fail-closed unknown frame")
	}
	rec := findOneWarn(t, h, "recv_unknown_frame_type")
	attrs := attrMap(rec)
	checkAttrEq(t, attrs, "frame", "recv_control")
	checkAttrEq(t, attrs, "session_id", "sess-failclosed")
	frameType, ok := attrs["frame_type"]
	if !ok {
		t.Fatal("frame_type field missing from unknown-frame WARN")
	}
	// The exact Go type name varies by protobuf version; just assert
	// it mentions "SessionAck" so the value is identifiably the
	// proto type we sent.
	if !strings.Contains(frameType.String(), "SessionAck") {
		t.Fatalf("frame_type=%v, want substring SessionAck", frameType)
	}
}

// checkAttrEq fails the test if attrs[key] != want (string compare).
func checkAttrEq(t *testing.T, attrs map[string]slog.Value, key, want string) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("attr %q missing from WARN record", key)
	}
	if got.String() != want {
		t.Fatalf("attr %q = %q, want %q", key, got.String(), want)
	}
}

// checkAttrBool fails the test if attrs[key].Bool() != want.
func checkAttrBool(t *testing.T, attrs map[string]slog.Value, key string, want bool) {
	t.Helper()
	got, ok := attrs[key]
	if !ok {
		t.Fatalf("attr %q missing from WARN record", key)
	}
	if got.Kind() != slog.KindBool {
		t.Fatalf("attr %q kind=%v, want Bool", key, got.Kind())
	}
	if got.Bool() != want {
		t.Fatalf("attr %q = %v, want %v", key, got.Bool(), want)
	}
}

// silence unused-import linter if errors import drifts later.
var _ = errors.New
