package watchtower_test

import (
	"bytes"
	"context"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
)

// invalidFrameReasonCounterRE captures the numeric value of
// wtp_dropped_invalid_frame_total for a specific reason. Mirrors
// reasonCounterRE in component_session_init_failure_test.go but
// targets the dropped-invalid-frame counter family wired by
// transport.ClassifyAndIncInvalidFrame on recv-side validation
// failures (recv_multiplexer.go Task 9).
//
// TODO: a parallel helper for wtp_session_init_failures_total lives in
// component_session_init_failure_test.go. If a third metric-counter
// component test arrives, extract a shared
// metricCounterRE(metricName, reason) helper into a new
// component_metrics_helpers_test.go file rather than cloning a third
// time.
func invalidFrameReasonCounterRE(reason string) *regexp.Regexp {
	return regexp.MustCompile(`wtp_dropped_invalid_frame_total\{reason="` + regexp.QuoteMeta(reason) + `"\} (\d+)`)
}

// waitForInvalidFrameCounter polls the metrics handler until the
// wtp_dropped_invalid_frame_total{reason=R} counter reaches `want` or
// the deadline elapses. Returns the observed count (-1 on timeout) and
// the last scraped body for diagnostics. Counterpart to
// waitForReasonCounter in component_session_init_failure_test.go.
func waitForInvalidFrameCounter(t *testing.T, c *metrics.Collector, reason string, want int, deadline time.Duration) (int, string) {
	t.Helper()
	re := invalidFrameReasonCounterRE(reason)
	end := time.Now().Add(deadline)
	var body string
	for time.Now().Before(end) {
		body = scrapeMetricsFor(t, c)
		m := re.FindStringSubmatch(body)
		if m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil && n >= want {
				return n, body
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return -1, body
}

// baseInvalidFrameOpts mirrors baseSessionInitOpts but is keyed for
// inbound-validation tests: the testserver injects a malformed
// ServerMessage immediately after SessionAck, so the watchtower must
// reach Live (a real Dialer) and then exercise the recv classifier.
func baseInvalidFrameOpts(t *testing.T, srv *testserver.Server, c *metrics.Collector) watchtower.Options {
	t.Helper()
	return watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:invalid-frame-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         c,
		BackoffInitial:  10 * time.Millisecond,
		BackoffMax:      50 * time.Millisecond,
	}
}

// TestStore_InboundGoaway_CodeUnspecified pins the contract that an
// inbound Goaway with Code=UNSPECIFIED is NOT classified as an invalid
// frame. ValidateGoaway accepts UNSPECIFIED because the proto contract
// is "unknown; clients MUST treat as transient and reconnect" — i.e. a
// valid wire value with well-defined semantics, not a malformed frame.
// Watchtower also routes every Fatal-with-generic-reason (gen mismatch,
// unexpected gap, stale stream, dedup failure) through Goaway with
// UNSPECIFIED code; classifying that as invalid silently dropped every
// such Goaway and caused a tight reconnect loop where the client never
// observed the server's stated reason.
//
// Regression guard: assert wtp_dropped_invalid_frame_total
// {reason="goaway_code_unspecified"} STAYS AT ZERO for at least 2 s
// even while the recv loop sees the Goaway and tears the stream down.
// The stream-teardown behavior itself is exercised by the recv-
// multiplexer integration test
// TestRecvMultiplexer_GoawaySurfacesFailClosedError.
func TestStore_InboundGoaway_CodeUnspecified(t *testing.T) {
	skipOnWindowsCI(t)

	srv := testserver.New(testserver.Options{
		InjectAfterSessionAck: &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{
					Code: wtpv1.GoawayCode_GOAWAY_CODE_UNSPECIFIED,
				},
			},
		},
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseInvalidFrameOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	// Let the recv loop process the Goaway + a few reconnect cycles.
	time.Sleep(2 * time.Second)
	got, body := waitForInvalidFrameCounter(t, c, "goaway_code_unspecified", 1, 1*time.Millisecond)
	if got > 0 {
		t.Fatalf("UNSPECIFIED Goaway must NOT increment wtp_dropped_invalid_frame_total{reason=goaway_code_unspecified}; got %d\nbody:\n%s", got, body)
	}
}

// TestStore_InboundSessionUpdate_GenerationZero drives the testserver
// to inject a SessionUpdate with NewGeneration=0 immediately after
// SessionAck. The recv multiplexer's ServerUpdate arm runs
// ValidateSessionUpdate, which the classifier maps to
// wtp_dropped_invalid_frame_total
// {reason="session_update_generation_invalid"}. Asserts the counter
// ticks at least once within the deadline.
func TestStore_InboundSessionUpdate_GenerationZero(t *testing.T) {
	skipOnWindowsCI(t)

	srv := testserver.New(testserver.Options{
		InjectAfterSessionAck: &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_ServerUpdate{
				ServerUpdate: &wtpv1.SessionUpdate{
					NewGeneration:     0,
					NewKeyFingerprint: "k",
					NewContextDigest:  "d",
				},
			},
		},
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseInvalidFrameOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	got, body := waitForInvalidFrameCounter(t, c, "session_update_generation_invalid", 1, 30*time.Second)
	if got < 1 {
		t.Fatalf("expected reason=session_update_generation_invalid counter >= 1 within 30s\nbody:\n%s", body)
	}
}
