package watchtower_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// skipOnWindowsCI mirrors the pattern used by transport-level component
// tests: end-to-end transport timing is unreliable on Windows CI runners
// due to slow disk I/O and scheduler quanta. The same metric paths are
// exercised at unit level on Windows; component coverage is Linux-only.
func skipOnWindowsCI(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("integration test skipped on Windows: slow CI runners flake on transport timing")
	}
}

func scrapeMetricsFor(t *testing.T, c *metrics.Collector) string {
	t.Helper()
	rr := httptest.NewRecorder()
	c.Handler(metrics.HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	return rr.Body.String()
}

// reasonCounterRE builds a regexp that captures the numeric value of
// the wtp_session_init_failures_total counter for a specific reason.
// The counter family is emitted with an always-zero baseline for every
// reason on every scrape, so a substring match for "{reason=X} 1" is
// fragile when the metric ticks more than once (e.g. retried paths
// like recv_failed and unexpected_message that loop through Connecting
// backoff). Capturing the count and asserting >= 1 sidesteps that.
//
// TODO: a parallel helper for wtp_dropped_invalid_frame_total lives in
// component_invalid_frame_test.go. If a third metric-counter component
// test arrives, extract a shared metricCounterRE(metricName, reason)
// + waitForMetricCounter helper into a new
// component_metrics_helpers_test.go file rather than cloning a third
// time.
func reasonCounterRE(reason string) *regexp.Regexp {
	return regexp.MustCompile(`wtp_session_init_failures_total\{reason="` + regexp.QuoteMeta(reason) + `"\} (\d+)`)
}

func waitForReasonCounter(t *testing.T, c *metrics.Collector, reason string, want int, deadline time.Duration) (int, string) {
	t.Helper()
	re := reasonCounterRE(reason)
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

func baseSessionInitOpts(t *testing.T, dialer transport.Dialer, c *metrics.Collector) watchtower.Options {
	t.Helper()
	return watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:session-init-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		AllowStubMapper: true,
		Dialer:          dialer,
		// Tight backoff so the retry-path tests (recv_failed,
		// unexpected_message, send_failed) can observe at least one
		// counter increment well within the test deadline. Production
		// defaults are 200ms initial / 30s max.
		BackoffInitial: 10 * time.Millisecond,
		BackoffMax:     50 * time.Millisecond,
		Metrics:        c,
	}
}

// TestStore_SessionInit_Rejected drives the agent against a testserver
// configured to return SessionAck.accepted=false; asserts the
// rejected counter ticks. This path returns StateShutdown so the
// counter increments exactly once.
func TestStore_SessionInit_Rejected(t *testing.T) {
	skipOnWindowsCI(t)
	srv := testserver.New(testserver.Options{
		RejectSession: true,
		RejectReason:  "test policy",
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv.DialerFor(), c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	got, body := waitForReasonCounter(t, c, "rejected", 1, 30*time.Second)
	if got < 1 {
		t.Fatalf("expected reason=rejected counter >= 1 within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_RecvFailed drives the agent against a testserver
// that closes the stream after receiving SessionInit but before sending
// any SessionAck; asserts the recv_failed counter ticks. This path
// returns StateConnecting (retry), so the counter may increment more
// than once during the wait window — assert >= 1.
func TestStore_SessionInit_RecvFailed(t *testing.T) {
	skipOnWindowsCI(t)
	srv := testserver.New(testserver.Options{
		CloseAfterSessionInitRecv: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv.DialerFor(), c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	got, body := waitForReasonCounter(t, c, "recv_failed", 1, 30*time.Second)
	if got < 1 {
		t.Fatalf("expected reason=recv_failed counter >= 1 within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_UnexpectedMessage drives the agent against a
// testserver that responds to SessionInit with a BatchAck (instead of
// SessionAck). The runConnecting classifier flags this as
// unexpected_message and returns StateConnecting (retry).
func TestStore_SessionInit_UnexpectedMessage(t *testing.T) {
	skipOnWindowsCI(t)
	srv := testserver.New(testserver.Options{
		RespondWithUnexpectedMessage: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv.DialerFor(), c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	got, body := waitForReasonCounter(t, c, "unexpected_message", 1, 30*time.Second)
	if got < 1 {
		t.Fatalf("expected reason=unexpected_message counter >= 1 within 30s\nbody:\n%s", body)
	}
}

// sendFailingConn is a transport.Conn whose Send always returns an
// error, so runConnecting's `conn.Send(SessionInit)` path fails with
// WTPSessionFailureReasonSendFailed. Used by the send_failed subtest
// because the bufconn-backed testserver does not expose a clean knob
// to fail the client's outbound send (the duplex pipe accepts the
// frame regardless of what the server intends to do with it).
type sendFailingConn struct {
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newSendFailingConn() *sendFailingConn {
	return &sendFailingConn{closeCh: make(chan struct{})}
}

func (c *sendFailingConn) Send(*wtpv1.ClientMessage) error {
	return errors.New("sendFailingConn: forced send failure")
}

func (c *sendFailingConn) Recv() (*wtpv1.ServerMessage, error) {
	// Block until Close so retry-path tests don't burn CPU; runConnecting
	// never reaches Recv on the send-failed branch, but a real Conn would
	// keep Recv pending until the stream tore down. Channel-based wait
	// avoids spawning a poller goroutine per call.
	<-c.closeCh
	return nil, errors.New("sendFailingConn: closed")
}

func (c *sendFailingConn) CloseSend() error { return nil }

func (c *sendFailingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

// TestStore_SessionInit_SendFailed wires a custom Dialer that returns
// a Conn whose Send always errors; asserts the send_failed counter
// ticks. Returns StateConnecting (retry) so the counter increments
// repeatedly — assert >= 1.
func TestStore_SessionInit_SendFailed(t *testing.T) {
	skipOnWindowsCI(t)
	c := metrics.New()

	dialer := transport.DialerFunc(func(_ context.Context) (transport.Conn, error) {
		return newSendFailingConn(), nil
	})

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, dialer, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	got, body := waitForReasonCounter(t, c, "send_failed", 1, 30*time.Second)
	if got < 1 {
		t.Fatalf("expected reason=send_failed counter >= 1 within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_Unknown is intentionally skipped.
//
// The reason=unknown path in runConnecting fires when the OUTBOUND
// SessionInit fails wtpv1.ValidateSessionInit — i.e. when the
// transport's own sessionInit() builder produces a malformed frame.
// Reaching that site from a component test would require Options that
// pass watchtower.Options.validate() (which enforces non-empty
// AgentID / SessionID / KeyFingerprint and HMAC secret length) AND
// also produce a SessionInit proto that fails the spec validator
// (which checks UTF-8 / length / required-field invariants on the
// same surface). The two validators overlap closely enough that
// engineering an Options shape that threads the gap is brittle and
// would mostly exercise the test scaffolding rather than the wiring
// under verification.
//
// Unit-level coverage for IncSessionInitFailures(unknown) lives in
// metrics/wtp_test.go (Task 2). The component-level wiring at this
// site is verified indirectly by the four other reason subtests
// sharing the same metrics.WTPMetrics handle.
func TestStore_SessionInit_Unknown(t *testing.T) {
	t.Skip("validator-failure path is unreachable from a component test today: " +
		"wtpv1.ValidateSessionInit (proto/canyonroad/wtp/v1/validate.go:265) only rejects " +
		"Algorithm==UNSPECIFIED, but watchtower.Options.validate() " +
		"(internal/store/watchtower/options.go) maps every accepted HMACAlgorithm to " +
		"a non-UNSPECIFIED proto enum. Unit coverage for IncSessionInitFailures(unknown) " +
		"lives in TestWTPMetrics_SessionInitFailures_PerReasonInc.")
}
