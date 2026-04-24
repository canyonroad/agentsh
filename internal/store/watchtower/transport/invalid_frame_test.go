package transport

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/metrics"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestReceiver_NonTypedErrorClassifiedAsClassifierBypass verifies the
// receiver-side defense-in-depth fallback classifies bare, non-
// *ValidationError errors under reason="classifier_bypass" (NOT
// "unknown"). The validator contract guarantees every failure returns
// a *ValidationError, so this branch SHOULD never trigger in
// production — but a non-validator caller (unit mock, future code
// path that bypasses ValidateEventBatch) might pass a bare error, and
// the WARN + metric make that drift visible to operators.
//
// Task 22b Step 4a: the test also asserts the receiver-side
// classifier_bypass rate-limiter contract by injecting the bare error
// TWICE in sequence (no time advance). Expected: counter increments
// TWICE (unconditional) while the receiver-side WARN log emits EXACTLY
// ONCE (the second call's WARN was throttled by the receiver-side
// per-path limiter). The metrics-side limiter is independent — see
// TestReceiver_PerPathLimiterNotStarvedByMetricsSide for the
// non-starvation guarantee.
func TestReceiver_NonTypedErrorClassifiedAsClassifierBypass(t *testing.T) {
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := metrics.New()
	m := c.WTP()

	bare := fmt.Errorf("%w: synthetic non-typed error", wtpv1.ErrInvalidFrame)

	ClassifyAndIncInvalidFrame(logger, m, bare)
	ClassifyAndIncInvalidFrame(logger, m, bare)

	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 2 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 2 (counter MUST be unconditional even when WARN is rate-limited)", got)
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonUnknown); got != 0 {
		t.Errorf("DroppedInvalidFrame(unknown) = %d, want 0 (classifier_bypass and unknown MUST be disjoint)", got)
	}

	out := buf.String()
	logged := 0
	if buf.Len() > 0 {
		logged = strings.Count(strings.TrimRight(out, "\n"), "\n") + 1
	}
	if logged != 1 {
		t.Errorf("WARN log emitted %d entries for 2 bare-error calls; want exactly 1 (first allowed, second throttled by shared limiter)\nlog:\n%s", logged, out)
	}
	if want := "non-typed frame validation error"; !strings.Contains(out, want) {
		t.Errorf("expected WARN message %q in log output\nlog:\n%s", want, out)
	}
	if want := `"reason":"classifier_bypass"`; !strings.Contains(out, want) {
		t.Errorf("expected reason=classifier_bypass field in log output\nlog:\n%s", out)
	}
	if want := `"err_type":"*fmt.wrapError"`; !strings.Contains(out, want) {
		t.Errorf("expected err_type field in log output\nlog:\n%s", out)
	}
}

// TestReceiver_PerPathLimiterNotStarvedByMetricsSide verifies the
// receiver-side classifier_bypass WARN consults a SEPARATE per-path
// limiter from the metrics-side path. Pre-drains the metrics-side
// bucket via IncDroppedInvalidFrame with an invalid label, then invokes
// the receiver-side classifier — the receiver-side WARN MUST still
// emit (its own bucket is fresh). Locks in the non-starvation contract
// from spec §"WARN rate-limit (both classifier_bypass paths)": a
// bursty caller on one path cannot silence the other path's diagnostic.
func TestReceiver_PerPathLimiterNotStarvedByMetricsSide(t *testing.T) {
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	c := metrics.New()
	m := c.WTP()

	// Drain the METRICS-side bucket via the metrics-side WARN path.
	m.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason("drain-token-1"))
	m.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason("drain-token-2"))

	// Receiver-side classifier must still emit its own WARN — its
	// bucket is fresh because the two paths use independent limiters.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	bare := fmt.Errorf("%w: synthetic after metrics drain", wtpv1.ErrInvalidFrame)
	ClassifyAndIncInvalidFrame(logger, m, bare)

	if buf.Len() == 0 {
		t.Error("receiver-side WARN was suppressed after metrics-side drain — limiters are not per-path")
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 3 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 3 (2 metrics drains + 1 receiver call — counter must be unconditional)", got)
	}
}

// TestReceiver_TypedValidationErrorClassifiedByReason verifies the
// happy path: a *wtpv1.ValidationError is classified under its
// canonical Reason, no WARN is logged, and the counter increments
// exactly once for that reason.
func TestReceiver_TypedValidationErrorClassifiedByReason(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := metrics.New()
	m := c.WTP()

	typed := &wtpv1.ValidationError{
		Reason: wtpv1.ReasonPayloadTooLarge,
		Inner:  fmt.Errorf("%w: 32MiB > 8MiB cap", wtpv1.ErrPayloadTooLarge),
	}

	ClassifyAndIncInvalidFrame(logger, m, typed)

	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonPayloadTooLarge); got != 1 {
		t.Errorf("DroppedInvalidFrame(payload_too_large) = %d, want 1", got)
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 0 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 0 on typed path", got)
	}

	if buf.Len() != 0 {
		t.Errorf("expected no WARN log on typed path, got:\n%s", buf.String())
	}
}

// TestReceiver_UnknownReasonClassifiedAsUnknown verifies the validator
// forward-compat reason (`unknown`, emitted by the unknown-oneof
// default branch) flows through as `reason="unknown"` — distinct from
// `classifier_bypass`.
func TestReceiver_UnknownReasonClassifiedAsUnknown(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := metrics.New()
	m := c.WTP()

	typed := &wtpv1.ValidationError{
		Reason: wtpv1.ReasonUnknown,
		Inner:  fmt.Errorf("%w: synthetic unknown oneof", wtpv1.ErrInvalidFrame),
	}

	ClassifyAndIncInvalidFrame(logger, m, typed)

	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonUnknown); got != 1 {
		t.Errorf("DroppedInvalidFrame(unknown) = %d, want 1", got)
	}
	if got := m.DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != 0 {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want 0 (disjoint reasons)", got)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no WARN on validator-emitted unknown reason, got:\n%s", buf.String())
	}

	// Sanity: errors.As still surfaces the typed wrapper.
	var ve *wtpv1.ValidationError
	if !errors.As(typed, &ve) {
		t.Fatal("errors.As failed on typed *ValidationError")
	}
	if ve.Reason != wtpv1.ReasonUnknown {
		t.Errorf("Reason = %q, want %q", ve.Reason, wtpv1.ReasonUnknown)
	}
}
