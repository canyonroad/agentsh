// Package: metrics_test (external) — DO NOT change to package metrics or
// merge into wtp_test.go. The parity test MUST live in an external test
// package because it consumes BOTH metrics.* and wtpv1.* exported APIs;
// the existing internal/metrics/wtp_test.go is package metrics, which
// cannot use the metrics.* qualifier.
package metrics_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/metrics"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestWTPInvalidFrameReason_ParityWithValidator locks the metrics-side
// WTPInvalidFrameReason constants to the proto-side wtpv1.ValidationReason
// constants. The two enums are intentionally duplicated (metrics MUST NOT
// import the proto package) but the string values for validator-emitted
// reasons MUST stay byte-equal so receivers can do
// metrics.WTPInvalidFrameReason(ve.Reason) safely. The metrics-only
// decompress_error and classifier_bypass reasons are intentionally NOT
// mirrored on the proto side (the former is emitted post-validator by
// streaming decompression; the latter is emitted only by the receiver-
// side defense-in-depth fallback and by the metrics-side invalid-label
// collapse, neither of which has a validator counterpart by definition).
//
// Adding a new reason in either package without the other will fail this
// test with a precise actionable message.
func TestWTPInvalidFrameReason_ParityWithValidator(t *testing.T) {
	// Per-package dedup guards. The cross-package length/set checks
	// below would silently accept a same-value alias added to BOTH
	// sides in lock-step (e.g., two metrics-side constants pointing
	// at "payload_too_large" alongside two proto-side constants at
	// the same string). Catch that class of drift up front by
	// asserting each package's slice is already deduplicated before
	// comparing across packages.
	validatorSlice := wtpv1.AllValidationReasons()
	validatorDedup := make(map[wtpv1.ValidationReason]struct{}, len(validatorSlice))
	for _, r := range validatorSlice {
		if _, dup := validatorDedup[r]; dup {
			t.Errorf("wtpv1.AllValidationReasons() contains duplicate reason %q — aliases are forbidden (see proto/canyonroad/wtp/v1/validate.go)", r)
		}
		validatorDedup[r] = struct{}{}
	}
	metricsSlice := metrics.ValidationReasons()
	metricsDedup := make(map[metrics.WTPInvalidFrameReason]struct{}, len(metricsSlice))
	for _, r := range metricsSlice {
		if _, dup := metricsDedup[r]; dup {
			t.Errorf("metrics.ValidationReasons() contains duplicate reason %q — aliases are forbidden (see internal/metrics/wtp.go)", r)
		}
		metricsDedup[r] = struct{}{}
	}
	metricsOnlySlice := metrics.MetricsOnlyReasons()
	metricsOnlyDedup := make(map[metrics.WTPInvalidFrameReason]struct{}, len(metricsOnlySlice))
	for _, r := range metricsOnlySlice {
		if _, dup := metricsOnlyDedup[r]; dup {
			t.Errorf("metrics.MetricsOnlyReasons() contains duplicate reason %q — aliases are forbidden (see internal/metrics/wtp.go)", r)
		}
		metricsOnlyDedup[r] = struct{}{}
	}

	validatorAll := validatorDedup
	metricsShared := metricsDedup

	// Length equality catches alias duplication (multiple constants
	// pointing at one string value) that a map-based dedupe would
	// silently mask. Either side gaining an alias fails the test.
	if got, want := len(wtpv1.AllValidationReasons()), len(metrics.ValidationReasons()); got != want {
		t.Errorf("len(wtpv1.AllValidationReasons())=%d vs len(metrics.ValidationReasons())=%d — alias duplication or drift between proto/canyonroad/wtp/v1/validate.go and internal/metrics/wtp.go", got, want)
	}

	// 1. Forward: every validator reason must have a metrics constant in the shared set.
	for r := range validatorAll {
		if _, ok := metricsShared[metrics.WTPInvalidFrameReason(string(r))]; !ok {
			t.Errorf("metrics package is missing WTPInvalidFrameReason constant for validator reason %q; add the constant to internal/metrics/wtp.go and append it to wtpInvalidFrameReasonsValid + wtpInvalidFrameReasonsEmitOrder + validationReasonsShared (returned by ValidationReasons())",
				r)
		}
	}

	// 2. Reverse: every metrics shared reason must have a validator constant.
	for r := range metricsShared {
		if _, ok := validatorAll[wtpv1.ValidationReason(string(r))]; !ok {
			t.Errorf("validator package is missing ValidationReason constant for metrics reason %q; add the constant to proto/canyonroad/wtp/v1/validate.go and append it to allValidationReasons (returned by AllValidationReasons())",
				r)
		}
	}

	// 3. Disjoint: metrics-only reasons MUST NOT appear on the validator side.
	for _, r := range metrics.MetricsOnlyReasons() {
		if _, ok := validatorAll[wtpv1.ValidationReason(string(r))]; ok {
			t.Errorf("metrics-only reason %q accidentally appears in wtpv1.AllValidationReasons() — the design contract is that classifier_bypass and decompress_error have NO proto-side counterpart; remove it from proto/canyonroad/wtp/v1/validate.go's allValidationReasons or remove it from internal/metrics/wtp.go's MetricsOnlyReasons() (whichever was added in error)",
				r)
		}
	}

	// 4. Coverage: shared ∪ metrics-only MUST equal the full valid (always-emit) set.
	covered := make(map[metrics.WTPInvalidFrameReason]struct{})
	for r := range metricsShared {
		covered[r] = struct{}{}
	}
	for _, r := range metrics.MetricsOnlyReasons() {
		covered[r] = struct{}{}
	}
	valid := metrics.ValidWTPInvalidFrameReasons()
	for r := range valid {
		if _, ok := covered[r]; !ok {
			t.Errorf("metrics constant %q is in ValidWTPInvalidFrameReasons() but in NEITHER ValidationReasons() NOR MetricsOnlyReasons(); add it to one of those getters in internal/metrics/wtp.go so the parity test can classify it",
				r)
		}
	}
	for r := range covered {
		if _, ok := valid[r]; !ok {
			t.Errorf("metrics constant %q appears in ValidationReasons() or MetricsOnlyReasons() but is NOT in ValidWTPInvalidFrameReasons() (the always-emit set); add it to wtpInvalidFrameReasonsValid in internal/metrics/wtp.go so it is registered for emit",
				r)
		}
	}
}

// TestClassifierBypassWARN_RateLimited verifies that the shared
// classifierBypassLimiter caps WARN log emissions at ~10/min while the
// counter still tracks true volume. Pumps 100 invalid-label calls in a
// tight loop and asserts: the counter increments exactly 100 times; the
// WARN log captures AT MOST 11 entries (10 steady-state + 1 initial
// burst); the first emission per burst always lands (token bucket
// starts full).
func TestClassifierBypassWARN_RateLimited(t *testing.T) {
	metrics.ResetClassifierBypassLimiterForTest()
	t.Cleanup(metrics.ResetClassifierBypassLimiterForTest)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := metrics.New()
	const burst = 100
	for i := 0; i < burst; i++ {
		c.WTP().IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason("not-a-canonical-reason"))
	}

	if got := c.WTP().DroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass); got != burst {
		t.Errorf("DroppedInvalidFrame(classifier_bypass) = %d, want %d (counter MUST track true volume regardless of WARN throttling)", got, burst)
	}

	logged := 0
	if buf.Len() > 0 {
		logged = strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") + 1
	}
	if logged > 11 {
		t.Errorf("WARN log emitted %d entries for %d invalid-label calls — rate-limiter failed to throttle (expected ≤11)", logged, burst)
	}
	if logged < 1 {
		t.Errorf("WARN log emitted %d entries — first emission per burst MUST be allowed (token bucket starts full)", logged)
	}
}
