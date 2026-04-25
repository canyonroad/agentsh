package metrics

import (
	"time"

	"golang.org/x/time/rate"
)

// The classifier_bypass WARN paths use PER-PATH token buckets (not one
// shared bucket) so a bursty caller on one path cannot starve the other
// path's diagnostic. The two emit sites are:
//
//   - metrics-side: IncDroppedInvalidFrame's invalid-label collapse
//     (caller passed a reason label outside the WTPInvalidFrameReason
//     enum).
//   - receiver-side: transport.classifyAndIncInvalidFrame's
//     defense-in-depth guard (caller passed a non-*ValidationError into
//     the receiver-side classifier).
//
// Per-path budgets trade a slightly higher TOTAL WARN ceiling (~20/min
// across both paths instead of ~10) for a guarantee that each path
// always surfaces at least one WARN per its own six-second interval
// regardless of how bursty the other path is. Operators paged on a
// classifier_bypass counter spike will see the diagnostic for the
// responsible path even during a same-incident burst on the other path.
//
// Rate `rate.Every(6*time.Second)` with burst 1 yields ~10/min on
// average per path; each limiter starts full so the first emission per
// path burst is always allowed. The COUNTER
// (wtp_dropped_invalid_frame_total{reason="classifier_bypass"}) tracks
// true volume across BOTH paths regardless of WARN throttling —
// operators read the metric for the rate signal and the sampled WARN
// for the discriminator (raw_reason for metrics, err_type for receiver).
//
// This rate-limiter applies ONLY to classifier_bypass WARN paths. Other
// validator-emitted-reason WARN logs follow the existing per-frame
// logging contract (those are gated by reconnect/Goaway, so log volume
// is bounded by the peer disconnecting).
var (
	metricsClassifierBypassLimiter  = rate.NewLimiter(rate.Every(6*time.Second), 1)
	receiverClassifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
)

// AllowMetricsClassifierBypassWARN returns true if the metrics-side
// `invalid invalid-frame reason label` WARN MAY be emitted now. It
// consults the METRICS-side per-path limiter; receiver-side traffic
// draws from a different bucket and cannot starve this one. Callers
// MUST still increment
// wtp_dropped_invalid_frame_total{reason="classifier_bypass"}
// regardless of the return value.
func AllowMetricsClassifierBypassWARN() bool {
	return metricsClassifierBypassLimiter.Allow()
}

// AllowReceiverClassifierBypassWARN returns true if the receiver-side
// `non-typed frame validation error` WARN MAY be emitted now. It
// consults the RECEIVER-side per-path limiter; metrics-side traffic
// draws from a different bucket and cannot starve this one. Callers
// MUST still increment
// wtp_dropped_invalid_frame_total{reason="classifier_bypass"}
// regardless of the return value.
func AllowReceiverClassifierBypassWARN() bool {
	return receiverClassifierBypassLimiter.Allow()
}

// ResetClassifierBypassLimiterForTest resets BOTH per-path classifier-
// bypass limiters to a fresh full-bucket state. Test-only — the
// "ForTest" suffix is the canonical Go convention. NEVER invoke from
// production code paths.
//
// Tests that assert rate-limit behavior MUST start from known-fresh
// buckets; without this hook, prior tests that drained either bucket
// would make assertions order-dependent. Callers MUST invoke this at
// test start AND register it via t.Cleanup so subsequent tests inherit
// fresh buckets.
func ResetClassifierBypassLimiterForTest() {
	metricsClassifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
	receiverClassifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
}
