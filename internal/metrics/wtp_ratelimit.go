package metrics

import (
	"time"

	"golang.org/x/time/rate"
)

// classifierBypassLimiter is the SHARED package-level token bucket used by
// BOTH classifier_bypass WARN paths:
//   - the metrics-side `invalid invalid-frame reason label` WARN emitted
//     by IncDroppedInvalidFrame when a caller passes an invalid label;
//   - the receiver-side `non-typed frame validation error` WARN emitted
//     by transport.classifyAndIncInvalidFrame's defense-in-depth guard
//     (Task 17 Step 4a).
//
// Sharing a single bucket between both paths bounds total log volume to
// AT MOST ~10 emissions per minute per process — a single bursty caller
// in either path cannot starve the other path's diagnostic. Rate
// `rate.Every(6*time.Second)` with burst 1 yields ~10/min on average;
// the limiter starts full so the first emission per process burst is
// always allowed (useful diagnostic for genuinely rare misuses while
// preventing a hot-path bug from flooding logs).
//
// The COUNTER (wtp_dropped_invalid_frame_total{reason="classifier_bypass"})
// tracks the true volume regardless of throttling — operators read the
// metric for the rate signal and the (sampled) WARN log for the
// diagnostic discriminator (err_type for the receiver path, raw_reason
// for the metrics path). When the limiter throttles a WARN, the
// suppressed event is NOT counted by any auxiliary "logs dropped"
// metric per spec §"WARN rate-limit (both classifier_bypass paths)".
//
// This rate-limiter applies ONLY to classifier_bypass WARN paths. Other
// validator-emitted-reason WARN logs follow the existing per-frame
// logging contract (those are gated by reconnect/Goaway, so log volume
// is bounded by the peer disconnecting).
var classifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)

// AllowClassifierBypassWARN returns true if a classifier_bypass WARN
// MAY be emitted now (the limiter has a token), false if the caller
// should suppress this WARN. The caller MUST still increment the
// wtp_dropped_invalid_frame_total{reason="classifier_bypass"} counter
// regardless of the return value — the metric is the canonical volume
// signal; the WARN is sampled diagnostic.
func AllowClassifierBypassWARN() bool {
	return classifierBypassLimiter.Allow()
}

// ResetClassifierBypassLimiterForTest resets the shared classifier-bypass
// rate-limiter to a fresh full-bucket state. Test-only — the "ForTest"
// suffix is the canonical Go convention signalling test-only intent.
// NEVER invoke from production code paths.
//
// Rationale: the limiter is a package-level singleton (so both WARN
// paths share one bucket per the rate-limit contract). Tests that
// assert rate-limit behavior MUST start from a known-fresh bucket;
// without this hook, a prior test that drained the bucket would make
// rate-limit assertions order-dependent. Callers MUST invoke this at
// test start AND register it via t.Cleanup so subsequent tests
// inherit a fresh bucket.
func ResetClassifierBypassLimiterForTest() {
	classifierBypassLimiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
}
