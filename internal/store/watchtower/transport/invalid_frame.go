package transport

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/metrics"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ClassifyAndIncInvalidFrame is the canonical receiver-side wrapper for
// a validator failure. It implements the two-step classification from
// spec §"Frame validation and forward compatibility":
//
//  1. errors.As against *wtpv1.ValidationError. If true, increment
//     wtp_dropped_invalid_frame_total{reason=string(ve.Reason)} via the
//     proto-side canonical reason string.
//  2. Defense-in-depth fallback: if errors.As returns false, classify
//     under reason="classifier_bypass" (NOT "unknown" — those are
//     disjoint reasons; see spec §"Operator runbook: invalid-frame
//     reason interpretation"). Emit a WARN carrying err_type so
//     operators paged on classifier_bypass can identify the offending
//     non-validator caller.
//
// Every receiver site that calls ValidateEventBatch / ValidateSessionInit
// on an inbound frame MUST route the non-nil error through this helper
// instead of stamping the counter directly; the helper is the single
// enforcement point for the validator-returns-*ValidationError contract.
//
// The validator contract guarantees every failure path returns a
// *ValidationError, so the classifier_bypass branch SHOULD never trigger
// in production — any non-zero increment is a local-side caller bug
// (non-validator error reached the receiver-side classifier).
//
// Exported so callers outside the transport package (notably the
// testserver's EventBatch receive path) can route validator failures
// through the single canonical classifier. Any client-owned or server-
// owned receive site that calls ValidateEventBatch / ValidateSessionInit
// MUST call this helper on the non-nil error.
func ClassifyAndIncInvalidFrame(logger *slog.Logger, m Metrics, err error) {
	var ve *wtpv1.ValidationError
	if !errors.As(err, &ve) {
		// Rate-limited WARN: the counter increments unconditionally (the
		// metric is the canonical volume signal) but the WARN is sampled
		// by the receiver-side classifier_bypass limiter so a hot-path
		// bug cannot flood logs. The metrics-side invalid-label WARN in
		// IncDroppedInvalidFrame has its OWN limiter — per-path budgets
		// prevent one path from starving the other.
		if metrics.AllowReceiverClassifierBypassWARN() {
			logger.Warn("non-typed frame validation error",
				slog.String("err_type", fmt.Sprintf("%T", err)),
				slog.String("reason", string(metrics.WTPInvalidFrameReasonClassifierBypass)))
		}
		m.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReasonClassifierBypass)
		return
	}
	m.IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason(ve.Reason))
}
