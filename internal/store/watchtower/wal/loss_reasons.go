package wal

// LossRecord.Reason strings. These are written byte-for-byte to disk
// inside the loss-marker payload (encodeLossPayload), so changing any
// value is an on-disk-format break. New reasons are additive.
//
// Wire-side mapping lives in
// internal/store/watchtower/transport/loss_reason.go (ToWireReason).
const (
	LossReasonOverflow             = "overflow"
	LossReasonCRCCorruption        = "crc_corruption"
	LossReasonAckRegressionAfterGC = "ack_regression_after_gc"

	// Extended (2026-04-27 spec) — emitted only when
	// EmitExtendedLossReasons is on at the producer site.
	LossReasonMapperFailure    = "mapper_failure"
	LossReasonInvalidMapper    = "invalid_mapper"
	LossReasonInvalidTimestamp = "invalid_timestamp"
	LossReasonInvalidUTF8      = "invalid_utf8"
	LossReasonSequenceOverflow = "sequence_overflow"
)
