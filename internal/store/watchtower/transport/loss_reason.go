package transport

import (
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ToWireReason maps an in-WAL wal.LossRecord.Reason string to its wire
// enum value. Returns (UNSPECIFIED, false) for unknown strings — the
// caller MUST treat false as a programming error: log ERROR, increment
// metrics.IncWTPLossUnknownReason, drop the marker. Never send
// UNSPECIFIED on the wire (it is wire-incompatible per the proto's
// TRANSPORT_LOSS_REASON_UNSPECIFIED contract).
//
// CI test (loss_reason_exhaustiveness_test.go, plan Task 6) verifies one
// entry here per wal.LossReason* constant, AST-walking the wal package
// source to catch a missing case at build time.
func ToWireReason(s string) (wtpv1.TransportLossReason, bool) {
	switch s {
	case wal.LossReasonOverflow:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW, true
	case wal.LossReasonCRCCorruption:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION, true
	case wal.LossReasonAckRegressionAfterGC:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC, true
	case wal.LossReasonMapperFailure:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE, true
	case wal.LossReasonInvalidMapper:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER, true
	case wal.LossReasonInvalidTimestamp:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP, true
	case wal.LossReasonInvalidUTF8:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8, true
	case wal.LossReasonSequenceOverflow:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW, true
	default:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED, false
	}
}
