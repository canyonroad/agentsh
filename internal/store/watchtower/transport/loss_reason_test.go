package transport

import (
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func TestToWireReason_MapsKnownConstants(t *testing.T) {
	cases := []struct {
		in   string
		want wtpv1.TransportLossReason
	}{
		{wal.LossReasonOverflow, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW},
		{wal.LossReasonCRCCorruption, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION},
		{wal.LossReasonAckRegressionAfterGC, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC},
		{wal.LossReasonMapperFailure, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE},
		{wal.LossReasonInvalidMapper, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER},
		{wal.LossReasonInvalidTimestamp, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP},
		{wal.LossReasonInvalidUTF8, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8},
		{wal.LossReasonSequenceOverflow, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ToWireReason(tc.in)
			if !ok {
				t.Fatalf("ToWireReason(%q) ok=false; want true", tc.in)
			}
			if got != tc.want {
				t.Fatalf("ToWireReason(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestToWireReason_UnknownReturnsFalseAndUnspecified(t *testing.T) {
	got, ok := ToWireReason("not-a-known-reason")
	if ok {
		t.Fatalf("ToWireReason(unknown) ok=true; want false")
	}
	if got != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED {
		t.Fatalf("ToWireReason(unknown) = %v, want UNSPECIFIED", got)
	}
}

func TestToWireReason_NeverReturnsUnspecifiedForKnownConstants(t *testing.T) {
	known := []string{
		wal.LossReasonOverflow,
		wal.LossReasonCRCCorruption,
		wal.LossReasonAckRegressionAfterGC,
		wal.LossReasonMapperFailure,
		wal.LossReasonInvalidMapper,
		wal.LossReasonInvalidTimestamp,
		wal.LossReasonInvalidUTF8,
		wal.LossReasonSequenceOverflow,
	}
	for _, r := range known {
		got, ok := ToWireReason(r)
		if !ok {
			t.Errorf("ToWireReason(%q) ok=false", r)
			continue
		}
		if got == wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED {
			t.Errorf("ToWireReason(%q) returned UNSPECIFIED — would emit wire-incompatible frame", r)
		}
	}
}
