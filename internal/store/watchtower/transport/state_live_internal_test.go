package transport

import (
	"testing"

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// marshalCompactEvent marshals a minimal CompactEvent with the given sequence
// into bytes suitable for wal.Record.Payload.
func marshalCompactEvent(t *testing.T, seq uint64) []byte {
	t.Helper()
	ce := &wtpv1.CompactEvent{
		Sequence:           seq,
		Generation:         1,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
	}
	b, err := proto.Marshal(ce)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestEncodeBatchMessage_HappyPathDataRecords pins the production
// encoder's data-record handling: every wal.RecordData in the input
// must round-trip into the UncompressedEvents body, and the batch
// envelope's from_sequence / to_sequence / generation must reflect the
// first and last data record. Regression for roborev #6126 ("the
// reverted encoder now returns an empty ClientMessage for every batch")
// — the production wiring is not a stub and store-level tests rely on
// real EventBatch traffic reaching the server.
func TestEncodeBatchMessage_HappyPathDataRecords(t *testing.T) {
	mkEvent := func(seq uint64) ([]byte, *wtpv1.CompactEvent) {
		ev := &wtpv1.CompactEvent{Sequence: seq, Generation: 3}
		raw, err := proto.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal CompactEvent seq=%d: %v", seq, err)
		}
		return raw, ev
	}
	pay1, _ := mkEvent(11)
	pay2, _ := mkEvent(12)
	pay3, _ := mkEvent(13)
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 11, Generation: 3, Payload: pay1},
		{Kind: wal.RecordData, Sequence: 12, Generation: 3, Payload: pay2},
		{Kind: wal.RecordData, Sequence: 13, Generation: 3, Payload: pay3},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encodeBatchMessage(data-only): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("encodeBatchMessage: got %d messages, want 1", len(msgs))
	}
	msg := msgs[0]
	eb := msg.GetEventBatch()
	if eb == nil {
		t.Fatalf("encodeBatchMessage: ClientMessage carries no EventBatch")
	}
	if eb.GetFromSequence() != 11 {
		t.Fatalf("from_sequence=%d, want 11", eb.GetFromSequence())
	}
	if eb.GetToSequence() != 13 {
		t.Fatalf("to_sequence=%d, want 13", eb.GetToSequence())
	}
	if eb.GetGeneration() != 3 {
		t.Fatalf("generation=%d, want 3", eb.GetGeneration())
	}
	if eb.GetCompression() != wtpv1.Compression_COMPRESSION_NONE {
		t.Fatalf("compression=%v, want COMPRESSION_NONE", eb.GetCompression())
	}
	body := eb.GetUncompressed()
	if body == nil {
		t.Fatalf("encodeBatchMessage: EventBatch carries no UncompressedEvents body")
	}
	if got := len(body.GetEvents()); got != 3 {
		t.Fatalf("UncompressedEvents.Events len=%d, want 3", got)
	}
	for i, want := range []uint64{11, 12, 13} {
		if got := body.GetEvents()[i].GetSequence(); got != want {
			t.Fatalf("event[%d].Sequence=%d, want %d", i, got, want)
		}
	}
}

// TestEncodeBatchMessage_DataOnly_OneFrame verifies that a pure data run
// produces a single EventBatch with correct from/to boundaries.
func TestEncodeBatchMessage_DataOnly_OneFrame(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 10, Generation: 1, Payload: marshalCompactEvent(t, 10)},
		{Kind: wal.RecordData, Sequence: 11, Generation: 1, Payload: marshalCompactEvent(t, 11)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	eb := msgs[0].GetEventBatch()
	if eb == nil {
		t.Fatal("expected EventBatch, got nil")
	}
	if eb.GetFromSequence() != 10 {
		t.Fatalf("from_sequence=%d, want 10", eb.GetFromSequence())
	}
	if eb.GetToSequence() != 11 {
		t.Fatalf("to_sequence=%d, want 11", eb.GetToSequence())
	}
}

// TestEncodeBatchMessage_LossOnly_OneFrame verifies that a single loss marker
// produces a single TransportLoss frame with the correct reason.
func TestEncodeBatchMessage_LossOnly_OneFrame(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5,
			ToSequence:   5,
			Generation:   1,
			Reason:       wal.LossReasonOverflow,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	tl := msgs[0].GetTransportLoss()
	if tl == nil {
		t.Fatal("expected TransportLoss, got nil")
	}
	if tl.GetFromSequence() != 5 {
		t.Fatalf("from_sequence=%d, want 5", tl.GetFromSequence())
	}
	if tl.GetToSequence() != 5 {
		t.Fatalf("to_sequence=%d, want 5", tl.GetToSequence())
	}
	if tl.GetReason() != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW {
		t.Fatalf("reason=%v, want OVERFLOW", tl.GetReason())
	}
}

// TestEncodeBatchMessage_DataLossData_ThreeFrames verifies that
// [data:10, loss:11, data:12] produces three frames in order:
// EventBatch, TransportLoss, EventBatch.
func TestEncodeBatchMessage_DataLossData_ThreeFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 10, Generation: 1, Payload: marshalCompactEvent(t, 10)},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 11, ToSequence: 11, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
		{Kind: wal.RecordData, Sequence: 12, Generation: 1, Payload: marshalCompactEvent(t, 12)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d messages, want 3", len(msgs))
	}
	if msgs[0].GetEventBatch() == nil {
		t.Fatalf("msgs[0]: expected EventBatch, got %T", msgs[0].Msg)
	}
	if msgs[1].GetTransportLoss() == nil {
		t.Fatalf("msgs[1]: expected TransportLoss, got %T", msgs[1].Msg)
	}
	if msgs[2].GetEventBatch() == nil {
		t.Fatalf("msgs[2]: expected EventBatch, got %T", msgs[2].Msg)
	}
	if msgs[0].GetEventBatch().GetFromSequence() != 10 || msgs[0].GetEventBatch().GetToSequence() != 10 {
		t.Fatalf("msgs[0] EventBatch: from=%d to=%d, want 10/10",
			msgs[0].GetEventBatch().GetFromSequence(), msgs[0].GetEventBatch().GetToSequence())
	}
	if msgs[2].GetEventBatch().GetFromSequence() != 12 || msgs[2].GetEventBatch().GetToSequence() != 12 {
		t.Fatalf("msgs[2] EventBatch: from=%d to=%d, want 12/12",
			msgs[2].GetEventBatch().GetFromSequence(), msgs[2].GetEventBatch().GetToSequence())
	}
}

// TestEncodeBatchMessage_LeadingLoss_TwoFrames verifies [loss:5, data:6]
// → 2 frames: TransportLoss then EventBatch.
func TestEncodeBatchMessage_LeadingLoss_TwoFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5, ToSequence: 5, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
		{Kind: wal.RecordData, Sequence: 6, Generation: 1, Payload: marshalCompactEvent(t, 6)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].GetTransportLoss() == nil {
		t.Fatalf("msgs[0]: expected TransportLoss, got %T", msgs[0].Msg)
	}
	if msgs[1].GetEventBatch() == nil {
		t.Fatalf("msgs[1]: expected EventBatch, got %T", msgs[1].Msg)
	}
}

// TestEncodeBatchMessage_TrailingLoss_TwoFrames verifies [data:6, loss:7]
// → 2 frames: EventBatch then TransportLoss.
func TestEncodeBatchMessage_TrailingLoss_TwoFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 6, Generation: 1, Payload: marshalCompactEvent(t, 6)},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 7, ToSequence: 7, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].GetEventBatch() == nil {
		t.Fatalf("msgs[0]: expected EventBatch, got %T", msgs[0].Msg)
	}
	if msgs[1].GetTransportLoss() == nil {
		t.Fatalf("msgs[1]: expected TransportLoss, got %T", msgs[1].Msg)
	}
}

// TestEncodeBatchMessage_ConsecutiveLosses_SeparateFrames verifies
// [loss:5, loss:6] → 2 separate TransportLoss frames (no coalescing).
func TestEncodeBatchMessage_ConsecutiveLosses_SeparateFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5, ToSequence: 5, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 6, ToSequence: 6, Generation: 1, Reason: wal.LossReasonCRCCorruption,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].GetTransportLoss() == nil {
		t.Fatalf("msgs[0]: expected TransportLoss")
	}
	if msgs[1].GetTransportLoss() == nil {
		t.Fatalf("msgs[1]: expected TransportLoss")
	}
	if msgs[0].GetTransportLoss().GetFromSequence() != 5 {
		t.Fatalf("msgs[0] from_sequence=%d, want 5", msgs[0].GetTransportLoss().GetFromSequence())
	}
	if msgs[1].GetTransportLoss().GetFromSequence() != 6 {
		t.Fatalf("msgs[1] from_sequence=%d, want 6", msgs[1].GetTransportLoss().GetFromSequence())
	}
}

// TestEncodeBatchMessage_UnknownReason_DropsMarkerIncrementsCounter verifies
// that a loss marker with an unrecognized Reason string is silently dropped
// (no TransportLoss frame emitted) and wtp_loss_unknown_reason_total is
// incremented.
func TestEncodeBatchMessage_UnknownReason_DropsMarkerIncrementsCounter(t *testing.T) {
	c := metrics.New()
	prev := encoderMetrics
	encoderMetrics = c.WTP()
	t.Cleanup(func() { encoderMetrics = prev })

	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 1, ToSequence: 1, Generation: 1, Reason: "garbage",
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("got %d messages, want 0 (unknown reason must be dropped)", len(msgs))
	}
	if got := c.WTP().WTPLossUnknownReason(); got != 1 {
		t.Fatalf("wtp_loss_unknown_reason_total=%d, want 1", got)
	}
}

// TestExtractWireHighWatermark_EventBatchAndTransportLoss verifies that
// extractWireHighWatermark returns the correct (gen, to_seq) for both
// EventBatch and TransportLoss frame types.
func TestExtractWireHighWatermark_EventBatchAndTransportLoss(t *testing.T) {
	t.Run("EventBatch", func(t *testing.T) {
		msg := &wtpv1.ClientMessage{
			Msg: &wtpv1.ClientMessage_EventBatch{
				EventBatch: &wtpv1.EventBatch{
					Generation: 3,
					ToSequence: 42,
				},
			},
		}
		gen, seq := extractWireHighWatermark(msg)
		if gen != 3 {
			t.Fatalf("gen=%d, want 3", gen)
		}
		if seq != 42 {
			t.Fatalf("seq=%d, want 42", seq)
		}
	})

	t.Run("TransportLoss", func(t *testing.T) {
		msg := &wtpv1.ClientMessage{
			Msg: &wtpv1.ClientMessage_TransportLoss{
				TransportLoss: &wtpv1.TransportLoss{
					Generation: 7,
					ToSequence: 99,
				},
			},
		}
		gen, seq := extractWireHighWatermark(msg)
		if gen != 7 {
			t.Fatalf("gen=%d, want 7", gen)
		}
		if seq != 99 {
			t.Fatalf("seq=%d, want 99", seq)
		}
	})

	t.Run("UnknownType", func(t *testing.T) {
		msg := &wtpv1.ClientMessage{}
		gen, seq := extractWireHighWatermark(msg)
		if gen != 0 || seq != 0 {
			t.Fatalf("unknown type: got gen=%d seq=%d, want 0/0", gen, seq)
		}
	})
}

