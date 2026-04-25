package transport

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

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
	msg, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encodeBatchMessage(data-only): %v", err)
	}
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

// TestEncodeBatchMessage_RecordLossReturnsSentinel pins the terminal-
// on-loss contract. The encoder MUST return ErrRecordLossEncountered
// (errors.Is-detectable) for any input that contains a wal.RecordLoss,
// because the dedicated TransportLoss carrier (Task 13) is not yet
// built and silent / retry-able / log-only handling all produce
// documented integrity regressions (roborev #6089 / #6095 / #6099).
// Callers in runLive / runReplaying translate the sentinel into a
// StateShutdown transition; the Run loop propagates that error out,
// latching the Store fatal.
func TestEncodeBatchMessage_RecordLossReturnsSentinel(t *testing.T) {
	t.Run("loss-only batch", func(t *testing.T) {
		records := []wal.Record{
			{Kind: wal.RecordLoss, Generation: 7},
		}
		msg, err := encodeBatchMessage(records)
		if err == nil {
			t.Fatalf("expected error, got msg=%v", msg)
		}
		if !errors.Is(err, ErrRecordLossEncountered) {
			t.Fatalf("error must be ErrRecordLossEncountered, got %v", err)
		}
	})

	t.Run("mixed data+loss batch", func(t *testing.T) {
		records := []wal.Record{
			{Kind: wal.RecordData, Sequence: 1, Generation: 7, Payload: nil},
			{Kind: wal.RecordLoss, Generation: 7},
		}
		msg, err := encodeBatchMessage(records)
		if err == nil {
			t.Fatalf("expected error, got msg=%v", msg)
		}
		if !errors.Is(err, ErrRecordLossEncountered) {
			t.Fatalf("error must be ErrRecordLossEncountered, got %v", err)
		}
	})
}
