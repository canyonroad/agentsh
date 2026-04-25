package transport

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// TestEncodeBatchMessage_RecordLossErrorsLoud asserts the encoder refuses
// to silently strip a wal.RecordLoss marker. Replayer.NextBatch
// (replayer.go) and Reader.TryNext (wal/reader.go) both surface loss
// markers verbatim, and the spec's TransportLoss carrier (Task 13) is
// the only sanctioned route to the server. A silent strip would be an
// integrity gap — WAL overflow / CRC-corruption notices the server relies
// on would never land — so encodeBatchMessage MUST fail loud here.
// Roborev #6089 (High): the prior implementation skipped non-RecordData
// records, masking loss markers across Live, Replaying, and Shutdown
// callers; this regression test pins the corrected fail-loud contract.
func TestEncodeBatchMessage_RecordLossErrorsLoud(t *testing.T) {
	t.Run("loss-only batch errors", func(t *testing.T) {
		records := []wal.Record{
			{Kind: wal.RecordLoss, Generation: 7},
		}
		msg, err := encodeBatchMessage(records)
		if err == nil {
			t.Fatalf("encodeBatchMessage(loss-only): expected error, got msg=%v", msg)
		}
		if !strings.Contains(err.Error(), "RecordLoss") {
			t.Fatalf("encodeBatchMessage(loss-only): error must mention RecordLoss, got %v", err)
		}
	})

	t.Run("mixed data+loss batch errors before encoding partial events", func(t *testing.T) {
		// Loss marker after one valid data record. The encoder must
		// refuse the whole batch rather than emit the data record and
		// drop the marker — the server-side ordering invariant requires
		// the marker to be observed alongside the data, not stripped.
		records := []wal.Record{
			{Kind: wal.RecordData, Sequence: 1, Generation: 7, Payload: nil},
			{Kind: wal.RecordLoss, Generation: 7},
		}
		msg, err := encodeBatchMessage(records)
		if err == nil {
			t.Fatalf("encodeBatchMessage(mixed): expected error, got msg=%v", msg)
		}
		if !strings.Contains(err.Error(), "RecordLoss") {
			t.Fatalf("encodeBatchMessage(mixed): error must mention RecordLoss, got %v", err)
		}
	})
}
