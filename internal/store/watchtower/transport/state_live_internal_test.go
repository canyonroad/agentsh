package transport

import (
	"bytes"
	"log/slog"
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

// TestFilterDataRecords pins the pre-Task-13 caller-side filter that
// keeps wal.RecordLoss markers OUT of the encoder so a persisted loss
// marker (overflow GC, CRC corruption recovery) does not turn replay /
// live / shutdown into permanent reconnect loops. Forward progress past
// the marker is the contract Live and Replaying rely on.
//
// Roborev #6095 (High): "Returning an encoder error for every
// wal.RecordLoss turns any persisted loss marker into a permanent
// reconnect loop... the same unsendable marker is retried forever and
// later records never progress." This test captures the corrected
// posture: encoder still fail-loud (above), callers strip + WARN.
func TestFilterDataRecords(t *testing.T) {
	makeData := func(seq uint64) wal.Record {
		return wal.Record{Kind: wal.RecordData, Sequence: seq, Generation: 7}
	}
	makeLoss := func() wal.Record {
		return wal.Record{
			Kind:       wal.RecordLoss,
			Generation: 7,
			Loss:       wal.LossRecord{FromSequence: 5, ToSequence: 9, Generation: 7, Reason: "overflow"},
		}
	}

	t.Run("data-only input passes through unchanged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		in := []wal.Record{makeData(1), makeData(2), makeData(3)}
		out := filterDataRecords(in, logger, "replaying", "s")
		if len(out) != 3 {
			t.Fatalf("expected 3 records, got %d", len(out))
		}
		if buf.Len() != 0 {
			t.Fatalf("expected no log output for data-only input, got %q", buf.String())
		}
	})

	t.Run("mixed data+loss strips loss and emits one WARN per marker", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		in := []wal.Record{makeData(1), makeLoss(), makeData(2), makeLoss(), makeData(3)}
		out := filterDataRecords(in, logger, "replaying", "s-fixture")
		if len(out) != 3 {
			t.Fatalf("expected 3 data records after filter, got %d (full=%v)", len(out), out)
		}
		for _, rec := range out {
			if rec.Kind != wal.RecordData {
				t.Fatalf("filtered slice must contain only RecordData, found Kind=%v", rec.Kind)
			}
		}
		// One WARN per dropped marker.
		warns := strings.Count(buf.String(), "level=WARN")
		if warns != 2 {
			t.Fatalf("expected 2 WARN entries, got %d in %q", warns, buf.String())
		}
		// Triage attrs must be present.
		if !strings.Contains(buf.String(), "caller_state=replaying") {
			t.Fatalf("missing caller_state attr: %q", buf.String())
		}
		if !strings.Contains(buf.String(), "session_id=s-fixture") {
			t.Fatalf("missing session_id attr: %q", buf.String())
		}
		if !strings.Contains(buf.String(), "loss_reason=overflow") {
			t.Fatalf("missing loss_reason attr: %q", buf.String())
		}
	})

	t.Run("loss-only input returns empty slice + WARN", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		in := []wal.Record{makeLoss()}
		out := filterDataRecords(in, logger, "live", "s")
		if len(out) != 0 {
			t.Fatalf("expected 0 records, got %d", len(out))
		}
		if !strings.Contains(buf.String(), "caller_state=live") {
			t.Fatalf("missing caller_state attr: %q", buf.String())
		}
	})
}
