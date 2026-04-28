package transport

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport/compress"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

func dataRecordForCompressTest(t *testing.T, seq uint64, gen uint32) wal.Record {
	t.Helper()
	ce := &wtpv1.CompactEvent{Sequence: seq, Generation: gen}
	b, err := proto.Marshal(ce)
	if err != nil {
		t.Fatalf("marshal CompactEvent: %v", err)
	}
	return wal.Record{Kind: wal.RecordData, Sequence: seq, Generation: gen, Payload: b}
}

func TestEncodeBatchMessage_NoneEncoderEmitsUncompressed(t *testing.T) {
	enc, _ := compress.NewEncoder("none", 0, 0)
	msgs, err := encodeBatchMessageWithCompressor([]wal.Record{
		dataRecordForCompressTest(t, 1, 1),
		dataRecordForCompressTest(t, 2, 1),
	}, false, enc, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 msg, got %d", len(msgs))
	}
	eb := msgs[0].GetEventBatch()
	if eb.GetCompression() != wtpv1.Compression_COMPRESSION_NONE {
		t.Fatalf("Compression = %v, want NONE", eb.GetCompression())
	}
	if eb.GetUncompressed() == nil {
		t.Fatal("body = nil; want UncompressedEvents")
	}
}

func TestEncodeBatchMessage_ZstdEmitsCompressedPayload(t *testing.T) {
	enc, err := compress.NewEncoder("zstd", 3, 0)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	msgs, err := encodeBatchMessageWithCompressor([]wal.Record{
		dataRecordForCompressTest(t, 1, 1),
		dataRecordForCompressTest(t, 2, 1),
		dataRecordForCompressTest(t, 3, 1),
	}, false, enc, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 msg, got %d", len(msgs))
	}
	eb := msgs[0].GetEventBatch()
	if eb.GetCompression() != wtpv1.Compression_COMPRESSION_ZSTD {
		t.Fatalf("Compression = %v, want ZSTD", eb.GetCompression())
	}
	if eb.GetCompressedPayload() == nil {
		t.Fatal("compressed_payload = nil")
	}
	if eb.GetUncompressed() != nil {
		t.Fatal("body should be CompressedPayload, not UncompressedEvents")
	}
}

func TestEncodeBatchMessage_GzipEmitsCompressedPayload(t *testing.T) {
	enc, err := compress.NewEncoder("gzip", 0, 6)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	msgs, err := encodeBatchMessageWithCompressor([]wal.Record{
		dataRecordForCompressTest(t, 1, 1),
	}, false, enc, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	eb := msgs[0].GetEventBatch()
	if eb.GetCompression() != wtpv1.Compression_COMPRESSION_GZIP {
		t.Fatalf("Compression = %v, want GZIP", eb.GetCompression())
	}
	if eb.GetCompressedPayload() == nil {
		t.Fatal("compressed_payload = nil")
	}
}

// failingEncoder always errors. Used to drive the fail-open path.
type failingEncoder struct{}

func (failingEncoder) Algo() wtpv1.Compression { return wtpv1.Compression_COMPRESSION_ZSTD }
func (failingEncoder) Encode([]byte) ([]byte, error) {
	return nil, errors.New("synthetic compress failure")
}

// compressMetricsRecorder captures method calls so the fail-open test
// can assert metric increments. Implements the unexported
// compressMetrics interface (this test file is package transport, so it
// can reference unexported types).
type compressMetricsRecorder struct {
	compressErrors []string
	ratios         []struct {
		algo  string
		ratio float64
	}
	uncompressedBytes []struct {
		algo string
		n    int
	}
	compressedBytes []struct {
		algo string
		n    int
	}
}

func (r *compressMetricsRecorder) IncCompressError(algo string) {
	r.compressErrors = append(r.compressErrors, algo)
}
func (r *compressMetricsRecorder) ObserveBatchCompressionRatio(algo string, ratio float64) {
	r.ratios = append(r.ratios, struct {
		algo  string
		ratio float64
	}{algo, ratio})
}
func (r *compressMetricsRecorder) AddBatchUncompressedBytes(algo string, n int) {
	r.uncompressedBytes = append(r.uncompressedBytes, struct {
		algo string
		n    int
	}{algo, n})
}
func (r *compressMetricsRecorder) AddBatchCompressedBytes(algo string, n int) {
	r.compressedBytes = append(r.compressedBytes, struct {
		algo string
		n    int
	}{algo, n})
}

func TestEncodeBatchMessage_FailOpenEmitsUncompressedAndIncMetric(t *testing.T) {
	rec := &compressMetricsRecorder{}
	msgs, err := encodeBatchMessageWithCompressor([]wal.Record{
		dataRecordForCompressTest(t, 1, 1),
		dataRecordForCompressTest(t, 2, 1),
	}, false, failingEncoder{}, rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 msg, got %d", len(msgs))
	}
	eb := msgs[0].GetEventBatch()
	if eb.GetCompression() != wtpv1.Compression_COMPRESSION_NONE {
		t.Fatalf("fail-open Compression = %v, want NONE", eb.GetCompression())
	}
	if eb.GetUncompressed() == nil {
		t.Fatal("fail-open body should be UncompressedEvents")
	}
	if got := rec.compressErrors; len(got) != 1 || got[0] != "zstd" {
		t.Fatalf("compress error metric = %v, want [\"zstd\"]", got)
	}
	// On fail-open, ratio/byte metrics should NOT be recorded.
	if len(rec.ratios) != 0 {
		t.Errorf("fail-open recorded ratios: %v; want none", rec.ratios)
	}
	if len(rec.compressedBytes) != 0 || len(rec.uncompressedBytes) != 0 {
		t.Errorf("fail-open recorded bytes; want none")
	}
}

func TestEncodeBatchMessage_ZstdRecordsRatioAndBytes(t *testing.T) {
	rec := &compressMetricsRecorder{}
	enc, _ := compress.NewEncoder("zstd", 3, 0)
	msgs, err := encodeBatchMessageWithCompressor([]wal.Record{
		dataRecordForCompressTest(t, 1, 1),
		dataRecordForCompressTest(t, 2, 1),
		dataRecordForCompressTest(t, 3, 1),
	}, false, enc, rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 msg, got %d", len(msgs))
	}
	if len(rec.ratios) != 1 || rec.ratios[0].algo != "zstd" {
		t.Fatalf("ratios = %v; want one zstd entry", rec.ratios)
	}
	if rec.ratios[0].ratio <= 0 {
		t.Fatalf("ratio = %v; want > 0", rec.ratios[0].ratio)
	}
	if len(rec.compressedBytes) != 1 || rec.compressedBytes[0].algo != "zstd" || rec.compressedBytes[0].n <= 0 {
		t.Fatalf("compressedBytes = %v; want one zstd entry with n > 0", rec.compressedBytes)
	}
	if len(rec.uncompressedBytes) != 1 || rec.uncompressedBytes[0].algo != "zstd" || rec.uncompressedBytes[0].n <= 0 {
		t.Fatalf("uncompressedBytes = %v; want one zstd entry with n > 0", rec.uncompressedBytes)
	}
	if len(rec.compressErrors) != 0 {
		t.Fatalf("compressErrors should be empty on happy path; got %v", rec.compressErrors)
	}
}
