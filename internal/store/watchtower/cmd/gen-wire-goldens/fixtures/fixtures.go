// Package fixtures owns the canonical construction of the WTP wire-format
// goldens. Both the gen-wire-goldens command and the wire-roundtrip tests
// import this package so the generator's output stays in lock-step with
// the checked-in .bin files. Drift is detected by
// TestWireGoldens_GeneratorReproducible (per-fixture byte equality) and
// TestWireGoldens_NoOrphanGoldens (testdata/ membership equals the All()
// set in both directions).
//
// Determinism note: the current fixture messages have no map fields, so
// proto.Marshal is byte-deterministic without proto.MarshalOptions.
// Adding map-bearing messages in the future will require switching to
// proto.MarshalOptions{Deterministic: true} in both this package and
// the test, otherwise the byte-comparison tests will become flaky.
//
// Compressed fixtures (event_batch_zstd.bin, event_batch_gzip.bin) are
// additionally pinned to: zstd level 3, gzip level 6, and the
// klauspost/compress version in go.sum. Bumping any of those requires
// regenerating the goldens via `go run ./internal/store/watchtower/cmd/gen-wire-goldens`.
package fixtures

import (
	"github.com/agentsh/agentsh/internal/store/watchtower/transport/compress"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// Fixture pairs a fixture filename with the message it serializes to.
type Fixture struct {
	Name    string
	Message proto.Message
}

// All returns the canonical fixture set in the order the goldens are
// emitted. Adding a fixture here is the only sanctioned way to grow the
// set; do NOT hand-edit .bin files in the testdata directory.
func All() []Fixture {
	return []Fixture{
		{Name: "compact_event.bin", Message: compactEvent()},
		{Name: "event_batch.bin", Message: eventBatch()},
		{Name: "event_batch_zstd.bin", Message: eventBatchZstd()},
		{Name: "event_batch_gzip.bin", Message: eventBatchGzip()},
		{Name: "session_init.bin", Message: sessionInit()},
		{Name: "transport_loss_overflow.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW)},
		{Name: "transport_loss_crc_corruption.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION)},
		{Name: "transport_loss_mapper_failure.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE)},
		{Name: "transport_loss_invalid_mapper.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER)},
		{Name: "transport_loss_invalid_timestamp.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP)},
		{Name: "transport_loss_invalid_utf8.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8)},
		{Name: "transport_loss_sequence_overflow.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW)},
		{Name: "transport_loss_ack_regression_after_gc.bin", Message: transportLoss(wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC)},
	}
}

func compactEvent() *wtpv1.CompactEvent {
	return &wtpv1.CompactEvent{
		Sequence:           42,
		Generation:         7,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
		OcsfClassUid:       3001,
		OcsfActivityId:     1,
		Payload:            []byte{0xde, 0xad, 0xbe, 0xef},
		Integrity: &wtpv1.IntegrityRecord{
			FormatVersion:  2,
			Sequence:       42,
			Generation:     7,
			PrevHash:       "deadbeef",
			EventHash:      "cafef00d",
			ContextDigest:  "0123456789abcdef",
			KeyFingerprint: "sha256:aabbccdd",
		},
	}
}

func eventBatch() *wtpv1.EventBatch {
	return &wtpv1.EventBatch{
		FromSequence: 40,
		ToSequence:   42,
		Generation:   7,
		Compression:  wtpv1.Compression_COMPRESSION_NONE,
		Body: &wtpv1.EventBatch_Uncompressed{
			Uncompressed: &wtpv1.UncompressedEvents{
				Events: []*wtpv1.CompactEvent{compactEvent()},
			},
		},
	}
}

// eventBatchZstd returns the same logical batch as eventBatch() but
// encoded with zstd level 3. The bytes are deterministic across
// machines because: (a) the inner UncompressedEvents has no map
// fields, so proto.Marshal is byte-deterministic; (b) klauspost/
// compress is locked in go.sum and zstd at a fixed level produces
// the same output for a given input. Goldens will need to be
// regenerated whenever klauspost/compress is upgraded.
func eventBatchZstd() *wtpv1.EventBatch {
	return mustCompressedBatch("zstd", 3, 0)
}

// eventBatchGzip returns the same logical batch as eventBatch() but
// encoded with gzip level 6. Determinism notes match eventBatchZstd.
func eventBatchGzip() *wtpv1.EventBatch {
	return mustCompressedBatch("gzip", 0, 6)
}

// mustCompressedBatch builds a compressed-body EventBatch using the
// production compress.NewEncoder. The fixture-level helper exists
// (rather than inlined in each constructor) so the algo and level
// pinning is in one place.
func mustCompressedBatch(algo string, zstdLevel, gzipLevel int) *wtpv1.EventBatch {
	enc, err := compress.NewEncoder(algo, zstdLevel, gzipLevel)
	if err != nil {
		panic(err)
	}
	inner := &wtpv1.UncompressedEvents{Events: []*wtpv1.CompactEvent{compactEvent()}}
	raw, err := proto.Marshal(inner)
	if err != nil {
		panic(err)
	}
	cz, err := enc.Encode(raw)
	if err != nil {
		panic(err)
	}
	return &wtpv1.EventBatch{
		FromSequence: 40,
		ToSequence:   42,
		Generation:   7,
		Compression:  enc.Algo(),
		Body:         &wtpv1.EventBatch_CompressedPayload{CompressedPayload: cz},
	}
}

func sessionInit() *wtpv1.SessionInit {
	return &wtpv1.SessionInit{
		SessionId:           "01HXAVD2N5VX3CZQK7Q7QWNYKE",
		OcsfVersion:         "1.8.0",
		FormatVersion:       2,
		Algorithm:           wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256,
		KeyFingerprint:      "sha256:aabbccdd",
		ContextDigest:       "0123456789abcdef",
		WalHighWatermarkSeq: 0,
		Generation:          0,
		AgentId:             "agentsh",
		AgentVersion:        "0.0.0-test",
		TotalChained:        0,
	}
}

// transportLoss builds a deterministic TransportLoss message with the
// given reason. Same (from, to, gen) for every reason so byte-diffs
// between goldens are exactly the reason field — useful for visually
// comparing the wire-encoding of each enum value.
func transportLoss(reason wtpv1.TransportLossReason) *wtpv1.TransportLoss {
	return &wtpv1.TransportLoss{
		FromSequence: 100,
		ToSequence:   100,
		Generation:   1,
		Reason:       reason,
	}
}
