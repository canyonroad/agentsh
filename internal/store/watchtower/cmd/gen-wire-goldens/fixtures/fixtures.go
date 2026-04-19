// Package fixtures owns the canonical construction of the WTP wire-format
// goldens. Both the gen-wire-goldens command and the wire-roundtrip test
// import this package so the generator's output stays in lock-step with
// the checked-in .bin files. Drift is detected by
// TestWireGoldens_GeneratorReproducible.
package fixtures

import (
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
		{Name: "session_init.bin", Message: sessionInit()},
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
