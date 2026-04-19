// Command gen-wire-goldens regenerates wire-format goldens for WTP messages.
//
// CI does NOT run this tool — it only verifies the existing goldens
// round-trip cleanly (TestWireGoldens_RoundTrip in
// proto/canyonroad/wtp/v1/wire_roundtrip_test.go).
//
// Run manually after intentional schema changes:
//
//	go run ./internal/store/watchtower/cmd/gen-wire-goldens
package main

import (
	"fmt"
	"os"
	"path/filepath"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

const outDir = "proto/canyonroad/wtp/v1/testdata"

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}

	ce := &wtpv1.CompactEvent{
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
	write("compact_event.bin", ce)

	eb := &wtpv1.EventBatch{
		FromSequence: 40,
		ToSequence:   42,
		Generation:   7,
		Compression:  wtpv1.Compression_COMPRESSION_NONE,
		Body: &wtpv1.EventBatch_Uncompressed{
			Uncompressed: &wtpv1.UncompressedEvents{
				Events: []*wtpv1.CompactEvent{ce},
			},
		},
	}
	write("event_batch.bin", eb)

	si := &wtpv1.SessionInit{
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
	write("session_init.bin", si)

	fmt.Println("regenerated goldens in", outDir)
}

func write(name string, m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		fail(err)
	}
	p := filepath.Join(outDir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		fail(err)
	}
	fmt.Println("wrote", p, len(b), "bytes")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
