package wtpv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestProto_RoundTripCompactEvent(t *testing.T) {
	src := &CompactEvent{
		Sequence:           42,
		Generation:         7,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
		OcsfClassUid:       3001,
		OcsfActivityId:     1,
		Payload:            []byte{0xde, 0xad, 0xbe, 0xef},
		Integrity: &IntegrityRecord{
			FormatVersion:  2,
			Sequence:       42,
			Generation:     7,
			PrevHash:       "deadbeef",
			EventHash:      "cafef00d",
			ContextDigest:  "0123456789abcdef",
			KeyFingerprint: "sha256:aabbccdd",
		},
	}
	wire, err := proto.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var dst CompactEvent
	if err := proto.Unmarshal(wire, &dst); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(src, &dst) {
		t.Fatalf("round trip differs\nsrc=%v\ndst=%v", src, &dst)
	}
}

func TestProto_OneofClientMessage(t *testing.T) {
	cm := &ClientMessage{
		Msg: &ClientMessage_EventBatch{EventBatch: &EventBatch{FromSequence: 1, ToSequence: 5, Generation: 0}},
	}
	wire, err := proto.Marshal(cm)
	if err != nil {
		t.Fatal(err)
	}
	var got ClientMessage
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetEventBatch() == nil {
		t.Fatal("event_batch oneof did not survive round trip")
	}
}

func TestProto_EventBatch_OneofBody(t *testing.T) {
	// uncompressed arm
	eb := &EventBatch{
		FromSequence: 10, ToSequence: 12, Generation: 1,
		Compression: Compression_COMPRESSION_NONE,
		Body: &EventBatch_Uncompressed{
			Uncompressed: &UncompressedEvents{
				Events: []*CompactEvent{{Sequence: 10}, {Sequence: 11}, {Sequence: 12}},
			},
		},
	}
	wire, err := proto.Marshal(eb)
	if err != nil {
		t.Fatal(err)
	}
	var got EventBatch
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetUncompressed() == nil {
		t.Fatal("uncompressed body lost in round trip")
	}
	if n := len(got.GetUncompressed().GetEvents()); n != 3 {
		t.Fatalf("expected 3 events; got %d", n)
	}
	if got.GetCompressedPayload() != nil {
		t.Fatal("compressed_payload should be nil for uncompressed batch")
	}
	// compressed arm
	eb2 := &EventBatch{
		FromSequence: 20, ToSequence: 25, Generation: 1,
		Compression: Compression_COMPRESSION_ZSTD,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: []byte("opaque-zstd-blob")},
	}
	wire2, err := proto.Marshal(eb2)
	if err != nil {
		t.Fatal(err)
	}
	var got2 EventBatch
	if err := proto.Unmarshal(wire2, &got2); err != nil {
		t.Fatal(err)
	}
	if string(got2.GetCompressedPayload()) != "opaque-zstd-blob" {
		t.Fatalf("compressed_payload lost: got %q", got2.GetCompressedPayload())
	}
	if got2.GetUncompressed() != nil {
		t.Fatal("uncompressed should be nil for compressed batch")
	}
}

func TestProto_AlgorithmEnum_DefaultIsUnspecified(t *testing.T) {
	si := &SessionInit{}
	if si.GetAlgorithm() != HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		t.Errorf("zero value of algorithm should be UNSPECIFIED; got %v", si.GetAlgorithm())
	}
}
