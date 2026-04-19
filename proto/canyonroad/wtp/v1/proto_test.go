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
