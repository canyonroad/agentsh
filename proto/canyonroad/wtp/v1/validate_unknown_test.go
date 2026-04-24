package wtpv1

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// unknownBodyForTest implements isEventBatch_Body so we can exercise the
// default branch of ValidateEventBatch's body switch. This simulates
// IN-TREE validator-vs-schema drift: a developer added a new oneof arm
// in wtp.proto, regenerated wtp.pb.go, but forgot to update the
// validator switch. Peer-driven drift does NOT reach this branch
// (proto3 decoding deposits unknown peer arms into the unknown-field
// set with Body==nil — see TestValidateEventBatch_PeerUnknownOneof
// below). This seam MUST live in package wtpv1 (NOT wtpv1_test) because
// the isEventBatch_Body() marker method is unexported in the generated
// wtp.pb.go.
type unknownBodyForTest struct{}

func (*unknownBodyForTest) isEventBatch_Body() {}

func TestValidateEventBatch_UnknownOneof_ReturnsReasonUnknown(t *testing.T) {
	batch := &EventBatch{
		Compression: Compression_COMPRESSION_NONE,
		Body:        &unknownBodyForTest{},
	}
	err := ValidateEventBatch(batch)
	if err == nil {
		t.Fatal("ValidateEventBatch returned nil for unknown body oneof; expected *ValidationError")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if ve.Reason != ReasonUnknown {
		t.Fatalf("want ReasonUnknown (%q), got %q", ReasonUnknown, ve.Reason)
	}
	if got, want := err.Error(), string(ReasonUnknown); got != want {
		t.Errorf("Error() = %q, want %q (must equal Reason, NOT Inner)", got, want)
	}
}

// TestValidateEventBatch_PeerUnknownFields_ReturnsReasonUnknown covers
// the peer schema-drift case: the peer sent an EventBatch with Body
// unset AND a top-level field at a tag number the client's proto does
// not recognise. Proto3 decoding parks the unknown field in the
// message's unknown-field set and leaves Body == nil. The validator
// MUST classify this as ReasonUnknown (NOT ReasonEventBatchBodyUnset)
// so operators see the schema-drift signal instead of collapsing it
// under the generic missing-payload bucket. The wire bytes cannot tell
// us whether the unknown field was intended as a new body oneof arm
// or a new sibling field — and both point at the same remediation
// (regenerate the client against the peer's schema), so ReasonUnknown
// covers both per the doc comment on the constant.
func TestValidateEventBatch_PeerUnknownFields_ReturnsReasonUnknown(t *testing.T) {
	batch := &EventBatch{
		Compression: Compression_COMPRESSION_NONE,
	}
	// Inject an unknown wire-format field at tag 999 (a tag the client's
	// proto does not know). This simulates either a new body oneof arm
	// or a new unrelated sibling field on the peer's side — the
	// validator's ReasonUnknown bucket covers both cases per the
	// constant's doc comment.
	raw := protowire.AppendTag(nil, 999, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("peer-unknown-field-payload"))
	batch.ProtoReflect().SetUnknown(raw)

	err := ValidateEventBatch(batch)
	if err == nil {
		t.Fatal("ValidateEventBatch returned nil for peer-unknown field; expected *ValidationError")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if ve.Reason != ReasonUnknown {
		t.Errorf("want ReasonUnknown (peer sent unknown fields while Body unset — schema drift), got %q", ve.Reason)
	}
}

// TestValidateEventBatch_NoUnknownFields_ReturnsBodyUnset asserts the
// inverse: Body unset AND no unknown fields means a genuine
// missing-payload case, which MUST classify as ReasonEventBatchBodyUnset
// (NOT ReasonUnknown).
func TestValidateEventBatch_NoUnknownFields_ReturnsBodyUnset(t *testing.T) {
	batch := &EventBatch{Compression: Compression_COMPRESSION_NONE}
	err := ValidateEventBatch(batch)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if ve.Reason != ReasonEventBatchBodyUnset {
		t.Errorf("want ReasonEventBatchBodyUnset (no unknown fields, body truly unset), got %q", ve.Reason)
	}
}
