package wtpv1

import (
	"errors"
	"testing"
)

// unknownBodyForTest implements isEventBatch_Body so we can exercise the
// default branch of ValidateEventBatch's body switch. Proto schema
// additions of new oneof discriminators are forward-compat events that
// hit this path in production until the validator is updated to
// classify them under a dedicated ValidationReason. This test seam MUST
// live in package wtpv1 (NOT wtpv1_test) because the isEventBatch_Body()
// marker method is unexported per the protobuf-generated code in
// wtp.pb.go — only same-package code can implement the sealed oneof
// interface.
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
