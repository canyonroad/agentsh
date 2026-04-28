package wtpv1_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestValidateEventBatch_ReasonClassification asserts each validator
// failure maps to the correct canonical *ValidationError.Reason, and
// that legacy `errors.Is(err, ErrInvalidFrame|ErrPayloadTooLarge)`
// semantics are preserved through the typed wrapper.
func TestValidateEventBatch_ReasonClassification(t *testing.T) {
	cases := []struct {
		name    string
		batch   *wtpv1.EventBatch
		reason  wtpv1.ValidationReason
		isInner error
	}{
		{
			name:    "nil_batch",
			batch:   nil,
			reason:  wtpv1.ReasonEventBatchBodyUnset,
			isInner: wtpv1.ErrInvalidFrame,
		},
		{
			name:    "compression_unspecified",
			batch:   &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_UNSPECIFIED},
			reason:  wtpv1.ReasonEventBatchCompressionUnspecified,
			isInner: wtpv1.ErrInvalidFrame,
		},
		{
			name:    "body_unset",
			batch:   &wtpv1.EventBatch{Compression: wtpv1.Compression_COMPRESSION_NONE, Body: nil},
			reason:  wtpv1.ReasonEventBatchBodyUnset,
			isInner: wtpv1.ErrInvalidFrame,
		},
		{
			name: "compression_mismatch_uncompressed_with_zstd",
			batch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_ZSTD,
				Body:        &wtpv1.EventBatch_Uncompressed{Uncompressed: &wtpv1.UncompressedEvents{}},
			},
			reason:  wtpv1.ReasonEventBatchCompressionMismatch,
			isInner: wtpv1.ErrInvalidFrame,
		},
		{
			name: "compression_mismatch_compressed_with_none",
			batch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_NONE,
				Body:        &wtpv1.EventBatch_CompressedPayload{CompressedPayload: []byte{1, 2, 3}},
			},
			reason:  wtpv1.ReasonEventBatchCompressionMismatch,
			isInner: wtpv1.ErrInvalidFrame,
		},
		{
			name: "payload_too_large",
			batch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_ZSTD,
				Body: &wtpv1.EventBatch_CompressedPayload{
					CompressedPayload: bytes.Repeat([]byte{0}, wtpv1.MaxCompressedPayloadBytes+1),
				},
			},
			reason:  wtpv1.ReasonPayloadTooLarge,
			isInner: wtpv1.ErrPayloadTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wtpv1.ValidateEventBatch(tc.batch)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var ve *wtpv1.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As: not a *ValidationError: %v", err)
			}
			if ve.Reason != tc.reason {
				t.Errorf("reason: got %q, want %q", ve.Reason, tc.reason)
			}
			if !errors.Is(err, tc.isInner) {
				t.Errorf("errors.Is(%v): want match for %v", err, tc.isInner)
			}
			if got, want := err.Error(), string(tc.reason); got != want {
				t.Errorf("Error() = %q, want %q (must equal Reason, NOT Inner)", got, want)
			}
			if ve.Unwrap() == nil {
				t.Errorf("Unwrap() returned nil; expected the Inner error to remain accessible")
			}
		})
	}
}

// TestValidationError_ErrorReturnsOnlyReason locks in the defense-in-depth
// contract: a naive logger that calls .Error() on a *ValidationError MUST
// NOT see peer-supplied content from Inner.
func TestValidationError_ErrorReturnsOnlyReason(t *testing.T) {
	ve := &wtpv1.ValidationError{
		Reason: wtpv1.ReasonPayloadTooLarge,
		Inner:  fmt.Errorf("32MiB exceeds 8MiB cap"),
	}
	if got, want := ve.Error(), "payload_too_large"; got != want {
		t.Errorf("Error() = %q, want %q (peer-derived Inner MUST NOT leak)", got, want)
	}
}

func TestValidateSessionInit_ReasonClassification(t *testing.T) {
	cases := []struct {
		name   string
		s      *wtpv1.SessionInit
		reason wtpv1.ValidationReason
	}{
		{
			name:   "nil_session_init",
			s:      nil,
			reason: wtpv1.ReasonSessionInitAlgorithmUnspecified,
		},
		{
			name:   "algorithm_unspecified",
			s:      &wtpv1.SessionInit{Algorithm: wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED},
			reason: wtpv1.ReasonSessionInitAlgorithmUnspecified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wtpv1.ValidateSessionInit(tc.s)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var ve *wtpv1.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("errors.As: not a *ValidationError: %v", err)
			}
			if ve.Reason != tc.reason {
				t.Errorf("reason: got %q, want %q", ve.Reason, tc.reason)
			}
			if !errors.Is(err, wtpv1.ErrInvalidFrame) {
				t.Errorf("errors.Is(ErrInvalidFrame): want true")
			}
		})
	}
}

// TestAllValidationReasons_ReturnsFreshCopy asserts mutation of the
// returned slice cannot corrupt the package-private enumeration.
func TestAllValidationReasons_ReturnsFreshCopy(t *testing.T) {
	a := wtpv1.AllValidationReasons()
	if len(a) == 0 {
		t.Fatal("AllValidationReasons() returned empty slice")
	}
	orig := a[0]
	a[0] = wtpv1.ValidationReason("mutated")
	b := wtpv1.AllValidationReasons()
	if b[0] != orig {
		t.Errorf("AllValidationReasons() exposes package-private slice: got %q, want %q", b[0], orig)
	}
}

// TestAllValidationReasons_ContainsCanonicalSet asserts the canonical
// reasons are present and no duplicates slipped in (aliases forbidden).
func TestAllValidationReasons_ContainsCanonicalSet(t *testing.T) {
	want := map[wtpv1.ValidationReason]struct{}{
		wtpv1.ReasonEventBatchBodyUnset:              {},
		wtpv1.ReasonEventBatchCompressionUnspecified: {},
		wtpv1.ReasonEventBatchCompressionMismatch:    {},
		wtpv1.ReasonSessionInitAlgorithmUnspecified:  {},
		wtpv1.ReasonPayloadTooLarge:                  {},
		wtpv1.ReasonGoawayCodeUnspecified:            {},
		wtpv1.ReasonSessionUpdateGenerationInvalid:   {},
		wtpv1.ReasonUnknown:                          {},
	}
	got := wtpv1.AllValidationReasons()
	if len(got) != len(want) {
		t.Fatalf("AllValidationReasons() length: got %d, want %d (aliases forbidden)", len(got), len(want))
	}
	seen := make(map[wtpv1.ValidationReason]struct{}, len(got))
	for _, r := range got {
		if _, dup := seen[r]; dup {
			t.Errorf("duplicate reason %q (aliases forbidden)", r)
		}
		seen[r] = struct{}{}
		if _, ok := want[r]; !ok {
			t.Errorf("unexpected reason %q not in canonical set", r)
		}
	}
	for r := range want {
		if _, ok := seen[r]; !ok {
			t.Errorf("canonical reason %q missing from AllValidationReasons()", r)
		}
	}
}
