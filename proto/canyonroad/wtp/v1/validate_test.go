package wtpv1

import (
	"errors"
	"testing"
)

func TestValidateEventBatch_UnsetBodyRejected(t *testing.T) {
	eb := &EventBatch{FromSequence: 1, ToSequence: 2, Generation: 1, Compression: Compression_COMPRESSION_NONE}
	err := ValidateEventBatch(eb)
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonEventBatchBodyUnset {
		t.Errorf("expected *ValidationError with Reason=%q; got %v", ReasonEventBatchBodyUnset, err)
	}
}

func TestValidateEventBatch_CompressionUnspecifiedRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_UNSPECIFIED,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{}},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_NoneWithCompressedPayloadRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_NONE,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: []byte("x")},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_ZstdWithUncompressedRejected(t *testing.T) {
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_ZSTD,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{}},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateEventBatch_OverCapCompressedRejected(t *testing.T) {
	huge := make([]byte, MaxCompressedPayloadBytes+1)
	eb := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_ZSTD,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: huge},
	}
	if err := ValidateEventBatch(eb); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge; got %v", err)
	}
}

func TestValidateEventBatch_HappyPaths(t *testing.T) {
	uncompressed := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_NONE,
		Body:        &EventBatch_Uncompressed{Uncompressed: &UncompressedEvents{Events: []*CompactEvent{{Sequence: 1}, {Sequence: 2}}}},
	}
	if err := ValidateEventBatch(uncompressed); err != nil {
		t.Errorf("uncompressed batch should validate; got %v", err)
	}
	compressed := &EventBatch{
		FromSequence: 1, ToSequence: 2, Generation: 1,
		Compression: Compression_COMPRESSION_GZIP,
		Body:        &EventBatch_CompressedPayload{CompressedPayload: []byte("blob")},
	}
	if err := ValidateEventBatch(compressed); err != nil {
		t.Errorf("compressed batch should validate; got %v", err)
	}
}

func TestValidateSessionInit_AlgorithmUnspecifiedRejected(t *testing.T) {
	si := &SessionInit{SessionId: "s", Algorithm: HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED}
	if err := ValidateSessionInit(si); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("expected ErrInvalidFrame; got %v", err)
	}
}

func TestValidateSessionInit_HappyPath(t *testing.T) {
	si := &SessionInit{SessionId: "s", Algorithm: HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256}
	if err := ValidateSessionInit(si); err != nil {
		t.Errorf("happy path should validate; got %v", err)
	}
}

func TestValidateGoaway_Nil(t *testing.T) {
	err := ValidateGoaway(nil)
	if err == nil {
		t.Fatal("ValidateGoaway(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ValidateGoaway(nil) err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonUnknown {
		t.Errorf("ValidateGoaway(nil) reason = %q; want %q", ve.Reason, ReasonUnknown)
	}
}

func TestValidateGoaway_CodeUnspecified(t *testing.T) {
	err := ValidateGoaway(&Goaway{Code: GoawayCode_GOAWAY_CODE_UNSPECIFIED})
	if err == nil {
		t.Fatal("ValidateGoaway(code=UNSPECIFIED): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonGoawayCodeUnspecified {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonGoawayCodeUnspecified)
	}
}

func TestValidateGoaway_HappyPath(t *testing.T) {
	cases := []GoawayCode{
		GoawayCode_GOAWAY_CODE_DRAINING,
		GoawayCode_GOAWAY_CODE_OVERLOAD,
		GoawayCode_GOAWAY_CODE_UPGRADE,
		GoawayCode_GOAWAY_CODE_AUTH,
	}
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) {
			if err := ValidateGoaway(&Goaway{Code: c}); err != nil {
				t.Errorf("ValidateGoaway(code=%v): %v", c, err)
			}
		})
	}
}

func TestValidateSessionUpdate_Nil(t *testing.T) {
	err := ValidateSessionUpdate(nil)
	if err == nil {
		t.Fatal("ValidateSessionUpdate(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonUnknown {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonUnknown)
	}
}

func TestValidateSessionUpdate_GenerationZero(t *testing.T) {
	err := ValidateSessionUpdate(&SessionUpdate{NewGeneration: 0, NewKeyFingerprint: "k", NewContextDigest: "d"})
	if err == nil {
		t.Fatal("ValidateSessionUpdate(gen=0): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonSessionUpdateGenerationInvalid {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonSessionUpdateGenerationInvalid)
	}
}

func TestValidateSessionUpdate_HappyPath(t *testing.T) {
	if err := ValidateSessionUpdate(&SessionUpdate{
		NewGeneration:     1,
		NewKeyFingerprint: "k",
		NewContextDigest:  "d",
		BoundarySequence:  42,
	}); err != nil {
		t.Errorf("ValidateSessionUpdate: %v", err)
	}
}

func TestValidateSessionAck_Nil(t *testing.T) {
	err := ValidateSessionAck(nil)
	if err == nil {
		t.Fatal("ValidateSessionAck(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateSessionAck_AcceptedHappyPath(t *testing.T) {
	if err := ValidateSessionAck(&SessionAck{Accepted: true, Generation: 1, AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateSessionAck(accepted): %v", err)
	}
}

func TestValidateSessionAck_RejectedHappyPath(t *testing.T) {
	if err := ValidateSessionAck(&SessionAck{Accepted: false, RejectReason: "auth failed"}); err != nil {
		t.Errorf("ValidateSessionAck(rejected w/ reason): %v", err)
	}
}

func TestValidateBatchAck_Nil(t *testing.T) {
	err := ValidateBatchAck(nil)
	if err == nil {
		t.Fatal("ValidateBatchAck(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateBatchAck_HappyPath(t *testing.T) {
	if err := ValidateBatchAck(&BatchAck{Generation: 1, AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateBatchAck: %v", err)
	}
}

func TestValidateServerHeartbeat_Nil(t *testing.T) {
	err := ValidateServerHeartbeat(nil)
	if err == nil {
		t.Fatal("ValidateServerHeartbeat(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateServerHeartbeat_HappyPath(t *testing.T) {
	if err := ValidateServerHeartbeat(&ServerHeartbeat{AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateServerHeartbeat: %v", err)
	}
}
