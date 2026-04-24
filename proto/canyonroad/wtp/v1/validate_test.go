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
