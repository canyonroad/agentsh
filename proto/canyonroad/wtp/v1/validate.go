package wtpv1

import (
	"errors"
	"fmt"
)

// MaxCompressedPayloadBytes is the receiver-enforced cap on EventBatch
// compressed_payload size. See spec §"Compression safety".
const MaxCompressedPayloadBytes = 8 * 1024 * 1024

// MaxDecompressedBatchBytes is the receiver-enforced cap applied to the
// streaming decoder once decompression begins. Validators here cap the
// compressed bytes; downstream decompression code is responsible for
// enforcing this second cap during the streaming decode.
const MaxDecompressedBatchBytes = 64 * 1024 * 1024

// ErrInvalidFrame is returned for schema-valid but semantically invalid frames.
var ErrInvalidFrame = errors.New("wtp: invalid frame")

// ErrPayloadTooLarge is returned when EventBatch.compressed_payload exceeds MaxCompressedPayloadBytes.
var ErrPayloadTooLarge = errors.New("wtp: payload too large")

// ValidateEventBatch enforces the rules in spec §"Frame validation and
// forward compatibility" + §"Compression safety". Receivers MUST call this
// before accepting an EventBatch.
func ValidateEventBatch(b *EventBatch) error {
	if b == nil {
		return fmt.Errorf("%w: batch is nil", ErrInvalidFrame)
	}
	if b.Compression == Compression_COMPRESSION_UNSPECIFIED {
		return fmt.Errorf("%w: compression unspecified", ErrInvalidFrame)
	}
	switch body := b.Body.(type) {
	case nil:
		return fmt.Errorf("%w: body unset", ErrInvalidFrame)
	case *EventBatch_Uncompressed:
		if b.Compression != Compression_COMPRESSION_NONE {
			return fmt.Errorf("%w: uncompressed body requires compression=NONE (got %s)", ErrInvalidFrame, b.Compression)
		}
	case *EventBatch_CompressedPayload:
		if b.Compression == Compression_COMPRESSION_NONE {
			return fmt.Errorf("%w: compressed_payload requires compression != NONE", ErrInvalidFrame)
		}
		if len(body.CompressedPayload) > MaxCompressedPayloadBytes {
			return fmt.Errorf("%w: compressed_payload is %d bytes (cap %d)", ErrPayloadTooLarge, len(body.CompressedPayload), MaxCompressedPayloadBytes)
		}
	default:
		return fmt.Errorf("%w: unknown body oneof case", ErrInvalidFrame)
	}
	return nil
}

// ValidateSessionInit rejects SessionInit frames with UNSPECIFIED enums or
// missing required fields, per spec §"Frame validation and forward compatibility".
func ValidateSessionInit(s *SessionInit) error {
	if s == nil {
		return fmt.Errorf("%w: session_init is nil", ErrInvalidFrame)
	}
	if s.Algorithm == HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return fmt.Errorf("%w: algorithm unspecified", ErrInvalidFrame)
	}
	return nil
}
