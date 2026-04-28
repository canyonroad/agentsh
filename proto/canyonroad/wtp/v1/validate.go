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

// ValidationReason is the canonical low-cardinality classification of
// validator failures. Receivers consume this via errors.As to stamp
// wtp_dropped_invalid_frame_total{reason=string(ve.Reason)} without
// parsing the formatted error message. Adding a new validator branch
// requires adding a new ValidationReason constant here AND the matching
// label to internal/metrics' WTPInvalidFrameReason enum (Task 22a).
//
// Note: decompress_error and classifier_bypass are NOT ValidationReasons
// — both are metrics-only (see internal/metrics): decompress_error is
// emitted by streaming decompression downstream of the validator, and
// classifier_bypass is emitted by the receiver-side defense-in-depth
// errors.As-false guard and by the metrics-side invalid-label collapse.
// Neither has a proto-side counterpart by definition.
type ValidationReason string

const (
	// ReasonEventBatchBodyUnset is returned by ValidateEventBatch when
	// the EventBatch is nil OR when its Body oneof is unset. The two
	// failure modes fold under one canonical reason because operators
	// cannot distinguish a nil envelope from an envelope-with-empty-body
	// at the metric layer — both are semantically "no payload."
	ReasonEventBatchBodyUnset ValidationReason = "event_batch_body_unset"

	// ReasonEventBatchCompressionUnspecified is returned when
	// EventBatch.Compression == COMPRESSION_UNSPECIFIED.
	ReasonEventBatchCompressionUnspecified ValidationReason = "event_batch_compression_unspecified"

	// ReasonEventBatchCompressionMismatch is returned when the Body
	// oneof discriminator disagrees with Compression (uncompressed body
	// with non-NONE compression, or compressed_payload with NONE).
	ReasonEventBatchCompressionMismatch ValidationReason = "event_batch_compression_mismatch"

	// ReasonSessionInitAlgorithmUnspecified is returned by
	// ValidateSessionInit when the SessionInit is nil OR when its
	// Algorithm enum is HASH_ALGORITHM_UNSPECIFIED. Like the body-unset
	// case, both failure modes share one canonical reason — operators
	// cannot differentiate a nil session-init from one missing the
	// algorithm enum, and both indicate the same root cause.
	ReasonSessionInitAlgorithmUnspecified ValidationReason = "session_init_algorithm_unspecified"

	// ReasonPayloadTooLarge is returned when EventBatch.compressed_payload
	// exceeds MaxCompressedPayloadBytes.
	ReasonPayloadTooLarge ValidationReason = "payload_too_large"

	// ReasonGoawayCodeUnspecified is returned by ValidateGoaway when the
	// inbound Goaway has code == GOAWAY_CODE_UNSPECIFIED — that value is
	// wire-incompatible per the proto's UNSPECIFIED contract.
	ReasonGoawayCodeUnspecified ValidationReason = "goaway_code_unspecified"

	// ReasonSessionUpdateGenerationInvalid is returned by
	// ValidateSessionUpdate when the inbound SessionUpdate has
	// generation == 0. Rotation MUST monotonically advance to a positive
	// generation per the WTP client design.
	ReasonSessionUpdateGenerationInvalid ValidationReason = "session_update_generation_invalid"

	// ReasonUnknown is the schema-drift reason. It covers two
	// failure classes that share one operator response ("investigate
	// the proto schema delta"):
	//   (i)  the VALIDATOR-VS-SCHEMA drift case: a developer added a
	//        new oneof arm in wtp.proto, regenerated wtp.pb.go, but
	//        forgot to update ValidateEventBatch's body switch. The
	//        new Body arm lands on the switch `default:` branch.
	//   (ii) the PEER-DRIFT-WITH-UNKNOWN-FIELDS case: the peer sent a
	//        message that leaves Body unset AND contains unknown
	//        top-level fields (any tag the client's proto does not
	//        know). This fires regardless of whether the unknown
	//        field was intended as a new body oneof arm or a new
	//        sibling field — wire bytes alone cannot distinguish
	//        those intents, and both point at the same remediation
	//        (regenerate the client against the peer's schema).
	// A non-zero wtp_dropped_invalid_frame_total{reason="unknown"}
	// series is the operator-visible signal that schema drift has
	// landed somewhere in the pipeline. The "unknown" reason is
	// RESERVED for these two validator-adjacent drift classes; the
	// receiver-side defense-in-depth path uses the separate metrics-
	// only "classifier_bypass" reason.
	ReasonUnknown ValidationReason = "unknown"
)

// ALIASES ARE FORBIDDEN. There is exactly ONE canonical ValidationReason
// constant per reason string value — six constants total above.
//   (a) AllValidationReasons() is the canonical enumeration; aliases
//       inflate its length without adding semantic content.
//   (b) Validator code MUST reference the canonical name so reading the
//       validator switch makes the reason obvious.
//   (c) External dashboard consumers see the reason string only and
//       cannot benefit from constant-name aliases.

// ValidationError carries both a structured Reason (safe for metric
// labels and structured logs) and the original Inner error (which
// embeds peer-supplied details and MUST NOT be logged by receivers per
// the spec sanitization rule). Receivers consume Reason via errors.As;
// Inner remains available via Unwrap for tests and developer-side
// debugging — it MUST NOT be serialized to any production log sink.
type ValidationError struct {
	Reason ValidationReason
	Inner  error
}

// Error returns ONLY the Reason string (no peer-derived content). This
// is intentional defense-in-depth: even a naive call site that does
// slog.Error("...", "err", ve) or fmt.Sprintf("%s", ve) cannot leak
// peer bytes — the formatted message is the canonical reason value.
// Callers that need the Inner detail (tests, in-memory debugging) read
// it via Unwrap().
func (e *ValidationError) Error() string { return string(e.Reason) }

// Unwrap exposes the Inner error for tests and developer-side
// debugging. Production receivers MUST NOT serialize this to any log
// sink per the spec sanitization rule.
func (e *ValidationError) Unwrap() error { return e.Inner }

// Is preserves errors.Is(err, ErrInvalidFrame) / ErrPayloadTooLarge
// semantics so legacy callers built before this typed boundary still
// work. The match is delegated to the Inner error which itself wraps
// the appropriate sentinel.
func (e *ValidationError) Is(target error) bool { return errors.Is(e.Inner, target) }

// allValidationReasons enumerates every ValidationReason constant in
// stable insertion order (matching enum declaration order). Package-
// private to prevent external mutation; consumers use the
// AllValidationReasons() getter which returns a fresh copy. Exactly one
// entry per canonical reason — no aliases.
var allValidationReasons = []ValidationReason{
	ReasonEventBatchBodyUnset,
	ReasonEventBatchCompressionUnspecified,
	ReasonEventBatchCompressionMismatch,
	ReasonSessionInitAlgorithmUnspecified,
	ReasonPayloadTooLarge,
	ReasonGoawayCodeUnspecified,
	ReasonSessionUpdateGenerationInvalid,
	ReasonUnknown,
}

// AllValidationReasons returns a fresh copy of every ValidationReason
// constant in stable insertion order (matching enum declaration order).
// Consumers (notably the metrics package's parity test, plus any
// external dashboard generator) range over this slice to assert the
// proto-side and metrics-side enums stay in sync. Adding a new
// ValidationReason constant MUST also append it to
// allValidationReasons above.
//
// STABLE PRODUCTION API: returns a fresh copy on each call so callers
// cannot mutate the package-private enumeration. Insertion order is
// documented stable; removals or renames are breaking changes
// regardless of pre-1.0 status — they require a coordinated metrics +
// dashboards migration.
func AllValidationReasons() []ValidationReason {
	out := make([]ValidationReason, len(allValidationReasons))
	copy(out, allValidationReasons)
	return out
}

// ValidateEventBatch returns a *ValidationError on failure; the typed
// Reason field lets receivers classify the failure into a fixed metric
// label without parsing the error message.
func ValidateEventBatch(b *EventBatch) error {
	if b == nil {
		return &ValidationError{
			Reason: ReasonEventBatchBodyUnset,
			Inner:  fmt.Errorf("%w: batch is nil", ErrInvalidFrame),
		}
	}
	// Schema-drift check FIRST (before Compression / Body switch):
	// a peer-drift frame may have Body unset, Compression unset, AND
	// unknown top-level fields simultaneously. Classifying
	// "compression_unspecified" first would hide the drift signal
	// under the generic missing-Compression bucket — operators paged
	// on an unexpected peer schema need to see the "unknown" reason,
	// not a misleading "compression_unspecified" that sends them
	// hunting for a field-population bug that isn't there. The
	// check is scoped to Body==nil because a peer that populates a
	// known Body oneof arm but ALSO attaches unknown sibling fields
	// still has usable payload; the Body switch below handles that
	// case under the specific known-arm branches.
	if b.Body == nil && len(b.ProtoReflect().GetUnknown()) > 0 {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: body unset but peer sent unknown fields (schema drift)", ErrInvalidFrame),
		}
	}
	if b.Compression == Compression_COMPRESSION_UNSPECIFIED {
		return &ValidationError{
			Reason: ReasonEventBatchCompressionUnspecified,
			Inner:  fmt.Errorf("%w: compression unspecified", ErrInvalidFrame),
		}
	}
	switch body := b.Body.(type) {
	case nil:
		// Body unset with no unknown fields — genuine missing-payload
		// bug (the Body==nil + unknown-fields case is handled above
		// before the Compression check so schema drift is never hidden
		// under compression_unspecified).
		return &ValidationError{
			Reason: ReasonEventBatchBodyUnset,
			Inner:  fmt.Errorf("%w: body unset", ErrInvalidFrame),
		}
	case *EventBatch_Uncompressed:
		if b.Compression != Compression_COMPRESSION_NONE {
			return &ValidationError{
				Reason: ReasonEventBatchCompressionMismatch,
				Inner:  fmt.Errorf("%w: uncompressed body requires compression=NONE (got %s)", ErrInvalidFrame, b.Compression),
			}
		}
	case *EventBatch_CompressedPayload:
		if b.Compression == Compression_COMPRESSION_NONE {
			return &ValidationError{
				Reason: ReasonEventBatchCompressionMismatch,
				Inner:  fmt.Errorf("%w: compressed_payload requires compression != NONE", ErrInvalidFrame),
			}
		}
		if len(body.CompressedPayload) > MaxCompressedPayloadBytes {
			return &ValidationError{
				Reason: ReasonPayloadTooLarge,
				Inner:  fmt.Errorf("%w: compressed_payload is %d bytes (cap %d)", ErrPayloadTooLarge, len(body.CompressedPayload), MaxCompressedPayloadBytes),
			}
		}
	default:
		// In-tree validator-vs-schema drift: a developer added a new
		// oneof arm to wtp.proto, regenerated wtp.pb.go, but forgot to
		// update this switch. The generated Body field now typed to the
		// new arm lands here. Peer-driven schema drift does NOT reach
		// this branch in real proto3 decoding — unknown peer arms stay
		// in the unknown-field set and are caught in the `case nil:`
		// branch above via the ProtoReflect().GetUnknown() check. The
		// ReasonUnknown bucket is shared across both drift classes so
		// operators see one reason regardless of where the drift lives.
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: unknown body oneof case", ErrInvalidFrame),
		}
	}
	return nil
}

// ValidateSessionInit rejects SessionInit frames whose `algorithm` is
// HASH_ALGORITHM_UNSPECIFIED. Required-field semantics for the other
// SessionInit fields (session_id, ocsf_version, key_fingerprint,
// context_digest, agent_id, agent_version) are not enforced here — they
// are validated by the server during SessionInit handling, which is out
// of scope for the MVP client.
func ValidateSessionInit(s *SessionInit) error {
	if s == nil {
		return &ValidationError{
			Reason: ReasonSessionInitAlgorithmUnspecified,
			Inner:  fmt.Errorf("%w: session_init is nil", ErrInvalidFrame),
		}
	}
	if s.Algorithm == HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return &ValidationError{
			Reason: ReasonSessionInitAlgorithmUnspecified,
			Inner:  fmt.Errorf("%w: algorithm unspecified", ErrInvalidFrame),
		}
	}
	return nil
}

// ValidateGoaway returns ReasonGoawayCodeUnspecified when the inbound
// Goaway has code == GOAWAY_CODE_UNSPECIFIED — wire-incompatible per
// the proto's UNSPECIFIED contract. Returns ReasonUnknown for nil
// messages (a structural failure).
//
// Other Goaway fields (message, retry_immediately) have no MUST-be-set
// invariants the validator can enforce statelessly.
func ValidateGoaway(g *Goaway) error {
	if g == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: goaway is nil", ErrInvalidFrame),
		}
	}
	if g.Code == GoawayCode_GOAWAY_CODE_UNSPECIFIED {
		return &ValidationError{
			Reason: ReasonGoawayCodeUnspecified,
			Inner:  fmt.Errorf("%w: goaway code unspecified", ErrInvalidFrame),
		}
	}
	return nil
}

// ValidateSessionUpdate returns ReasonSessionUpdateGenerationInvalid
// when SessionUpdate.new_generation == 0 — rotation MUST monotonically
// advance to a positive generation per the WTP client design (see
// 2026-04-18-wtp-client-design.md). Returns ReasonUnknown for nil.
//
// State-dependent invariants ("new generation must be strictly higher
// than current") are not the validator's concern; the rotation
// handler enforces those (when Project C lands).
func ValidateSessionUpdate(u *SessionUpdate) error {
	if u == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: session_update is nil", ErrInvalidFrame),
		}
	}
	if u.NewGeneration == 0 {
		return &ValidationError{
			Reason: ReasonSessionUpdateGenerationInvalid,
			Inner:  fmt.Errorf("%w: session_update new_generation == 0", ErrInvalidFrame),
		}
	}
	return nil
}
