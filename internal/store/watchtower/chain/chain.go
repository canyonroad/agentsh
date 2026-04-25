// Package chain provides WTP-specific helpers around audit.SinkChain.
//
// This package does NOT re-implement chain mutation. The Compute/Commit/Fatal
// API lives on audit.SinkChain (Phase 0 contract). The helpers here cover only
// the WTP-specific bits: the canonical record encoding, the context digest, and
// the per-event hash.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
)

// IntegrityRecord is the WTP integrity_record structure that gets canonical-
// encoded and passed as the payload to audit.SinkChain.Compute. Field names
// match the on-the-wire JSON object in CompactEvent.integrity (spec §6.3).
//
// Sequence-width contract (layered):
//   - WTP wire format (this struct, the .proto definition) reserves the full
//     uint64 sequence space.
//   - audit.SinkChain.Compute consumes int64; values above math.MaxInt64
//     overflow at that boundary.
//   - The bounds check (0..math.MaxInt64) lives at the store-integration
//     boundary in watchtower.Store.AppendEvent (Task 22), where ev.Chain.Sequence
//     is converted before being passed to the chain.
//   - The encoder in this package handles the full uint64 range so wire-level
//     conformance vectors can exercise it; constraint enforcement is the
//     boundary's job, not the encoder's.
type IntegrityRecord struct {
	FormatVersion  uint32
	Sequence       uint64
	Generation     uint32
	PrevHash       string
	EventHash      string
	ContextDigest  string
	KeyFingerprint string
}

// SessionContext is the input to ComputeContextDigest. Bound at SessionInit,
// re-bound at SessionUpdate and at chain key rotation. Spec §6.4.6.
type SessionContext struct {
	SessionID      string
	AgentID        string
	AgentVersion   string
	OCSFVersion    string
	FormatVersion  uint32
	Algorithm      string
	KeyFingerprint string
}

// ComputeContextDigest returns the lowercase-hex SHA-256 of the canonical JSON
// encoding of the SessionContext. Bound into every event hash for the segment.
//
// The digest changes on session establishment and on chain rotation; tests can
// assert byte-equality against this output as part of the conformance suite.
//
// Returns ErrInvalidUTF8 if any SessionContext string field contains invalid
// UTF-8. See EncodeCanonical for the cross-implementation rationale.
func ComputeContextDigest(ctx SessionContext) (string, error) {
	canon, err := encodeContextCanonical(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeEventHash returns the lowercase-hex SHA-256 of the canonical CompactEvent
// bytes. Used to populate IntegrityRecord.EventHash before the IntegrityRecord
// is canonical-encoded and passed as payload to audit.SinkChain.Compute.
func ComputeEventHash(canonicalEvent []byte) string {
	sum := sha256.Sum256(canonicalEvent)
	return hex.EncodeToString(sum[:])
}
