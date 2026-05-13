package events

import "time"

// LifecycleEvent is a non-statement DB-proxy event: listener-auth failures,
// handshake failures (Plan 04b), degraded-visibility warnings (Plan 04b),
// and cancel side-channel lifecycle outcomes.
// Carries less data than DBEvent because there is no statement to redact.
//
// Kind is a small enumerated string:
// "db_listener_auth_fail", "db_handshake_fail",
// "degraded_visibility_warning", "db_cancel_unmatched",
// "db_cancel_after_disconnect", "db_cancel_forward_failed",
// "db_cancel_mapping_fail". Each plan that emits a new kind is responsible
// for documenting the value in plan release notes.
type LifecycleEvent struct {
	EventID        string    `json:"event_id"`
	SessionID      string    `json:"session_id,omitempty"`
	Timestamp      time.Time `json:"ts"`
	DBService      string    `json:"db_service,omitempty"`
	ClientIdentity string    `json:"client_identity,omitempty"`

	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`

	// Listener-auth specific (Plan 04a). Zero when not applicable.
	PeerUID uint32 `json:"peer_uid,omitempty"`
	PeerPID int32  `json:"peer_pid,omitempty"`

	// Handshake/error specific (Plan 04b). Zero when not applicable.
	ErrorCode string `json:"error_code,omitempty"`

	// TLS SNI extracted from the inbound ClientHello. Empty when the client
	// omitted SNI or the connection is not TLS. Spec §13.2 footnote: SNI
	// is advisory; do not gate access decisions on it.
	SNIHostname string `json:"sni_hostname,omitempty"`

	// DegradedReason classifies a degraded_visibility_warning event. Values:
	// "replication_passthrough" (Plan 04b₂), "gssenc_passthrough" (Plan 05).
	// "tls_passthrough" is reserved but never set in 04b₂ — spec §11.1 says
	// no per-connection DVW under tls_mode: passthrough; the value is kept
	// for symmetry with the future GSSENC enum.
	DegradedReason string `json:"degraded_reason,omitempty"`
}
