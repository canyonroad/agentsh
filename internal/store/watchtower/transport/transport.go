package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Options configures a Transport.
type Options struct {
	Dialer    Dialer
	AgentID   string
	SessionID string
	// FormatVersion is sent in SessionInit; defaults to 2.
	FormatVersion uint32
	// Algorithm is the chain HMAC algorithm advertised in SessionInit.
	// Defaults to HASH_ALGORITHM_HMAC_SHA256 in New() so that the proto
	// validator (wtpv1.ValidateSessionInit) accepts the frame; later
	// tasks may surface a config knob to override this.
	Algorithm wtpv1.HashAlgorithm
	// AgentVersion identifies the running agent build. Empty by default;
	// the sink wiring task will populate it.
	AgentVersion string
	// OcsfVersion is the OCSF schema version the sink emits. Empty by
	// default; the sink wiring task will populate it.
	OcsfVersion string
	// KeyFingerprint identifies the active signing key (hex-encoded).
	// Empty by default; the key-rotation task will populate it.
	KeyFingerprint string
	// ContextDigest is the hex-encoded SHA-256 of the session context.
	// Empty by default; the sink wiring task will populate it.
	ContextDigest string
	// TotalChained is the count of records the sink has chained so far.
	// Zero by default; the sink wiring task will populate it.
	TotalChained uint64
}

// Transport runs the four-state WTP client state machine. It is owned by
// a single goroutine — callers interact via channels.
type Transport struct {
	opts Options
	conn Conn

	// last acknowledged watermark, updated when SessionAck/SessionUpdate
	// is observed.
	ackedSequence   uint64
	ackedGeneration uint32

	// rejectReason is populated when the server rejects the session
	// (SessionAck.accepted=false). Surfaced via RejectReason().
	rejectReason string
}

// New constructs a Transport. It does not dial; call Run to start.
func New(opts Options) *Transport {
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	if opts.Algorithm == wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		opts.Algorithm = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256
	}
	return &Transport{opts: opts}
}

// RejectReason returns the reject_reason surfaced by the most recent
// SessionAck with accepted=false. It is empty until the server rejects
// the session.
func (t *Transport) RejectReason() string {
	return t.rejectReason
}

// sessionInit returns the SessionInit message for the current connection.
func (t *Transport) sessionInit() *wtpv1.ClientMessage {
	return &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_SessionInit{
			SessionInit: &wtpv1.SessionInit{
				SessionId:           t.opts.SessionID,
				OcsfVersion:         t.opts.OcsfVersion,
				FormatVersion:       t.opts.FormatVersion,
				Algorithm:           t.opts.Algorithm,
				KeyFingerprint:      t.opts.KeyFingerprint,
				ContextDigest:       t.opts.ContextDigest,
				WalHighWatermarkSeq: t.ackedSequence,
				Generation:          t.ackedGeneration,
				AgentId:             t.opts.AgentID,
				AgentVersion:        t.opts.AgentVersion,
				TotalChained:        t.opts.TotalChained,
			},
		},
	}
}
