package transport

import (
	"errors"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Options configures a Transport.
//
// SessionInit field provenance: the Transport itself is a thin wire-format
// adapter — it does not look up identity, key material, or sink state. The
// fields below document who is expected to populate each value when the
// sink-integration task (Task 27) wires this Transport into the real
// pipeline. Until then, callers (and tests) supply the values directly via
// Options.
//
// TODO(Task 17/18): runReplaying needs a recv multiplexer before
// production use; see state_replaying.go runReplaying header. The
// Replaying-state handler is currently unexported and reachable only via
// the RunReplayingForTest seam in state_replaying_internal_test.go;
// production wiring (a RunOnce dispatch table that selects per-state
// handlers) lands in Task 22 after Task 17 (Live Batcher) and Task 18
// (heartbeat) introduce the shared recv goroutine.
type Options struct {
	// Dialer establishes the underlying gRPC stream. Required.
	Dialer Dialer
	// AgentID identifies the agent process. Required. Supplied by the
	// agent's identity layer (build/runtime config); echoed in
	// SessionInit so the server can scope the session.
	AgentID string
	// SessionID identifies the session. Required. Supplied by the
	// session-management layer.
	SessionID string
	// FormatVersion is sent in SessionInit; defaults to 2.
	FormatVersion uint32
	// Algorithm is the chain HMAC algorithm advertised in SessionInit.
	// Supplied by chain config; defaults to HASH_ALGORITHM_HMAC_SHA256
	// in New() so the proto validator (wtpv1.ValidateSessionInit)
	// accepts the frame.
	Algorithm wtpv1.HashAlgorithm
	// AgentVersion identifies the running agent build. An agent build
	// constant — populated by the build/wiring layer.
	AgentVersion string
	// OcsfVersion is the OCSF schema version the sink emits. An agent
	// build constant — populated by the build/wiring layer.
	OcsfVersion string
	// KeyFingerprint identifies the active signing key (hex-encoded).
	// Supplied by chain config (KMS/key provider); empty until sink
	// wiring (Task 27).
	KeyFingerprint string
	// ContextDigest is the hex-encoded SHA-256 of the session context.
	// Computed at sink integration (Task 27) over the agent's
	// session-context inputs (see chain.SessionContext).
	ContextDigest string
	// TotalChained is the count of records the sink has chained so far.
	// Running count from chain.SinkChain; supplied by sink integration.
	TotalChained uint64
}

// validate enforces the construction-time invariants documented on
// Options. It is called by New before any defaults are applied.
func validate(opts Options) error {
	if opts.Dialer == nil {
		return errors.New("transport: nil Dialer")
	}
	if opts.AgentID == "" {
		return errors.New("transport: AgentID required")
	}
	if opts.SessionID == "" {
		return errors.New("transport: SessionID required")
	}
	return nil
}

// Transport runs the four-state WTP client state machine. It is owned by
// a single goroutine — callers interact via channels.
type Transport struct {
	opts Options
	conn Conn

	// ackedSequence/ackedGeneration TOGETHER hold the EFFECTIVE ack watermark
	// — the clamped (gen, seq) tuple per spec §"Acknowledgement model"
	// (design.md:601). The two fields MOVE TOGETHER; mixing local-seq with
	// server-gen (or vice versa) creates an impossible state under the WAL's
	// lex-(gen, seq) GC semantics (see wal/wal.go MarkAcked / segmentFullyAckedLocked).
	//
	// Clamp rule on every server-supplied watermark (SessionAck, BatchAck,
	// ServerHeartbeat):
	//   - if (server_gen, server_seq) < (local_gen, local_seq) lex: ADOPT the
	//     server tuple wholesale (both fields). This is the legitimate
	//     stale-watermark recovery path during gradual rollout / partition
	//     recovery.
	//   - if (server_gen, server_seq) > (local_gen, local_seq) lex: KEEP the
	//     local tuple wholesale (both fields). Log a WARN with FULL tuple
	//     context (server_gen, server_seq, local_gen, local_seq) per the
	//     anomaly-log contract in spec §"Acknowledgement model".
	//   - if equal: no-op.
	//
	// Seeded on cold start from wal.Meta (see Task 15.1 startup-seed step) and
	// then advanced by SessionAck (state_connecting.go) and by BatchAck/
	// ServerHeartbeat handlers in the recv multiplexer (Tasks 17/18) — all of
	// them via the same clamp helper. Read by Replaying/Live state handlers
	// for their reader-start calculations; state handlers do NOT advance these
	// fields.
	//
	// SessionUpdate is NOT an acknowledgement — it is a control frame for
	// key/generation rotation per spec §"Acknowledgement model" (design.md:617);
	// it never advances ackedSequence/ackedGeneration.
	ackedSequence   uint64
	ackedGeneration uint32

	// rejectReason is populated when the server rejects the session
	// (SessionAck.accepted=false). Surfaced via RejectReason().
	rejectReason string
}

// New constructs a Transport. It does not dial; call Run to start.
// New validates the required Options fields and returns an error if any
// are missing so misconfiguration fails at construction rather than
// inside the run loop.
func New(opts Options) (*Transport, error) {
	if err := validate(opts); err != nil {
		return nil, err
	}
	if opts.FormatVersion == 0 {
		opts.FormatVersion = 2
	}
	if opts.Algorithm == wtpv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		opts.Algorithm = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256
	}
	return &Transport{opts: opts}, nil
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
