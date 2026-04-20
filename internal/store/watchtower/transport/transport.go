package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"golang.org/x/time/rate"
)

// Metrics is the production-side counter/gauge surface the Transport calls
// into. The real implementation is *internal/metrics.WTPMetrics; tests
// substitute fakes. New() defaults to a no-op when Options.Metrics is nil
// so callers can construct a Transport without wiring metrics.
type Metrics interface {
	SetAckHighWatermark(seq int64)
	IncAnomalousAck(reason string)
	IncResendNeeded()
	IncAckRegressionLoss()
}

type noopMetrics struct{}

func (noopMetrics) SetAckHighWatermark(int64)  {}
func (noopMetrics) IncAnomalousAck(string)     {}
func (noopMetrics) IncResendNeeded()           {}
func (noopMetrics) IncAckRegressionLoss()      {}

// AckTuple is the persisted (gen, seq) ack pair seeded from wal.Meta on
// cold start. Present=false means the WAL has never recorded an ack
// (meta.AckRecorded=false) — the Transport treats the next server-supplied
// tuple as the first-apply seed.
type AckTuple struct {
	Sequence   uint64
	Generation uint32
	Present    bool
}

// AckCursor is a (gen, seq) pair compared lexicographically. Used for both
// persistedAck (mirrors wal.Meta) and remoteReplayCursor (server-belief).
type AckCursor struct {
	Sequence   uint64
	Generation uint32
}

// AckOutcomeKind classifies the result of applyServerAckTuple. The dispatch
// site in state_connecting.go (and the recv multiplexer in Tasks 17/18) uses
// this to decide whether to persist via wal.MarkAcked, log/metric an
// anomaly, or no-op.
type AckOutcomeKind int

const (
	// AckOutcomeNoOp means the server's tuple matched the persistedAck
	// exactly — neither cursor moved.
	AckOutcomeNoOp AckOutcomeKind = iota
	// AckOutcomeAdopted means the server tuple is a healthy advance.
	// Both persistedAck and remoteReplayCursor moved to the server tuple.
	// Caller MUST persist via wal.MarkAcked; on failure the cursors are
	// rolled back.
	AckOutcomeAdopted
	// AckOutcomeResendNeeded means same-gen lex-lower: server is behind
	// persistedAck. Only remoteReplayCursor moved; persistedAck stays in
	// lock-step with on-disk meta.json.
	AckOutcomeResendNeeded
	// AckOutcomeAnomaly means the server tuple is in one of five disjoint
	// shapes that cannot be reconciled in-band: stale_generation,
	// unwritten_generation, server_ack_exceeds_local_data,
	// server_ack_exceeds_local_seq, or wal_read_failure. Cursors UNCHANGED.
	AckOutcomeAnomaly
)

// AckOutcome carries the helper's classification plus the post-clamp
// cursors so the dispatch site can persist/log without re-reading
// Transport fields.
type AckOutcome struct {
	Kind              AckOutcomeKind
	PersistedTuple    AckCursor
	ReplayCursor      AckCursor
	PersistedAdvanced bool
	// AnomalyReason is one of the five labels documented on
	// AckOutcomeAnomaly. Empty for non-Anomaly outcomes.
	AnomalyReason string
}

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

	// InitialAckTuple seeds persistedAck/remoteReplayCursor at construction.
	// Populated by the Task 27 wiring layer from wal.ReadMeta. nil ⇒
	// persistedAckPresent=false (first-apply path: next server tuple is
	// adopted ONLY after wal.WrittenDataHighWater(serverGen) validates
	// the seq is within local data; vacuous serverSeq==0 short-circuits
	// to adopt; unwritten/over-tip server tuples take the Anomaly path
	// per round-15 Finding 1).
	InitialAckTuple *AckTuple
	// Logger is the slog handle used for anomaly/info diagnostics.
	// Defaults to slog.Default() in New() when nil.
	Logger *slog.Logger
	// WAL is the WAL handle used for ack persistence and per-generation
	// data-bearing high-water lookups. nil is permitted — the helper
	// treats WAL accessors as ok=false and the MarkAcked dispatch as a
	// no-op. Production callers (Task 27 wiring) MUST supply this.
	WAL *wal.WAL
	// Metrics is the counter/gauge surface. Defaults to a no-op when nil.
	Metrics Metrics
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

	// Two-cursor ack model per spec §"Acknowledgement model" (round-13
	// design.md "Effective-ack tuple and clamp"). The cursors split the
	// server's ack into two operationally distinct quantities:
	//
	//   - persistedAck: monotonic mirror of wal.Meta. Advances ONLY on
	//     AckOutcomeAdopted, AFTER wal.MarkAcked succeeds. Drives the
	//     SessionInit watermark and the per-generation GC predicate.
	//   - remoteReplayCursor: server-belief about its high-water. May
	//     regress on AckOutcomeResendNeeded (legitimate stale ack from a
	//     newer server replica) or hold steady on Anomaly. Drives the
	//     replay reader's start cursor.
	//
	// Both cursors are seeded from Options.InitialAckTuple at construction
	// (Task 27 wiring layer reads wal.Meta and supplies the tuple). When
	// no InitialAckTuple is supplied, persistedAckPresent stays false and
	// the next server tuple takes the first-apply path.
	persistedAck        AckCursor
	persistedAckPresent bool
	remoteReplayCursor  AckCursor

	// metrics, wal, ackAnomalyLimiter are convenience shortcuts wired in
	// New() from Options. Defaults: Metrics=noopMetrics{}, Logger via
	// opts.Logger, ackAnomalyLimiter=rate.Every(1m)/burst 1.
	wal               *wal.WAL
	metrics           Metrics
	ackAnomalyLimiter *rate.Limiter

	// walMarkAckedFn / walWrittenDataHighWaterFn / walEarliestDataSequenceFn /
	// walHighGenerationFn are seams the helper calls instead of t.wal.*
	// directly. New() wires them to t.wal.* when wal != nil and to safe stubs
	// (no-op success / ok=false / 0) otherwise. Test code overrides via
	// SetWAL*FnForTest in seams_export_test.go to inject error paths.
	walMarkAckedFn            func(gen uint32, seq uint64) error
	walWrittenDataHighWaterFn func(gen uint32) (uint64, bool, error)
	walEarliestDataSequenceFn func(gen uint32) (uint64, bool, error)
	walHighGenerationFn       func() uint32

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
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = noopMetrics{}
	}
	t := &Transport{
		opts:              opts,
		wal:               opts.WAL,
		metrics:           opts.Metrics,
		ackAnomalyLimiter: rate.NewLimiter(rate.Every(time.Minute), 1),
	}
	if opts.InitialAckTuple != nil && opts.InitialAckTuple.Present {
		seed := AckCursor{
			Sequence:   opts.InitialAckTuple.Sequence,
			Generation: opts.InitialAckTuple.Generation,
		}
		t.persistedAck = seed
		t.remoteReplayCursor = seed
		t.persistedAckPresent = true
	}
	if t.wal != nil {
		t.walMarkAckedFn = t.wal.MarkAcked
		t.walWrittenDataHighWaterFn = t.wal.WrittenDataHighWater
		t.walEarliestDataSequenceFn = t.wal.EarliestDataSequence
		t.walHighGenerationFn = t.wal.HighGeneration
	} else {
		t.walMarkAckedFn = func(uint32, uint64) error { return nil }
		t.walWrittenDataHighWaterFn = func(uint32) (uint64, bool, error) { return 0, false, nil }
		t.walEarliestDataSequenceFn = func(uint32) (uint64, bool, error) { return 0, false, nil }
		t.walHighGenerationFn = func() uint32 { return 0 }
	}
	return t, nil
}

// RejectReason returns the reject_reason surfaced by the most recent
// SessionAck with accepted=false. It is empty until the server rejects
// the session.
func (t *Transport) RejectReason() string {
	return t.rejectReason
}

// sessionInit returns the SessionInit message for the current connection.
// The ack watermark is taken from persistedAck — the on-disk-mirrored
// cursor — so a reconnect carries the durable position even if the
// previous session's remoteReplayCursor regressed via ResendNeeded.
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
				WalHighWatermarkSeq: t.persistedAck.Sequence,
				Generation:          t.persistedAck.Generation,
				AgentId:             t.opts.AgentID,
				AgentVersion:        t.opts.AgentVersion,
				TotalChained:        t.opts.TotalChained,
			},
		},
	}
}

// applyServerAckTuple is the SINGLE source of truth for the two-cursor ack
// clamp. The SessionAck handler (state_connecting.go) and the recv
// multiplexer's BatchAck/ServerHeartbeat handlers (Tasks 17/18) all
// dispatch through this helper.
//
// The helper mutates the in-memory cursors but does NOT call
// wal.MarkAcked — the dispatch site is responsible for persistence so it
// can roll back the cursors on persistence failure.
//
// See AckOutcomeKind constants for the five disjoint outcomes.
func (t *Transport) applyServerAckTuple(serverGen uint32, serverSeq uint64) AckOutcome {
	server := AckCursor{Sequence: serverSeq, Generation: serverGen}

	// First-apply: seed both cursors from the server tuple, but ONLY after
	// validating it against local WAL data — otherwise a server ack pointing
	// past anything we ever wrote (e.g. stale durable state on the server
	// after the agent's WAL was wiped/restored from a snapshot) would seed
	// persistedAck at an impossible position, advance the GC predicate, and
	// permanently delete records that have not yet been delivered.
	//
	// Validation rules (mirror the cross-gen and same-gen-advance branches):
	//   - serverSeq == 0: vacuous "I haven't acked anything yet" — adopt
	//     unconditionally; no record can be over-acked.
	//   - WAL read failure → Anomaly("wal_read_failure"). Cursors UNCHANGED;
	//     persistedAckPresent stays false so the next ack re-runs the seed
	//     gate against a (presumably) recovered WAL.
	//   - WrittenDataHighWater(serverGen) ok=false → Anomaly(
	//     "unwritten_generation"): no data ever written for this generation
	//     locally, so the server cannot legitimately ack any seq in it.
	//   - serverSeq > maxDataSeq → Anomaly("server_ack_exceeds_local_data"):
	//     the server is past our highest local data-bearing seq.
	if !t.persistedAckPresent {
		if serverSeq == 0 {
			t.persistedAck = server
			t.persistedAckPresent = true
			t.remoteReplayCursor = server
			return AckOutcome{
				Kind:              AckOutcomeAdopted,
				PersistedTuple:    server,
				ReplayCursor:      server,
				PersistedAdvanced: true,
			}
		}
		maxDataSeq, haveData, walErr := t.walWrittenDataHighWaterFn(serverGen)
		if walErr != nil {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "wal_read_failure",
			}
		}
		if !haveData {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "unwritten_generation",
			}
		}
		if serverSeq > maxDataSeq {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "server_ack_exceeds_local_data",
			}
		}
		t.persistedAck = server
		t.persistedAckPresent = true
		t.remoteReplayCursor = server
		return AckOutcome{
			Kind:              AckOutcomeAdopted,
			PersistedTuple:    server,
			ReplayCursor:      server,
			PersistedAdvanced: true,
		}
	}

	// Cross-generation: refined taxonomy (round-12 unified with same-gen).
	if serverGen < t.persistedAck.Generation {
		return AckOutcome{
			Kind:           AckOutcomeAnomaly,
			PersistedTuple: t.persistedAck,
			ReplayCursor:   t.remoteReplayCursor,
			AnomalyReason:  "stale_generation",
		}
	}
	if serverGen > t.persistedAck.Generation {
		maxDataSeq, haveData, walErr := t.walWrittenDataHighWaterFn(serverGen)
		if walErr != nil {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "wal_read_failure",
			}
		}
		if !haveData {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "unwritten_generation",
			}
		}
		if serverSeq > maxDataSeq {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "server_ack_exceeds_local_data",
			}
		}
		t.persistedAck = server
		t.remoteReplayCursor = server
		return AckOutcome{
			Kind:              AckOutcomeAdopted,
			PersistedTuple:    server,
			ReplayCursor:      server,
			PersistedAdvanced: true,
		}
	}

	// Same-generation lex compare on seq.
	switch {
	case serverSeq > t.persistedAck.Sequence:
		maxDataSeq, haveData, walErr := t.walWrittenDataHighWaterFn(serverGen)
		if walErr != nil {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "wal_read_failure",
			}
		}
		if !haveData || serverSeq > maxDataSeq {
			return AckOutcome{
				Kind:           AckOutcomeAnomaly,
				PersistedTuple: t.persistedAck,
				ReplayCursor:   t.remoteReplayCursor,
				AnomalyReason:  "server_ack_exceeds_local_seq",
			}
		}
		t.persistedAck = server
		t.remoteReplayCursor = server
		return AckOutcome{
			Kind:              AckOutcomeAdopted,
			PersistedTuple:    server,
			ReplayCursor:      server,
			PersistedAdvanced: true,
		}
	case serverSeq < t.persistedAck.Sequence:
		t.remoteReplayCursor = server
		return AckOutcome{
			Kind:           AckOutcomeResendNeeded,
			PersistedTuple: t.persistedAck,
			ReplayCursor:   server,
		}
	default:
		return AckOutcome{
			Kind:           AckOutcomeNoOp,
			PersistedTuple: t.persistedAck,
			ReplayCursor:   t.remoteReplayCursor,
		}
	}
}

// computeReplayStart is the canonical helper that returns the
// (prefixLoss, readerStart) tuple for the Replaying state's reader-open
// path. See plan §"Step 1b.5" / spec §"Loss between replay cursor and
// persisted ack" for the four-case decision tree.
//
// Same-generation invariant: by the time this code runs, the cursor split
// has already classified cross-gen as Anomaly (cursors unchanged), so
// remoteReplayCursor.Generation == persistedAck.Generation by construction.
//
// Returns:
//   - prefixLoss != nil: an in-memory wal.LossRecord describing a GC'd gap.
//     NOT persisted. The Replayer surfaces it as the first record of the
//     first NextBatch via ReplayerOptions.PrefixLoss (Task 22 wiring).
//   - readerStart: the seq the WAL Reader should be opened at.
//   - err != nil: a hard I/O error reading WAL state. The caller MUST
//     treat this as a transport error and reconnect.
func (t *Transport) computeReplayStart(remoteReplayCursor AckCursor, persistedAck AckCursor) (*wal.LossRecord, uint64, error) {
	earliestOnDisk, ok, err := t.walEarliestDataSequenceFn(persistedAck.Generation)
	if err != nil {
		return nil, 0, fmt.Errorf("ack_regression_check: wal.EarliestDataSequence: %w", err)
	}
	gapStart := remoteReplayCursor.Sequence + 1

	var prefixLoss *wal.LossRecord
	var readerStart uint64
	switch {
	case ok && earliestOnDisk > gapStart:
		// Case A — partial GC.
		prefixLoss = &wal.LossRecord{
			FromSequence: gapStart,
			ToSequence:   earliestOnDisk - 1,
			Generation:   persistedAck.Generation,
			Reason:       "ack_regression_after_gc",
		}
		readerStart = earliestOnDisk
	case ok && earliestOnDisk <= gapStart:
		// Case B — no gap.
		readerStart = gapStart
	case !ok && gapStart <= persistedAck.Sequence:
		// Case C — fully GC'd, server BEHIND persistedAck.
		prefixLoss = &wal.LossRecord{
			FromSequence: gapStart,
			ToSequence:   persistedAck.Sequence,
			Generation:   persistedAck.Generation,
			Reason:       "ack_regression_after_gc",
		}
		readerStart = gapStart
	default:
		// Case D — fully GC'd, server AT OR PAST persistedAck. Defensive.
		readerStart = gapStart
	}

	if prefixLoss != nil {
		// Round-13 Finding 5: counter is incremented at EMIT time by the
		// Replayer's OnPrefixLossEmitted callback (wired in Task 22).
		// The INFO log fires here because it describes the inputs that
		// led to the synthesized loss — meaningful even if the loss is
		// never emitted (the Run loop may abort before NextBatch).
		t.opts.Logger.LogAttrs(context.Background(), slog.LevelInfo,
			"ack_regression_check: synthesized in-memory loss for GC'd gap",
			slog.Uint64("from_seq", prefixLoss.FromSequence),
			slog.Uint64("to_seq", prefixLoss.ToSequence),
			slog.Uint64("gen", uint64(prefixLoss.Generation)),
			slog.Uint64("remote_replay_seq", remoteReplayCursor.Sequence),
			slog.Bool("earliest_on_disk_present", ok),
			slog.Uint64("earliest_on_disk_seq", earliestOnDisk),
			slog.Uint64("local_persisted_seq", persistedAck.Sequence),
			slog.String("session_id", t.opts.SessionID))
	}
	return prefixLoss, readerStart, nil
}

// ReplayStage is one entry in the multi-generation replay plan returned by
// computeReplayPlan. Each stage maps to one generation-scoped wal.Reader
// the Replaying state will open in sequence.
//
// Stages are returned in ascending generation order. The first stage covers
// persistedAck.Generation and may carry an in-memory PrefixLoss synthesized
// by computeReplayStart for an ack_regression_after_gc gap. Subsequent
// stages cover gen=persistedAck.Generation+1 .. HighGeneration() and start
// at seq=0 (the WAL Reader handles header-record skipping internally); they
// never carry a PrefixLoss because the cursor split has no per-generation
// state for "future" generations.
type ReplayStage struct {
	// Generation is the WAL generation this stage will replay. The
	// Replaying state opens a Reader pinned to this generation via
	// ReaderOptions.Generation (Task 14b).
	Generation uint32
	// StartSeq is the seq the Reader should be opened at. For the first
	// stage this is computeReplayStart's readerStart; for later stages it
	// is 0 ("from the start of this generation").
	StartSeq uint64
	// PrefixLoss is the in-memory wal.LossRecord the Replayer should
	// surface as the first record of the first NextBatch via
	// ReplayerOptions.PrefixLoss. nil for stages that have no synthesized
	// loss. Only the first stage may have a non-nil PrefixLoss.
	PrefixLoss *wal.LossRecord
}

// computeReplayPlan returns the ordered list of replay stages the
// Replaying state should drain before transitioning to Live. The plan
// covers persistedAck.Generation (with the four-case decision tree from
// computeReplayStart) plus every higher generation that has data on
// disk, up to and including HighGeneration().
//
// Why multi-stage: the WAL is generation-scoped (Task 14b). After a
// reconnect that lands in StateConnecting → StateReplaying, the plan must
// cover BOTH the still-unacked tail of persistedAck.Generation AND any
// records in later generations that were appended before the disconnect
// (e.g. the agent rolled to gen+1 mid-session, wrote 100 records, then
// the link died before the server could ack into gen+1). Without this
// orchestrator the Replaying state would only drain persistedAck.Generation
// and hand off to Live, dropping the later-gen backlog on the floor — the
// reconnect would not surface those records until the agent appended a new
// record to wake the Live Reader, and even then only the post-wake records
// would be sent.
//
// Stages are returned in strictly ascending generation order. The
// Replaying state handler is responsible for opening one Reader per stage,
// draining via Replayer.NextBatch, and only entering Live after the LAST
// stage's done flag is true. (Task 22 wires this orchestration; Task
// 17/18 land the recv multiplexer that the Replaying state still depends
// on per state_replaying.go runReplaying header.)
//
// Returns:
//   - []ReplayStage: at least one stage (the persistedAck.Generation stage
//     is always present, even if it has no records to drain — the caller
//     decides whether to skip it based on Reader.TryNext returning ok=false
//     immediately).
//   - err != nil: a hard I/O error reading WAL state. The caller MUST
//     treat this as a transport error and reconnect. Errors from
//     computeReplayStart (the first-stage call) and from
//     walWrittenDataHighWaterFn (later-stage probes) are both surfaced
//     here unchanged; on error the partial plan is discarded.
func (t *Transport) computeReplayPlan(remoteReplayCursor AckCursor, persistedAck AckCursor) ([]ReplayStage, error) {
	prefixLoss, readerStart, err := t.computeReplayStart(remoteReplayCursor, persistedAck)
	if err != nil {
		return nil, err
	}
	stages := []ReplayStage{{
		Generation: persistedAck.Generation,
		StartSeq:   readerStart,
		PrefixLoss: prefixLoss,
	}}

	highGen := t.walHighGenerationFn()
	// Iterate strictly past persistedAck.Generation. HighGeneration() is
	// the highest generation the WAL has observed (set from segment
	// headers); per Task 14b the Reader is generation-scoped, so we probe
	// each later gen in turn and skip those with no data-bearing records
	// (e.g. an empty rolled generation that only has a header). Bail on
	// uint32 wraparound: persistedAck.Generation == math.MaxUint32 is a
	// degenerate state but skipping the loop is the safe action.
	for gen := persistedAck.Generation + 1; gen <= highGen && gen > persistedAck.Generation; gen++ {
		_, haveData, walErr := t.walWrittenDataHighWaterFn(gen)
		if walErr != nil {
			return nil, fmt.Errorf("computeReplayPlan: wal.WrittenDataHighWater(gen=%d): %w", gen, walErr)
		}
		if !haveData {
			continue
		}
		stages = append(stages, ReplayStage{
			Generation: gen,
			StartSeq:   0,
			PrefixLoss: nil,
		})
	}
	return stages, nil
}
