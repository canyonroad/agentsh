package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
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
	IncDroppedInvalidFrame(reason metrics.WTPInvalidFrameReason)
}

type noopMetrics struct{}

func (noopMetrics) SetAckHighWatermark(int64)                             {}
func (noopMetrics) IncAnomalousAck(string)                                {}
func (noopMetrics) IncResendNeeded()                                      {}
func (noopMetrics) IncAckRegressionLoss()                                 {}
func (noopMetrics) IncDroppedInvalidFrame(metrics.WTPInvalidFrameReason) {}

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

	// LogGoawayMessage controls whether the Goaway WARN log emitted
	// by the recv-multiplexer fail-closed branch (Task 22d) includes
	// the server-supplied message text verbatim (after sanitization).
	// Defaults to false (conservative posture) — the message is
	// OMITTED from the log payload and only a goaway_message_present
	// boolean marker is emitted.
	//
	// Setting this to true is OPT-IN and is gated on the Watchtower-
	// server-side contract that forbids secrets, credentials, or PII
	// in Goaway.message. That contract lives in the canyonroad repo
	// (Watchtower server team — see spec §"`goaway_message`
	// redaction policy" for the follow-up tracker). Operators who
	// set this to true while the contract is pending take
	// responsibility for their own server-side redaction posture
	// (e.g. by trusting only their own internal Watchtower
	// deployments).
	//
	// Independent of this flag, ALL logged Goaway message text is
	// passed through sanitizeForLog — invalid UTF-8 is replaced with
	// U+FFFD, all C0 control characters (including \t and \n) are
	// replaced with U+FFFD, and the output is truncated to at most
	// 512 bytes with a literal `...[truncated]` marker.
	//
	// This field is internal/construction-time only on
	// transport.Options. It is NOT yet exposed via
	// AuditWatchtowerConfig or daemon-facing config; Task 27b owns
	// the config-surface expansion.
	LogGoawayMessage bool

	// BackoffInitial is the starting duration for the exponential back-off
	// between reconnect attempts. Zero means "use the default" (200 ms),
	// which applyBackoffDefaults fills in before Run starts. Supplied by
	// the watchtower.Options threading path in store.go.
	BackoffInitial time.Duration
	// BackoffMax is the ceiling for the exponential back-off. Zero means
	// "use the default" (30 s). Supplied by the watchtower.Options threading
	// path in store.go.
	BackoffMax time.Duration
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

// ErrTransportSingleUse is returned by Run when invoked a second
// time on the same Transport. Transport is single-use per run-loop
// lifetime — callers MUST construct a fresh Transport via New() to
// reconnect. Per Task 27c: making Transport explicitly single-use
// avoids the close-of-closed-channel panic that would otherwise
// fire at `defer close(t.runDone)`.
var ErrTransportSingleUse = errors.New("transport: Run already invoked; Transport is single-use")

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
	// walHighGenerationFn / walHasDataBelowGenerationFn / walHasReplayableRecordsFn
	// are seams the helper calls instead of t.wal.* directly. New() wires
	// them to t.wal.* when wal != nil and to safe stubs (no-op success /
	// ok=false / 0 / false) otherwise. Test code overrides via
	// SetWAL*FnForTest in seams_export_test.go to inject error paths.
	walMarkAckedFn              func(gen uint32, seq uint64) error
	walWrittenDataHighWaterFn   func(gen uint32) (uint64, bool, error)
	walEarliestDataSequenceFn   func(gen uint32) (uint64, bool, error)
	walHighGenerationFn         func() uint32
	walHasDataBelowGenerationFn func(threshold uint32) (bool, error)
	walHasReplayableRecordsFn   func(gen uint32) (bool, error)

	// rejectReason is populated when the server rejects the session
	// (SessionAck.accepted=false). Surfaced via RejectReason().
	rejectReason string

	// stopCh carries Stop requests into the Run loop per Task 19. The
	// channel is buffered with cap 1 so a single in-flight Stop fits
	// even when no state currently has a select arm consuming it; the
	// Run loop's per-iteration check (or the StateLive select arm)
	// drains it on the next pass. See Stop / runShutdown.
	stopCh chan stopReq

	// runDone is closed by Run's defer when the run loop returns
	// (any path: ctx cancel, Stop, or terminal error such as
	// SessionAck rejection). Stop selects on this channel so it
	// returns promptly when called AFTER Run has already exited —
	// without it, Stop's <-r.done wait would deadlock because no
	// consumer is left to service stopReq. Per Task 27c.
	runDone chan struct{}

	// runStarted guards Run's single-use contract. Set true on the
	// first Run invocation; subsequent calls return
	// ErrTransportSingleUse rather than panicking on
	// `close(t.runDone)`. Per Task 27c.
	runStarted atomic.Bool

	// recv holds the per-connection recv-multiplexer state per round-22
	// plan §"Per-connection recv state". A new recvSession is created on
	// each successful dial and discarded on every tear-down; the field
	// is nil when no recv goroutine is running (between connections, or
	// in tests that drive applyAckFromRecv directly without a dial).
	//
	// Channel reads in the state-machine select arms are gated on
	// `t.recv != nil` — Go's nil-channel semantics make those select
	// arms dormant when the field is nil, preserving the "recv goroutine
	// not started yet" behaviour that recv-clamp unit tests rely on.
	//
	// Every state exit path that tears down the conn MUST cancel the
	// session's ctx and nil out this field (round-22 Finding 2). The
	// per-connection ctx is the only thing that can wake a recv
	// goroutine blocked on a full event channel; the transport-wide
	// ctx alone is insufficient because state-local errors must be
	// able to drop a connection without shutting down the transport.
	recv *recvSession
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
		stopCh:            make(chan stopReq, 1),
		runDone:           make(chan struct{}),
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
		t.walHasDataBelowGenerationFn = t.wal.HasDataBelowGeneration
		t.walHasReplayableRecordsFn = t.wal.HasReplayableRecords
	} else {
		t.walMarkAckedFn = func(uint32, uint64) error { return nil }
		t.walWrittenDataHighWaterFn = func(uint32) (uint64, bool, error) { return 0, false, nil }
		t.walEarliestDataSequenceFn = func(uint32) (uint64, bool, error) { return 0, false, nil }
		t.walHighGenerationFn = func() uint32 { return 0 }
		t.walHasDataBelowGenerationFn = func(uint32) (bool, error) { return false, nil }
		t.walHasReplayableRecordsFn = func(uint32) (bool, error) { return false, nil }
	}
	return t, nil
}

// RejectReason returns the reject_reason surfaced by the most recent
// SessionAck with accepted=false. It is empty until the server rejects
// the session.
func (t *Transport) RejectReason() string {
	return t.rejectReason
}

// LogGoawayMessage returns the LogGoawayMessage option the Transport was
// constructed with. Used by watchtower.Store's test seam
// (TransportLogGoawayMessageForTest in store_export_test.go) to assert that
// store.go correctly wires opts.LogGoawayMessage through to transport.New.
func (t *Transport) LogGoawayMessage() bool {
	return t.opts.LogGoawayMessage
}

// stopReq carries a Stop request through the run loop. The done channel
// is closed by whichever loop branch services the request, which
// unblocks the Stop caller. drainDeadline bounds how long runShutdown
// will pull additional records before flushing and CloseSend'ing.
type stopReq struct {
	drainDeadline time.Duration
	done          chan struct{}
}

// Stop signals the transport to best-effort flush pending records (up
// to drainDeadline in Live) and tear down the conn. It blocks until
// the run loop has finished servicing the request.
//
// Stop is observed ONLY at interruptible checkpoints of the run loop.
// It CANNOT preempt a blocked `Dial`, `Send`, `Recv`, or `NextBatch`
// call — those are synchronous from the main goroutine's perspective
// and Stop has no mechanism to asynchronously cancel them. Callers
// that need a bounded shutdown while blocked I/O is in flight must
// combine Stop with an operation-specific cancellation lever. Each
// lever has different reach:
//
//   - Blocked `Dial`: only parent-ctx cancellation or a dialer-
//     specific cancel is effective. There is no Conn to Close out-
//     of-band — the Conn does not exist until Dial returns. If the
//     dialer ignores ctx, there is NO mechanism in this MVP to
//     unblock a hung Dial.
//   - Blocked `Send` (runLive, runReplaying, runConnecting's
//     SessionInit): out-of-band `Conn.Close` from another goroutine
//     (the test seam model) unblocks the Send by returning a stream-
//     closed error; parent-ctx cancellation is NOT plumbed into the
//     Conn layer's Send today.
//   - Blocked `Recv` (runConnecting's SessionAck, runRecv's demux
//     goroutine): same as Send — out-of-band `Conn.Close` unblocks,
//     parent-ctx is not plumbed.
//   - Replay-side `NextBatch`: ctx is consulted only between TryNext
//     calls inside NextBatch (see replayer.NextBatch ctx check). The
//     WAL Reader.TryNext itself has no ctx hook (see reader.go
//     TryNext), so ctx cancellation is observed only at the ~per-
//     record boundaries that NextBatch visits. For most batch sizes
//     this is sufficient; for very large single-batch caps, the
//     latency is bounded by the number of records in a batch.
//
// Interruptible checkpoints (Stop is observed here within one
// scheduler hop):
//
//   - Top-of-iteration select (handleOuterStop).
//   - Each of the three backoff sleeps (Connecting / Replaying
//     stage-error / Live-error) — `time.After(bo.Next())` shares the
//     select with stopCh.
//   - Between replay iterations in runReplaying (`case sr := <-t.stopCh`
//     at the top of its drain-and-send loop).
//   - Inside runLive's main select alongside ctx.Done, Notify,
//     recvEventCh, recvErrCh, and tick.C.
//
// NOT interruptible windows (Stop queues into the buffered stopCh but
// does not service until the blocked call returns via the per-
// operation levers documented above):
//
//   - Inside runConnecting's Dialer.Dial, Send(SessionInit), or
//     Recv(SessionAck) — runConnecting has no stopCh arm.
//   - Inside runReplaying's `Replayer.NextBatch` or `Conn.Send`
//     (the stopCh case only runs at the top of the loop, not mid-
//     send).
//   - Inside runLive's `Conn.Send`.
//
// Stop is single-use. A second call may block forever because the run
// loop has already returned and nothing will close done. The intended
// pairing is:
//
//	runDone := make(chan error, 1)
//	go func() { runDone <- tr.Run(ctx, ...) }()
//	...
//	tr.Stop(drainDeadline) // blocks until Run services the request
//	<-runDone              // Run returns nil after Stop
//
// Stop-vs-Run-exit race: if Run has already returned (via ctx
// cancellation, a terminal StateShutdown error, or some other exit),
// the buffered send into stopCh succeeds but nothing closes done, so
// Stop will hang. Callers that want Stop to be safe in either order
// should check Run's return channel before calling Stop, or use a
// sync.Once + non-blocking select wrapper at the call site. The
// store-integration task (Task 22/27) that owns both Run's goroutine
// and the Stop call site is the natural place to enforce this
// ordering; Task 19 does not add a runtime guard because it would
// require a second done-channel on Transport that the current plan
// does not model.
//
// Behavior by state when Stop is observed:
//
//   - StateLive: runLive's select arm consumes the request, calls
//     runShutdown for a best-effort drain, full-tears down the conn,
//     and returns StateShutdown. The Run loop exits nil.
//   - StateReplaying: runReplaying's select arm (at the top of its
//     loop, between NextBatch iterations) consumes the request,
//     aborts in-flight replay (no drain — replay is send-after-build
//     with no batcher to flush), full-tears down the conn, and
//     returns StateShutdown. The Run loop exits nil.
//   - Backoff sleep between any state and Connecting: the sleep's
//     stopCh arm fires, handleOuterStop tears down any held conn,
//     and Run returns nil.
//   - Between state transitions (top-of-iteration check): same as
//     the backoff-sleep path.
//
// In all non-Live paths the drain is effectively no-op; drainDeadline
// is consulted only by runShutdown.
func (t *Transport) Stop(drainDeadline time.Duration) {
	t.stopWithHooks(drainDeadline, nil, nil)
}

// stopWithHooks is the shared implementation behind Stop and the
// test-only EnqueueStopAndWaitForTest seam. Splitting it here means
// both the public Stop path and the instrumented test path go
// through the same enqueue/wait code: a regression in either step
// is observable through both entry points.
//
// preEnqueue / postEnqueue are called synchronously around the
// `t.stopCh <- r` send. Production Stop passes nil for both (no-ops);
// tests pass the hooks they need.
//
// A nil t.stopCh (New not yet called, or a direct zero-value
// Transport) is treated as an instant no-op — this matches the
// public Stop's previous behavior and avoids a panic on uninitialized
// instances.
func (t *Transport) stopWithHooks(drainDeadline time.Duration, preEnqueue, postEnqueue func()) {
	if t.stopCh == nil {
		return
	}
	if preEnqueue != nil {
		preEnqueue()
	}
	r := stopReq{drainDeadline: drainDeadline, done: make(chan struct{})}
	// Fast-path: if Run has already exited, bail BEFORE the enqueue
	// select. A plain `select { case stopCh <- r: case <-runDone: }`
	// is racy when stopCh has buffer slack and runDone is closed —
	// Go picks randomly among ready arms, so the send sometimes
	// wins and postEnqueue fires for a request nobody will service.
	// Per Task 27c.
	select {
	case <-t.runDone:
		return
	default:
	}
	// Enqueue, still racing runDone in case Run exits between the
	// fast-path check and now.
	//
	// postEnqueue is documented to fire AFTER a successful send to
	// stopCh; on the runDone bail-out below the send did NOT happen,
	// so postEnqueue is intentionally NOT invoked.
	select {
	case t.stopCh <- r:
	case <-t.runDone:
		return
	}
	if postEnqueue != nil {
		postEnqueue()
	}
	// Wait for the run loop to service the request OR for it to have
	// exited via another path between enqueue and now.
	select {
	case <-r.done:
	case <-t.runDone:
	}
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
	//   - serverSeq == 0: "I haven't acked anything yet" within serverGen.
	//     Vacuous within the same generation, but adopting (G, 0) when local
	//     data exists at any (g < G) lex-over-acks all of that lower-gen data
	//     via wal.MarkAcked's (gen, seq) compare. Validate with
	//     HasDataBelowGeneration(serverGen) before adopting; if any
	//     lower-generation data remains on disk, fall through to the
	//     "server_ack_exceeds_local_data" anomaly branch below. Same-gen
	//     (G, 0) with no lower-gen data is safe to adopt unconditionally —
	//     no record can be over-acked.
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
			hasLowerData, walErr := t.walHasDataBelowGenerationFn(serverGen)
			if walErr != nil {
				return AckOutcome{
					Kind:           AckOutcomeAnomaly,
					PersistedTuple: t.persistedAck,
					ReplayCursor:   t.remoteReplayCursor,
					AnomalyReason:  "wal_read_failure",
				}
			}
			if hasLowerData {
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
			Reason:       wal.LossReasonAckRegressionAfterGC,
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
			Reason:       wal.LossReasonAckRegressionAfterGC,
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
	// each later gen in turn and skip those with no replayable records
	// (round-16 Finding 2: a generation that contains ONLY loss markers
	// — produced by overflow GC mid-session, with no subsequent Append
	// before disconnect — must still get a stage so the receiver observes
	// the gap; using HasReplayableRecords here, not WrittenDataHighWater,
	// keeps loss-only generations on the replay schedule). Bail on uint32
	// wraparound: persistedAck.Generation == math.MaxUint32 is a degenerate
	// state but skipping the loop is the safe action.
	for gen := persistedAck.Generation + 1; gen <= highGen && gen > persistedAck.Generation; gen++ {
		haveAny, walErr := t.walHasReplayableRecordsFn(gen)
		if walErr != nil {
			return nil, fmt.Errorf("computeReplayPlan: wal.HasReplayableRecords(gen=%d): %w", gen, walErr)
		}
		if !haveAny {
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

// handleOuterStop is the teardown path shared by every stopCh arm in
// Run's outer loop (top-of-iteration check and the three backoff
// sleeps). It tears down any held conn + recvSession and signals the
// Stop caller by closing sr.done. Returns always; the caller must
// `return nil` from Run immediately after.
//
// This path does NOT drain any reader — there is no batcher/reader
// in scope outside of StateLive's runLive. The drain-then-CloseSend
// contract is honoured only when Stop arrives during StateLive; in
// any other state the documented contract collapses to "abort
// cleanly, flush what runLive had buffered (if any)." See Stop.
func (t *Transport) handleOuterStop(sr stopReq) {
	if t.conn != nil {
		_ = t.conn.CloseSend()
		_ = t.conn.Close()
		t.teardownRecv()
		t.conn = nil
	}
	close(sr.done)
}

// regressToConnecting tears down the live conn + recv goroutine
// established by a prior runConnecting (startRecv on accepted
// SessionAck), used by run-loop branches that bail BEFORE
// runReplaying or runLive owns teardown — i.e. computeReplayPlan
// failure, rdrFactory failure inside the StateReplaying stagesLoop,
// NewReplayer failure, and the StateLive rdrFactory failure. Without
// this teardown, the next dial's startRecv would orphan the prior
// recvSession and let it race the new connection through the shared
// t.conn pointer.
//
// Idempotent: a nil t.conn (already torn down) makes both sub-calls
// no-ops. The conn-then-recv order is load-bearing — runRecv blocks
// on t.conn.Recv() and only unblocks when the conn is closed, so
// closing recv first would deadlock on teardownRecv's <-rs.done wait.
func (t *Transport) regressToConnecting() {
	if t.conn != nil {
		_ = t.conn.Close()
		t.teardownRecv()
		t.conn = nil
	}
}

// Run loops the four-state state machine until ctx is cancelled, the
// state machine reaches StateShutdown, or runConnecting returns a
// terminal error (StateShutdown + non-nil error). It applies
// exponential backoff with jitter between StateConnecting attempts
// (200ms → 30s, factor 2).
//
// PRODUCTION-CONSUMABLE — the three SCAFFOLDING ONLY blockers are
// closed (this commit, Task 27 prereq):
//
//  1. Recv-goroutine startup is wired. runConnecting calls startRecv
//     (recv_multiplexer.go) on accepted SessionAck so runReplaying /
//     runLive can consume BatchAck, ServerHeartbeat, Goaway, and
//     stream-error events. teardownRecv is paired with conn.Close on
//     every exit path.
//  2. Wire encoding is real. encodeBatchMessage (state_live.go) and
//     the replay-side buildEventBatchFn (state_replaying.go, aliased
//     to encodeBatchMessage) build full EventBatch frames from WAL
//     RecordData via proto.Unmarshal of the per-record CompactEvent
//     payloads.
//  3. inflight decrements on BatchAck. The runLive recv arm releases
//     one slot per acknowledged batch (floor at zero to absorb stale
//     or duplicate acks), so the send path no longer stalls at
//     MaxInflight.
//
// Caller wiring: rdrFactory takes the WAL generation AND the start
// sequence so the caller can position the Reader explicitly per state
// entry. `gen` is the WAL generation the Reader will be scoped to
// (segments with a different SegmentHeader.Generation are skipped at
// segment iteration before record decoding — see wal/reader.go
// ReaderOptions.Generation and Task 14b); `start` is the inclusive
// lowest seq the returned Reader will surface for RecordData
// (RecordLoss markers always surface — see wal/reader.go NewReader).
//
// Replaying opens one Reader per stage returned by computeReplayPlan;
// only the first stage carries a non-nil PrefixLoss. Subsequent stages
// start at the generation's earliest sequence (the Reader handles
// header-record skipping internally). Live opens its Reader at
// max(rep.LastReplayedSequence()+1, t.remoteReplayCursor.Sequence+1)
// so it picks up exactly past the boundary record without re-emitting
// it AND without missing any trailing TransportLoss marker overflow GC
// may have appended at the WAL tail mid-replay (loss markers bypass
// the Reader's nextSeq filter — see wal/reader.go nextLocked).
//
// rep is threaded across the Replaying → Live boundary so Live can
// compute its start cursor from rep.LastReplayedSequence(). On any
// regress to StateConnecting (Replaying error, Live error) rep is
// reset to nil so a stale handoff doesn't leak into the next Live
// entry on the next connect cycle. rep is also consumed (cleared to
// nil) at the top of StateLive so a subsequent Live entry after a
// reconnect picks up the fresh value (or nil if no replay ran).
func (t *Transport) Run(ctx context.Context, rdrFactory func(gen uint32, start uint64) (*wal.Reader, error), liveOpts LiveOptions) error {
	// Single-use guard: Run owns the close of t.runDone, so a second
	// invocation would panic on close-of-closed-channel. Reject the
	// second call cleanly. Per Task 27c.
	if !t.runStarted.CompareAndSwap(false, true) {
		return ErrTransportSingleUse
	}
	// Signal Stop callers that the run loop has exited regardless of
	// which return path is taken (ctx cancel, Stop request, terminal
	// error). Stop selects on t.runDone so a Stop arriving AFTER the
	// loop has already returned does not deadlock on stopReq.done.
	// Per Task 27c.
	defer close(t.runDone)
	boInitial := t.opts.BackoffInitial
	if boInitial <= 0 {
		boInitial = 200 * time.Millisecond
	}
	boMax := t.opts.BackoffMax
	if boMax <= 0 {
		boMax = 30 * time.Second
	}
	bo := NewBackoff(BackoffOptions{
		Initial: boInitial,
		Max:     boMax,
		Factor:  2.0,
	})
	st := StateConnecting
	var rep *Replayer
	for {
		select {
		case <-ctx.Done():
			// If cancellation lands between state transitions
			// (after runConnecting → StateReplaying or after
			// runReplaying → StateLive) the prior state handler
			// has not yet had a chance to teardown — without this
			// cleanup the transport would exit holding an open
			// conn and a live recvSession (roborev Medium follow-
			// up). regressToConnecting is idempotent so it is
			// also safe when the prior handler already tore down.
			t.regressToConnecting()
			return ctx.Err()
		case sr := <-t.stopCh:
			// Stop arrived between states (or during a Connecting
			// back-off whose sleep arm did not observe the request
			// first). Tear down any held conn and signal done.
			t.handleOuterStop(sr)
			return nil
		default:
		}
		switch st {
		case StateConnecting:
			next, err := t.runConnecting(ctx)
			if err != nil {
				// Terminal-vs-retriable contract: runConnecting
				// returns StateShutdown for unrecoverable failures
				// (invalid SessionInit per local validation; server
				// SessionAck rejection). For those, surface the
				// error immediately instead of retrying — otherwise
				// misconfiguration or a server-side reject would
				// become an infinite reconnect loop. All other
				// errors (dial / Send / Recv / unexpected frame)
				// are transient and back off to retry.
				if next == StateShutdown {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case sr := <-t.stopCh:
					t.handleOuterStop(sr)
					return nil
				case <-time.After(bo.Next()):
				}
				continue
			}
			bo.Reset()
			rep = nil
			st = next
			// Start the per-connection recv goroutine now that the
			// dial succeeded and the SessionAck was accepted;
			// runReplaying / runLive consume from t.recv.eventCh /
			// t.recv.errCh and teardown is owned by their exit
			// paths (with regressToConnecting as the safety-net for
			// run-loop bail-outs that bypass them). Doing this
			// here — not inside runConnecting — keeps RunOnce a
			// pure single-transition seam that does not leak a
			// recvSession when callers stop after Connecting.
			// Per roborev Medium round-3.
			if next == StateReplaying {
				t.startRecv(ctx)
			}
		case StateReplaying:
			stages, lerr := t.computeReplayPlan(t.remoteReplayCursor, t.persistedAck)
			if lerr != nil {
				// runConnecting started the recv goroutine after
				// SessionAck; without teardown here the next dial's
				// startRecv would orphan it and let it race the
				// new conn through t.conn (roborev High).
				t.regressToConnecting()
				rep = nil
				st = StateConnecting
				continue
			}
			var stageErr error
			stageTransitioned := false
		stagesLoop:
			for i := range stages {
				stage := stages[i]
				rdr, err := rdrFactory(stage.Generation, stage.StartSeq)
				if err != nil {
					stageErr = err
					break stagesLoop
				}
				// TODO(Task 22): thread stage.PrefixLoss through
				// ReplayerOptions once the Replayer gains the
				// PrefixLoss + OnPrefixLossEmitted surface the plan
				// describes. Today the Replayer has no such field, so
				// a non-nil stage.PrefixLoss (Case A or C in
				// computeReplayStart) is not yet surfaced as the first
				// batch record. computeReplayPlan still emits the
				// marker + INFO log so the decision is observable.
				_ = stage.PrefixLoss
				rep, err = NewReplayer(rdr, ReplayerOptions{
					MaxBatchRecords: liveOpts.Batcher.MaxRecords,
					MaxBatchBytes:   liveOpts.Batcher.MaxBytes,
				})
				if err != nil {
					_ = rdr.Close()
					stageErr = err
					break stagesLoop
				}
				next, err := t.runReplaying(ctx, rep)
				_ = rdr.Close()
				if err != nil {
					if next == StateShutdown {
						// Terminal-vs-retriable contract mirroring
						// runConnecting: an inner handler returning
						// StateShutdown with a non-nil error signals an
						// unrecoverable session condition (today: the
						// ErrRecordLossEncountered sentinel — see
						// state_live.go). Surface immediately so the
						// Store's runDone receives the error and the
						// fatal latch trips, instead of looping back to
						// Connecting and re-hitting the same marker.
						return err
					}
					stageErr = err
					break stagesLoop
				}
				if next != StateLive {
					st = next
					stageTransitioned = true
					break stagesLoop
				}
			}
			if stageErr != nil {
				// rdrFactory and NewReplayer failures inside the
				// stagesLoop above leak conn + recv if not torn down
				// here — runReplaying returns its own teardown only
				// when it actually executed. A break before
				// runReplaying lands here without teardown (roborev
				// High).
				t.regressToConnecting()
				rep = nil
				st = StateConnecting
				select {
				case <-ctx.Done():
					return ctx.Err()
				case sr := <-t.stopCh:
					t.handleOuterStop(sr)
					return nil
				case <-time.After(bo.Next()):
				}
				continue
			}
			if !stageTransitioned {
				st = StateLive
			}
		case StateLive:
			start := t.remoteReplayCursor.Sequence + 1
			if rep != nil {
				if _, seq := rep.LastReplayedSequence(); seq+1 > start {
					start = seq + 1
				}
			}
			rep = nil
			var liveGen uint32
			if t.wal != nil {
				liveGen = t.wal.HighGeneration()
			}
			rdr, err := rdrFactory(liveGen, start)
			if err != nil {
				// Same leak path as the StateReplaying rdrFactory
				// failure above — runLive never executes, so its
				// internal teardown never runs (roborev High).
				t.regressToConnecting()
				st = StateConnecting
				continue
			}
			next, err := t.runLive(ctx, rdr, liveOpts)
			if err != nil {
				if next == StateShutdown {
					// Terminal-vs-retriable: see the runReplaying
					// branch above for the full contract. Same
					// rationale — an unrecoverable encoder error
					// (ErrRecordLossEncountered) must not be
					// retried by the Connecting backoff path.
					return err
				}
				st = StateConnecting
				select {
				case <-ctx.Done():
					return ctx.Err()
				case sr := <-t.stopCh:
					t.handleOuterStop(sr)
					return nil
				case <-time.After(bo.Next()):
				}
				continue
			}
			st = next
		case StateShutdown:
			return nil
		}
	}
}
