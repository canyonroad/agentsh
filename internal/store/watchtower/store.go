// Package watchtower implements a store.EventStore that ships events
// to a Watchtower endpoint via the WTP protocol.
package watchtower

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// closeRunCancelGrace bounds how long Close waits on the run loop
// AFTER runCancel fires (i.e. AFTER the cooperative Stop drain has
// either succeeded or timed out). The bg loop's per-iteration ctx
// checks unblock within a single backoff sleep on dial-fail or a
// single select hop on Live, so this grace is only relevant if the
// Transport is wedged inside a non-interruptible Conn.Send / Recv /
// Dial (Transport.Stop's documented limitation).
//
// Exposed as a constant rather than an Options field because (a) the
// only relevant configuration knob is opts.DrainDeadline, which the
// operator controls, and (b) the fallback is a safety net not a
// tunable — making it configurable invites operators to set it to
// values that mask real wedge bugs. If a future production scenario
// requires a different value, promote this to Options at that point.
//
// Latency contract per shutdown branch (canonical reference is the
// Store docstring's "Close()" block; this comment exists to keep
// the constant's local context honest):
//
//   Happy path  : DrainDeadline + closeRunCancelGrace + wal.Close
//   Safety net  : DrainDeadline + closeRunCancelGrace
//                 (wal.Close is INTENTIONALLY skipped — see
//                  the IMPORTANT incomplete-cleanup case on the
//                  Store docstring for why)
const closeRunCancelGrace = 2 * time.Second

// ErrCloseSafetyNet is the sentinel error returned by Close when the
// synthetic-timeout safety net fires (closeRunCancelGrace elapsed
// after runCancel without the bg run loop exiting). Higher layers
// can errors.Is(err, ErrCloseSafetyNet) to reliably detect the
// "WAL handle leaked, restart required, same-process reopen
// unsupported" case WITHOUT string-matching the returned error
// message. The wrapped error message also names the elapsed grace
// duration for operator triage.
var ErrCloseSafetyNet = errors.New("watchtower.Close: shutdown safety net hit; bg goroutine and WAL handle leaked, process restart required")

// Store is the watchtower store.EventStore implementation.
//
// Lifecycle:
//
//   - New(ctx, opts) constructs the Store, runs validation, opens the
//     WAL, and STARTS the transport's run loop in a background
//     goroutine. The supplied ctx is SETUP-ONLY — it bounds the
//     synchronous construction work (validate, wal.Open, transport
//     New). The background goroutine uses an INTERNAL ctx the Store
//     owns and cancels in Close. This matches the OTEL store's
//     constructor convention (ctx for setup, lifetime owned by
//     Close), and crucially means a setup-scoped ctx that the caller
//     cancels right after New returns will NOT silently kill the
//     background transport.
//
//   - Close() (matching the EventStore.Close() error signature)
//     shuts the Store down. The shutdown latency budget depends on
//     which branch fires:
//
//       Happy path (cooperative drain succeeds OR runCancel
//       unblocks the bg loop within closeRunCancelGrace):
//         DrainDeadline + closeRunCancelGrace + wal.Close
//         (wal.Close is typically sub-millisecond)
//
//       Safety-net path (synthetic timeout fires):
//         DrainDeadline + closeRunCancelGrace
//         wal.Close is NOT called on this path — see the
//         IMPORTANT note below.
//
//     Idempotent — second and later calls return the same captured
//     error.
//
//     IMPORTANT incomplete-cleanup case: if the Transport is wedged
//     inside a non-interruptible call (Conn.Send / Recv / Dial that
//     does not honour ctx — see Transport.Stop's documented
//     limitations), runCancel does NOT unblock it. After
//     closeRunCancelGrace elapses, Close returns a synthetic
//     "watchtower.Close: ... bg goroutine + WAL handle leaked"
//     error AND emits a WARN log carrying the stable instance
//     identifiers (session_id, agent_id, wal_dir) so multi-instance
//     failures are triageable. In that path Close DELIBERATELY does
//     NOT close the WAL — calling wal.Close while a wal.Reader is
//     mid-read inside the bg loop would race (potential panic or
//     corrupted state). The bg goroutine, the in-flight Stop
//     goroutine, AND the WAL handle are all leaked.
//
//     SAME-PROCESS REOPEN AFTER SAFETY-NET HIT IS UNSUPPORTED. The
//     leaked bg goroutine still holds a wal.WAL reference; opening
//     a fresh wal.WAL on the same Dir would race with the existing
//     handle's writes. The operator's intended remedy is process
//     restart, at which point the OS reclaims the leaked handle
//     and a fresh process can open the Dir cleanly. Constructing a
//     replacement watchtower.Store in the same process after a
//     synthetic Close error is a CONTRACT VIOLATION.
//
//     Higher layers detect the safety-net path via
//     errors.Is(err, ErrCloseSafetyNet) — a typed sentinel returned
//     from Close on the leak path. This avoids string-matching the
//     wrapped error message for the same-process-reopen guard.
//
//     Related tracked work: **Task 27c** in the plan
//     (docs/superpowers/plans/2026-04-18-wtp-client.md) eliminates
//     the narrower "Stop called AFTER Run has already exited" race
//     by adding a Transport-side RunDone signal; the wedged-goroutine
//     case (Run parked inside a ctx-ignoring Conn.Send/Recv/Dial)
//     stays covered by ErrCloseSafetyNet. Today ALL dialers are
//     injected via Options.Dialer (the built-in production dialer
//     lands in Task 27), so every current caller is on the
//     custom-dialer path and the sentinel/no-reopen contract
//     applies universally. Once Task 27 lands its built-in dialer
//     (gRPC over TLS, ctx-honouring) the wedge case becomes
//     reachable only via custom-dialer injection. If a production
//     custom-dialer ever hits the wedge, Task 27d would cover
//     reclamation — not pre-filed.
//
//   - Err() returns the run loop's terminal error if Run has
//     already exited (or the canonical Close-captured error after
//     Close has run). Non-blocking; returns nil if Run is still
//     alive and Close has not yet run.
//
// AppendEvent and the rest of the store.EventStore surface land in
// Task 23.
type Store struct {
	opts    Options
	w       *wal.WAL
	tr      *transport.Transport
	sink    chain.SinkChainAPI
	metrics *metrics.WTPMetrics

	// runCancel cancels the internal context the bg run loop watches.
	// Closed by Close. The internal context is independent of the
	// constructor's ctx so the bg goroutine survives setup-ctx
	// cancellation.
	runCancel context.CancelFunc
	// runDone receives Run's terminal return value (nil on clean
	// shutdown, non-nil on terminal SessionAck rejection or other
	// fatal). Buffer 1 so the bg goroutine never blocks on send.
	runDone chan error

	// closeOnce + closeErr track Close's single-execution result.
	// closed is set to true atomically AFTER closeOnce.Do completes
	// so Err() can distinguish the pre-close path (peek runDone) from
	// the post-close path (return closeErr verbatim — the canonical
	// post-close error source per the High finding in roborev #5767).
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error

	// fatalLatched is set by AppendEvent when an ambiguous WAL failure
	// or a terminal chain.Commit failure occurs. Once latched, every
	// subsequent AppendEvent returns errFatalLatch without touching
	// the WAL or the chain. atomic.Bool is sufficient — the latch is
	// one-shot and no field other than the boolean is read back by
	// isFatal.
	fatalLatched atomic.Bool
	// fatalErr carries the original cause of the latch for diagnostic
	// logging via Err() / operator inspection. Guarded by the CAS in
	// latchFatal so only the first latching call's error is stored.
	fatalErr atomic.Value // error

	// appendMu serializes the full Compute → Append → Commit sequence
	// in AppendEvent. The composite store fans events out to its sinks
	// under RLock, which admits multiple concurrent AppendEvent calls
	// against this Store. Without this mutex, two concurrent Compute
	// calls would both see the same prev_hash, both proceed to Append,
	// and one would then lose at Commit as a stale result — turning
	// ordinary concurrent traffic into a fatal-latch event and
	// leaving a WAL record that never committed into the integrity
	// chain. The mutex is held across the entire transaction so the
	// (Compute, Append, Commit) triple is atomic with respect to
	// other appenders.
	//
	// Close() ALSO acquires this mutex to wait for in-flight
	// transactions before draining transport + closing the WAL
	// (roborev #5957 Medium #1 — without the drain, a concurrent
	// AppendEvent could land a record after Stop has already drained
	// the transport, so the record would miss the final send window).
	appendMu sync.Mutex

	// closing is set by Close BEFORE it drains the transport and
	// closes the WAL. AppendEvent checks it AFTER acquiring appendMu
	// and returns errStoreClosing to reject new appends once shutdown
	// has begun. Appends that had already acquired appendMu before
	// Close ran complete normally — Close waits on appendMu for that
	// drain to finish.
	closing atomic.Bool

	// contextDigest is the session-bound chain.ComputeContextDigest
	// value stamped into every IntegrityRecord.ContextDigest. Computed
	// once in New() from the Options-provided SessionContext fields
	// (AgentID, SessionID, KeyFingerprint, HMACAlgorithm, format
	// version) and held for the lifetime of the Store. Session rotation
	// / key rollover re-computation is follow-up work; today a Store
	// binds exactly one context digest.
	contextDigest string
}

// New constructs a Store, validates options, opens the WAL, wires the
// chain sink, and starts the transport state machine in the
// background.
//
// Construction order (load-bearing):
//
//  1. applyDefaults + validate — fail fast on misconfiguration before
//     any IO.
//  2. Build the chain sink (pure, no IO). Failures here do not leak a
//     half-opened WAL.
//  3. Open the WAL. On wal.ErrIdentityMismatch the recovery path
//     quarantines the stale dir and reopens with the new identity.
//  4. Read meta.json to seed the Transport's persistedAck cursor so
//     the FIRST SessionInit after restart carries the durable
//     watermark instead of (0, 0).
//  5. Build the Transport with the dialer + WAL + metrics handle, and
//     start its run loop in a background goroutine bound to an
//     INTERNAL context owned by the Store.
//
// The supplied ctx parameter is SETUP-ONLY. The bg run loop uses a
// separate, Store-owned context that Close cancels. This matches the
// OTEL store convention so callers can write
// `s, err := watchtower.New(setupCtx, opts)` without worrying that a
// short-lived setupCtx will silently kill the transport.
func New(ctx context.Context, opts Options) (*Store, error) {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	// Wire the chain sink BEFORE opening the WAL so a failure here
	// returns immediately without leaking an open WAL.
	innerChain, err := audit.NewSinkChain(opts.HMACSecret, opts.HMACAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("audit.NewSinkChain: %w", err)
	}
	var sinkChain chain.SinkChainAPI = chain.NewWatchtowerSink(innerChain)
	if opts.SinkChainOverrideForTests != nil {
		sinkChain = opts.SinkChainOverrideForTests
	}

	// Compute context_digest BEFORE wal.Open so it can participate in
	// the identity check. Same computation as the transport handshake
	// below — a shared value across both the SessionInit advertisement
	// AND the WAL's persisted identity triple (roborev #5957
	// Medium #2): if AgentID changes across restarts while session_id
	// / key_fingerprint stay, wal.Open quarantines the stale dir
	// instead of silently replaying records whose chain carries a
	// different digest than the new SessionInit.
	algo := opts.HMACAlgorithm
	if algo == "" {
		algo = "hmac-sha256"
	}
	ctxDigest, err := chain.ComputeContextDigest(chain.SessionContext{
		SessionID:      opts.SessionID,
		AgentID:        opts.AgentID,
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Algorithm:      algo,
		KeyFingerprint: opts.KeyFingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("chain.ComputeContextDigest: %w", err)
	}

	w, err := openWALWithIdentityRecovery(opts, ctxDigest)
	if err != nil {
		return nil, err
	}

	// Restore the chain state from the last committed WAL record so
	// the next AppendEvent chains correctly across restarts. Without
	// this, every cold start begins at prev_hash="" regardless of
	// existing on-disk data, and the first record of the new process
	// would serialise an empty prev_hash even though earlier records
	// had committed a real chain — breaking integrity continuity.
	// (roborev #5945 High #2)
	//
	// Skipped when SinkChainOverrideForTests is set: test overrides
	// bring their own state and do not want the production restore
	// path replaying records into them.
	if opts.SinkChainOverrideForTests == nil {
		if err := restoreChainFromWAL(innerChain, w, opts); err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("restore chain from WAL: %w", err)
		}
	}

	initialAck, err := readInitialAckTuple(opts, w)
	if err != nil {
		_ = w.Close()
		return nil, err
	}

	// Production-dialer rejection: the placeholder dialer (Task 27
	// will wire the real one) deliberately fails every Dial. Returning
	// success from New with that dialer wired would give callers a
	// half-built Store that infinite-loops in the bg dial-fail backoff
	// — an opaque failure mode. Until Task 27 lands, production
	// callers MUST inject a Dialer (testserver.DialerFor for tests,
	// or a real grpc.Dial wrapper).
	dialer := opts.Dialer
	if dialer == nil {
		_ = w.Close()
		return nil, errors.New("watchtower: Options.Dialer is required (production gRPC dialer wiring lands in Task 27; tests should use testserver.DialerFor)")
	}

	// Sanity-check setup ctx: callers passing an already-cancelled
	// ctx have made a configuration mistake. Surface it before we
	// allocate the bg goroutine.
	if err := ctx.Err(); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("watchtower.New: setup ctx already cancelled: %w", err)
	}

	mw := opts.Metrics.WTP()

	// ctxDigest was computed up-front (before wal.Open) so it could
	// participate in the WAL identity check. It's also stamped into
	// Store.contextDigest and fed to transport.New below so the
	// SessionInit handshake, the IntegrityRecord on every append,
	// and the persisted WAL identity all agree.

	// Map the chain HMAC algorithm string to the proto enum the
	// transport advertises in SessionInit. validate() rejects unknown
	// algorithm strings upstream, so the default branch is unreachable
	// for valid Options.
	var tpAlgo wtpv1.HashAlgorithm
	switch algo {
	case "hmac-sha256":
		tpAlgo = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256
	case "hmac-sha512":
		tpAlgo = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA512
	default:
		tpAlgo = wtpv1.HashAlgorithm_HASH_ALGORITHM_HMAC_SHA256
	}

	tr, err := transport.New(transport.Options{
		Dialer:          dialer,
		AgentID:         opts.AgentID,
		SessionID:       opts.SessionID,
		InitialAckTuple: initialAck,
		Logger:          opts.Logger,
		WAL:             w,
		Metrics:         mw,
		// Handshake metadata: the SessionInit frame MUST advertise the
		// SAME algorithm / key fingerprint / context digest that the
		// WAL records are chained with; otherwise the receiver sees a
		// handshake that doesn't match the integrity chain it's about
		// to verify. (roborev #5945 High)
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Algorithm:      tpAlgo,
		KeyFingerprint: opts.KeyFingerprint,
		ContextDigest:  ctxDigest,
	})
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("transport.New: %w", err)
	}

	// Internal context owned by the Store; cancelled by Close. The
	// caller's ctx parameter is intentionally NOT threaded into the
	// bg goroutine — see the lifecycle docstring above.
	runCtx, runCancel := context.WithCancel(context.Background())

	s := &Store{
		opts:          opts,
		w:             w,
		tr:            tr,
		sink:          sinkChain,
		metrics:       mw,
		runCancel:     runCancel,
		runDone:       make(chan error, 1),
		contextDigest: ctxDigest,
	}

	go func() {
		s.runDone <- tr.Run(runCtx, func(gen uint32, start uint64) (*wal.Reader, error) {
			return w.NewReader(wal.ReaderOptions{Generation: gen, Start: start})
		}, transport.LiveOptions{
			Batcher: transport.BatcherOptions{
				MaxRecords: opts.BatchMaxRecords,
				MaxBytes:   opts.BatchMaxBytes,
				MaxAge:     opts.BatchMaxAge,
			},
			MaxInflight:    8,
			HeartbeatEvery: 5 * time.Second,
		})
	}()

	return s, nil
}

// Close shuts down the Store and matches the store.EventStore.Close()
// signature so *Store can be used wherever the interface is expected.
//
// Behavior:
//
//  1. If the bg run loop has ALREADY exited (peek runDone non-
//     blockingly), skip the cooperative drain — calling tr.Stop on a
//     dead run loop would block forever (the buffered stopCh send
//     would succeed but nothing would close r.done; documented on
//     Transport.Stop). Then close the WAL.
//  2. Otherwise, request a cooperative drain via tr.Stop in a
//     goroutine bounded by opts.DrainDeadline. Wait on runDone OR
//     the deadline.
//  3. On deadline, fall back to runCancel() and wait on runDone,
//     bounded by closeRunCancelGrace.
//  4. CONDITIONAL WAL close:
//       - If runDone fired in step 2 OR step 3 — close the WAL.
//         WAL-close errors are merged into the captured close error.
//       - If closeRunCancelGrace ALSO elapsed in step 3 (the
//         synthetic-timeout safety-net path) — DO NOT close the
//         WAL. The bg goroutine may still hold a wal.Reader; closing
//         the WAL would race. Return the synthetic error directly
//         and emit the operator WARN per the Store docstring.
//
// Returns the run loop's terminal error on clean shutdown, a wrapped
// WAL-close error if step 4 surfaced one, or the synthetic safety-
// net error if step 3's grace elapsed. Idempotent — second and later
// calls return the error captured on the first call.
//
// SAME-PROCESS REOPEN AFTER SAFETY-NET HIT IS UNSUPPORTED — see the
// Store docstring's "incomplete-cleanup case" block. Operators must
// restart the process to recover; constructing a replacement
// watchtower.Store on the same WAL Dir in the same process is a
// contract violation.
//
// CAVEAT: under racy shutdown (Run exits between the peek and the
// Stop goroutine launch) the Stop goroutine MAY leak. Until
// Transport.Stop gains a non-blocking-on-late-call mode, this is the
// least-bad shutdown shape that satisfies EventStore.Close()'s
// no-ctx contract while still attempting graceful drain.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		// Gate new AppendEvent transactions from entering the
		// Compute → Append → Commit path, then wait for any
		// already-in-flight transaction to finish before draining
		// the transport. Without this, a concurrent appender could
		// land a record in the WAL after Stop has already drained
		// the in-memory send queue — the record would be durable
		// but miss the final send window, surprising callers who
		// assume post-Close records do not linger. (roborev
		// #5957 Medium #1)
		s.closing.Store(true)
		s.appendMu.Lock()
		s.appendMu.Unlock()

		s.closeErr = s.shutdown()
		// Mark closed AFTER closeErr is fully populated so a
		// concurrent Err() never sees the closed flag with a
		// half-written closeErr.
		s.closed.Store(true)
	})
	return s.closeErr
}

// shutdown is the body of Close, factored out so closeOnce.Do can
// capture a single return value without inlining a 60-line closure.
// Bounded by opts.DrainDeadline (or 0 → immediate cancel + wait).
func (s *Store) shutdown() error {
	// Step 1: did Run already exit? If so, do NOT call Stop —
	// Transport.Stop's <-r.done wait would block forever because
	// the consumer is gone.
	select {
	case err := <-s.runDone:
		// Replay so a subsequent Err() observation is consistent
		// with this captured value. Buffered cap-1, never blocks.
		s.runDone <- err
		s.runCancel() // idempotent; quiets the linter
		return s.combineWALCloseErr(err)
	default:
	}

	// Step 2: Run is alive. Cooperative drain via Stop, bounded by
	// DrainDeadline. Stop runs in a goroutine because if Run dies
	// between our peek above and Stop's send below, Stop's
	// <-r.done would block forever.
	stopGoroutineExited := make(chan struct{})
	go func() {
		s.tr.Stop(s.opts.DrainDeadline)
		close(stopGoroutineExited)
	}()

	deadline := s.opts.DrainDeadline
	if deadline <= 0 {
		// Drain disabled by configuration — fall straight to
		// runCancel + wait.
		s.runCancel()
		return s.combineWALCloseErr(<-s.runDone)
	}

	timer := time.NewTimer(deadline)
	defer timer.Stop()

	var runErr error
	select {
	case runErr = <-s.runDone:
		// Drain succeeded (or run loop exited via Stop's path).
		_ = stopGoroutineExited // best-effort; may still be running
	case <-timer.C:
		// Drain deadline elapsed. Fall back to runCancel and a
		// bounded wait on runDone (closeRunCancelGrace).
		s.runCancel()
		select {
		case runErr = <-s.runDone:
		case <-time.After(closeRunCancelGrace):
			// Synthetic-timeout case — UNSAFE-CLEANUP path. The bg
			// goroutine is still alive; calling wal.Close while a
			// wal.Reader is mid-read inside the bg loop would race
			// (potential panic or corrupted state). We DELIBERATELY
			// leak the WAL handle, the bg goroutine, and the
			// in-flight Stop goroutine — all three are tied to a
			// process-level safety-net failure that the operator
			// should resolve by restart, at which point the OS
			// reclaims everything. The WARN log below carries the
			// stable instance identifiers (session_id, agent_id,
			// wal_dir) so multi-instance failures are triageable.
			s.opts.Logger.Warn("watchtower.Close: shutdown safety net hit; transport likely wedged in non-interruptible Conn.Send/Recv/Dial",
				"drain_deadline", s.opts.DrainDeadline,
				"close_run_cancel_grace", closeRunCancelGrace,
				"session_id", s.opts.SessionID,
				"agent_id", s.opts.AgentID,
				"wal_dir", s.opts.WALDir,
				"action", "returning synthetic timeout error; bg goroutine + WAL handle leaked, restart required for clean state")
			// IMPORTANT: do NOT call s.combineWALCloseErr — that
			// would invoke wal.Close while a Reader inside the bg
			// loop may still be active. Return the sentinel
			// (wrapped with the elapsed grace) directly; the leaked
			// WAL handle is part of the safety-net contract.
			// Higher layers detect via errors.Is(err, ErrCloseSafetyNet).
			return fmt.Errorf("%w (closeRunCancelGrace=%v elapsed)", ErrCloseSafetyNet, closeRunCancelGrace)
		}
	}
	return s.combineWALCloseErr(runErr)
}

// combineWALCloseErr closes the WAL and merges any error with runErr.
// Both errors are surfaced in the returned message; neither is
// silently dropped.
func (s *Store) combineWALCloseErr(runErr error) error {
	walErr := s.w.Close()
	if walErr == nil {
		return runErr
	}
	if runErr == nil {
		return fmt.Errorf("watchtower.Close: WAL close: %w", walErr)
	}
	return fmt.Errorf("%w (also: WAL close: %v)", runErr, walErr)
}

// Err returns the run loop's terminal error if it has already exited,
// the AppendEvent fatal-latch cause if a prior Append latched the
// store, or nil otherwise. Useful for callers polling on transport
// health.
//
// Precedence (first non-nil wins):
//  1. Post-close: closeErr (canonical post-close source captured by
//     Close from runDone + wal.Close merging).
//  2. Pre-close, fatal-latched: fatalErr (set by AppendEvent's
//     ambiguous-WAL / terminal-Commit paths). Surfacing this before
//     the run-loop-terminal check lets health probes see the cause
//     without waiting for the run loop to unwind.
//  3. Pre-close, run-loop already exited: peek runDone and replay.
//
// Non-blocking — peeks at runDone via a non-blocking receive so the
// caller does not stall waiting for the run loop.
func (s *Store) Err() error {
	if s.closed.Load() {
		// Canonical post-close source. Close has populated closeErr
		// in full; the channel-state below has been consumed.
		return s.closeErr
	}
	// Pre-close, fatal-latch visible to operators before the run loop
	// unwinds. AppendEvent sets fatalLatched + stores fatalErr on
	// ambiguous WAL or terminal Commit failure; surfacing it here
	// gives health probes the diagnostic cause without depending on
	// Close to run.
	if s.fatalLatched.Load() {
		if v := s.fatalErr.Load(); v != nil {
			if e, ok := v.(error); ok && e != nil {
				return e
			}
		}
		return errFatalLatch
	}
	// Pre-close: peek runDone. If Run has terminated but Close has
	// not yet run, replay so a subsequent peek (or Close's pre-Stop
	// check) still sees the value.
	select {
	case err := <-s.runDone:
		s.runDone <- err
		return err
	default:
		return nil
	}
}

// openWALWithIdentityRecovery wraps wal.Open with the Task 14a
// quarantine recovery path. On wal.ErrIdentityMismatch the stale dir
// is renamed to "<dir>.quarantine.<unix-nanos>-<rand4hex>" and a fresh
// WAL is opened against the now-empty Dir. Each quarantine increments
// metrics.IncWALQuarantine with the typed reason classified from
// idErr.PersistedSessionID / PersistedKeyFingerprint.
func openWALWithIdentityRecovery(opts Options, contextDigest string) (*wal.WAL, error) {
	w, err := wal.Open(wal.Options{
		Dir:            opts.WALDir,
		SegmentSize:    opts.WALSegmentSize,
		MaxTotalBytes:  opts.WALMaxTotalSize,
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
		ContextDigest:  contextDigest,
	})
	if err == nil {
		return w, nil
	}

	var idErr *wal.ErrIdentityMismatch
	if !errors.As(err, &idErr) {
		return nil, fmt.Errorf("open WAL: %w", err)
	}

	// Quarantine recovery: rename the stale dir, reopen against an
	// empty Dir. The probe-then-rename pattern guards against
	// concurrent restarts collision-on-name; a 4-byte random tag
	// keeps the namespace effectively unique.
	quarantineDir, qerr := quarantineWAL(opts.WALDir)
	if qerr != nil {
		return nil, fmt.Errorf("wtp: WAL identity mismatch and quarantine failed: %w (original: %v)", qerr, err)
	}

	reasonField := "unknown"
	reason := metrics.WTPWALQuarantineReasonUnknown
	switch {
	case idErr.PersistedSessionID != opts.SessionID:
		reasonField = "session_id_mismatch"
		reason = metrics.WTPWALQuarantineReasonSessionIDMismatch
	case idErr.PersistedKeyFingerprint != opts.KeyFingerprint:
		reasonField = "key_fingerprint_mismatch"
		reason = metrics.WTPWALQuarantineReasonKeyFingerprintMismatch
	case idErr.MismatchedField == "context_digest":
		reasonField = "context_digest_mismatch"
		reason = metrics.WTPWALQuarantineReasonContextDigestMismatch
	}
	opts.Logger.Warn("wtp: WAL identity mismatch; quarantining stale WAL dir",
		"persisted_session_id", idErr.PersistedSessionID,
		"expected_session_id", opts.SessionID,
		"persisted_key_fingerprint", idErr.PersistedKeyFingerprint,
		"expected_key_fingerprint", opts.KeyFingerprint,
		"reason", reasonField,
		"quarantine_dir", quarantineDir,
		"action", "renamed stale WAL dir; opening fresh WAL with new identity")
	// Task 22a: increment the always-emit wtp_wal_quarantine_total
	// {reason} family. opts.Metrics.WTP() is nil-safe so a Store
	// constructed with Options.Metrics == nil (production wiring not
	// yet plumbed, or a test deliberately using a no-op) is a no-op.
	opts.Metrics.WTP().IncWALQuarantine(reason)

	w, err = wal.Open(wal.Options{
		Dir:            opts.WALDir,
		SegmentSize:    opts.WALSegmentSize,
		MaxTotalBytes:  opts.WALMaxTotalSize,
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
		ContextDigest:  contextDigest,
	})
	if err != nil {
		return nil, fmt.Errorf("open WAL (post-quarantine): %w", err)
	}
	return w, nil
}

// readInitialAckTuple reads wal.Meta and constructs the Transport's
// initial ack-tuple seed per the round-10 v1-migration rules.
func readInitialAckTuple(opts Options, w *wal.WAL) (*transport.AckTuple, error) {
	meta, err := wal.ReadMeta(opts.WALDir)
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist):
		// Pre-ack cold start: no meta.json on disk. Return nil seed.
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read WAL meta: %w", err)
	case meta.SessionID != "" && meta.SessionID != opts.SessionID:
		// Round-10 Finding 4: empty meta.SessionID is V1 legacy and
		// treated as MATCH. Non-empty mismatch is defense-in-depth
		// (the wal.Open path above usually catches it first).
		opts.Logger.Warn("wtp: meta session_id mismatch; ignoring persisted ack",
			"persisted_session_id", meta.SessionID,
			"expected_session_id", opts.SessionID,
			"action", "ignoring persisted ack tuple; first SessionAck will adopt server tuple wholesale")
		return nil, nil
	case meta.KeyFingerprint != "" && meta.KeyFingerprint != opts.KeyFingerprint:
		opts.Logger.Warn("wtp: meta key_fingerprint mismatch; ignoring persisted ack",
			"persisted_key_fingerprint", meta.KeyFingerprint,
			"expected_key_fingerprint", opts.KeyFingerprint,
			"action", "ignoring persisted ack tuple; first SessionAck will adopt server tuple wholesale")
		return nil, nil
	case !meta.AckRecorded:
		// Identity matches but no ack ever recorded. Leave seed nil.
		return nil, nil
	default:
		return &transport.AckTuple{
			Generation: meta.AckHighWatermarkGen,
			Sequence:   meta.AckHighWatermarkSeq,
			Present:    true,
		}, nil
	}
}

// newGRPCDialer is reserved for the production gRPC wiring landing
// in Task 27. Until then New rejects an unset Options.Dialer rather
// than wiring a placeholder that would silently infinite-loop in the
// bg dial-fail backoff.
//
// Kept as a package-private symbol so Task 27 can drop in the real
// implementation without restructuring New's call site.
func newGRPCDialer(_ Options) transport.Dialer {
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		return nil, fmt.Errorf("watchtower: production dialer not yet wired (Task 27)")
	})
}
