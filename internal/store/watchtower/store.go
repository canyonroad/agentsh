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
)

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
//   - Close(ctx) cancels the run loop, calls tr.Stop with the
//     configured drain deadline, closes the WAL, and returns any
//     error the run loop surfaced (or ctx.Err() if Close's own ctx
//     elapses before the run loop exits). Idempotent — second call
//     is a no-op that returns the same error captured on the first
//     call.
//
//   - Err() returns the run loop's terminal error if it has already
//     exited (e.g. terminal SessionAck rejection from the server),
//     or nil if the loop is still running. Callers polling on
//     transport health should use Err in conjunction with their own
//     liveness check.
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
//
// TODO(Task 22a): the WAL identity-mismatch recovery path needs to
// emit metrics.IncWALQuarantine(reason). The metric does not exist in
// the metrics package yet (Task 22a adds it); the recovery path is
// implemented without the metric for now and the call site is
// commented inline so Task 22a can wire it in.
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

	w, err := openWALWithIdentityRecovery(opts)
	if err != nil {
		return nil, err
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
	tr, err := transport.New(transport.Options{
		Dialer:          dialer,
		AgentID:         opts.AgentID,
		SessionID:       opts.SessionID,
		InitialAckTuple: initialAck,
		Logger:          opts.Logger,
		WAL:             w,
		Metrics:         mw,
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
		opts:      opts,
		w:         w,
		tr:        tr,
		sink:      sinkChain,
		metrics:   mw,
		runCancel: runCancel,
		runDone:   make(chan error, 1),
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
//     Transport.Stop).
//  2. Otherwise, request a cooperative drain via tr.Stop in a
//     goroutine bounded by opts.DrainDeadline. Wait on runDone OR
//     the deadline.
//  3. On deadline, fall back to runCancel() and wait on runDone
//     (bounded — the bg run loop's select arms honour ctx.Done in
//     short order).
//  4. Close the WAL. WAL-close errors are appended to the captured
//     close error so neither is silently dropped.
//
// Returns the run loop's terminal error on clean shutdown, or a
// wrapped deadline / WAL-close error otherwise. Idempotent — second
// and later calls return the error captured on the first call.
//
// CAVEAT: under racy shutdown (Run exits between the peek and the
// Stop goroutine launch) the Stop goroutine MAY leak. Until
// Transport.Stop gains a non-blocking-on-late-call mode, this is the
// least-bad shutdown shape that satisfies EventStore.Close()'s
// no-ctx contract while still attempting graceful drain.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
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
		// bounded wait on runDone.
		s.runCancel()
		select {
		case runErr = <-s.runDone:
		case <-time.After(2 * time.Second):
			runErr = errors.New("watchtower.Close: run loop did not exit within fallback deadline after runCancel")
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
// or nil if the loop is still running. Useful for callers polling on
// transport health.
//
// Post-close behavior: after Close has run, Err returns the EXACT
// value Close captured (terminal err, deadline-fallback wrap, OR
// WAL-close-merged err). Pre-close behavior: peek runDone non-
// blockingly; nil if Run is alive, the captured terminal err
// otherwise. The closed flag (set inside closeOnce.Do AFTER closeErr
// is fully populated) discriminates between the two paths.
//
// Non-blocking — peeks at runDone via a non-blocking receive so the
// caller does not stall waiting for the run loop.
func (s *Store) Err() error {
	if s.closed.Load() {
		// Canonical post-close source. Close has populated closeErr
		// in full; the channel-state below has been consumed.
		return s.closeErr
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
// WAL is opened against the now-empty Dir.
//
// TODO(Task 22a): the recovery path does NOT yet emit
// metrics.IncWALQuarantine — the metric is added in Task 22a per the
// plan. The reason classification is kept here as a string so Task
// 22a can drop in the typed reason directly.
func openWALWithIdentityRecovery(opts Options) (*wal.WAL, error) {
	w, err := wal.Open(wal.Options{
		Dir:            opts.WALDir,
		SegmentSize:    opts.WALSegmentSize,
		MaxTotalBytes:  opts.WALMaxTotalSize,
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
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
	switch {
	case idErr.PersistedSessionID != opts.SessionID:
		reasonField = "session_id_mismatch"
	case idErr.PersistedKeyFingerprint != opts.KeyFingerprint:
		reasonField = "key_fingerprint_mismatch"
	}
	opts.Logger.Warn("wtp: WAL identity mismatch; quarantining stale WAL dir",
		"persisted_session_id", idErr.PersistedSessionID,
		"expected_session_id", opts.SessionID,
		"persisted_key_fingerprint", idErr.PersistedKeyFingerprint,
		"expected_key_fingerprint", opts.KeyFingerprint,
		"reason", reasonField,
		"quarantine_dir", quarantineDir,
		"action", "renamed stale WAL dir; opening fresh WAL with new identity")
	// TODO(Task 22a): opts.Metrics.WTP().IncWALQuarantine(reason) —
	// metric not present in metrics package yet.

	w, err = wal.Open(wal.Options{
		Dir:            opts.WALDir,
		SegmentSize:    opts.WALSegmentSize,
		MaxTotalBytes:  opts.WALMaxTotalSize,
		SessionID:      opts.SessionID,
		KeyFingerprint: opts.KeyFingerprint,
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
