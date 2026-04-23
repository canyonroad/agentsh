// Package watchtower implements a store.EventStore that ships events
// to a Watchtower endpoint via the WTP protocol.
package watchtower

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// Store is the watchtower store.EventStore implementation. The struct
// itself is intentionally small; AppendEvent and Close land in Task 23.
type Store struct {
	opts    Options
	w       *wal.WAL
	tr      *transport.Transport
	sink    chain.SinkChainAPI
	metrics *metrics.WTPMetrics

	mu      sync.Mutex
	fatalCh chan error
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
//     start its run loop in a background goroutine.
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

	dialer := opts.Dialer
	if dialer == nil {
		dialer = newGRPCDialer(opts)
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

	s := &Store{
		opts:    opts,
		w:       w,
		tr:      tr,
		sink:    sinkChain,
		metrics: mw,
		fatalCh: make(chan error, 1),
	}

	go func() {
		_ = tr.Run(ctx, func(gen uint32, start uint64) (*wal.Reader, error) {
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

// newGRPCDialer is a placeholder dialer for production wiring. Real
// TLS / auth construction lands in Task 27. Until then any production
// caller (without Options.Dialer set) gets an explicit error from the
// Run loop instead of a silent stall.
func newGRPCDialer(opts Options) transport.Dialer {
	_ = opts
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		return nil, fmt.Errorf("watchtower: production dialer not yet wired (Task 27)")
	})
}
