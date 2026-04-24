package wal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyncMode controls whether each Append fsyncs synchronously or via a timer.
type SyncMode int

const (
	// SyncImmediate causes every Append to fsync the segment before returning.
	SyncImmediate SyncMode = iota
	// SyncDeferred batches fsyncs onto a timer driven by SyncInterval. The
	// timer-driven path is not yet wired by this WAL: there is no public
	// flush hook the higher-level Task can call between appends, so a crash
	// in this mode would silently lose acknowledged records. Open() rejects
	// SyncDeferred until the periodic-sync API is added; this constant is
	// kept so the surface is forward-compatible.
	SyncDeferred
)

// Options configures a WAL. Defaults are not applied here — callers should
// pre-validate via internal/config (which does apply defaults).
type Options struct {
	Dir           string
	SegmentSize   int64
	MaxTotalBytes int64
	SyncMode      SyncMode
	SyncInterval  time.Duration

	// SessionID is the daemon's per-installation session identifier. It is
	// written into meta.json on every WriteMeta call and is IMMUTABLE for
	// the WAL directory's lifetime — first writer wins. If a later wal.Open
	// is invoked with a different SessionID and meta.json on disk already
	// carries a non-empty SessionID, Open errors out (this is the same
	// logical condition the round-7 store-wiring identity gate detects, but
	// surfaced one layer down so the WAL itself refuses to mutate). Empty
	// SessionID is allowed for back-compat with pre-Task-14a callers and
	// tests that don't care about identity; it disables both the persist
	// and the Open validation. Production wiring (Task 27) MUST set this
	// to opts.SessionID.
	SessionID string

	// KeyFingerprint is the daemon's signing-key fingerprint
	// ("sha256:<hex>"). Same persistence and immutability rules as
	// SessionID; same back-compat allowance for empty values.
	KeyFingerprint string

	// ContextDigest is the chain.ComputeContextDigest value the
	// caller has bound to this session (computed from AgentID +
	// SessionID + KeyFingerprint + algorithm + format_version). Same
	// persistence and immutability rules as SessionID: persisted on
	// every WriteMeta call, validated on Open when BOTH the on-disk
	// value AND the caller-supplied value are non-empty. A mismatch
	// triggers ErrIdentityMismatch so the Store can quarantine the
	// old directory and reopen with the new identity — preventing a
	// stale chain (e.g., old AgentID's records) from replaying under
	// a new SessionInit advertising a different digest. Empty is
	// allowed for back-compat with pre-ContextDigest meta files.
	ContextDigest string
}

// ErrIdentityMismatch is returned by Open when the persisted meta.json
// carries a SessionID, KeyFingerprint, or ContextDigest that disagrees
// with the caller-supplied opts. The persisted-vs-expected pairs are
// exposed so upstream callers can include them in operator-facing logs
// without re-parsing the error message.
//
// All three pairs are populated even when only one mismatched — the
// non-mismatching pair carries the matching value on both sides (so
// the operator sees the full identity context). The MismatchedField
// string is one of "session_id", "key_fingerprint", or
// "context_digest" and identifies which check tripped first; the
// checks run in that priority order.
type ErrIdentityMismatch struct {
	MismatchedField         string // "session_id" | "key_fingerprint" | "context_digest"
	PersistedSessionID      string
	ExpectedSessionID       string
	PersistedKeyFingerprint string
	ExpectedKeyFingerprint  string
	PersistedContextDigest  string
	ExpectedContextDigest   string
}

// Error implements the error interface for ErrIdentityMismatch. The message
// shape ("wal.Open: <field> mismatch: persisted=%q opts=%q") is part of the
// public contract so log scrapers and tests can match without re-parsing.
func (e *ErrIdentityMismatch) Error() string {
	switch e.MismatchedField {
	case "session_id":
		return fmt.Sprintf("wal.Open: session_id mismatch: persisted=%q opts=%q", e.PersistedSessionID, e.ExpectedSessionID)
	case "context_digest":
		return fmt.Sprintf("wal.Open: context_digest mismatch: persisted=%q opts=%q", e.PersistedContextDigest, e.ExpectedContextDigest)
	default:
		return fmt.Sprintf("wal.Open: key_fingerprint mismatch: persisted=%q opts=%q", e.PersistedKeyFingerprint, e.ExpectedKeyFingerprint)
	}
}

// AppendResult is returned by WAL.Append. GenerationRolled is set exactly when
// this Append rolled the segment for a new generation (i.e. the previous
// segment was sealed and a fresh segment was opened with the new generation
// header). The first record on a brand-new WAL does NOT count as a roll.
type AppendResult struct {
	GenerationRolled bool
}

// FailureClass classifies an Append failure into clean or ambiguous, driving
// the caller's transactional Compute → Append → Commit/Fatal pattern.
type FailureClass int

const (
	// FailureNone is the zero value used for non-failure paths.
	FailureNone FailureClass = iota
	// FailureClean means no I/O was attempted (validation rejected the call).
	// The caller can safely retry or surface the error without re-shaping
	// downstream chain state.
	FailureClean
	// FailureAmbiguous means I/O was attempted and the on-disk state may or
	// may not have been mutated. The caller MUST treat the chain as broken
	// (audit.SinkChain.Fatal).
	FailureAmbiguous
)

// AppendError wraps an Append error with its classification. Use IsClean or
// IsAmbiguous to inspect; use errors.As for type-assertion.
type AppendError struct {
	Class FailureClass
	Op    string
	Err   error
}

func (e *AppendError) Error() string { return fmt.Sprintf("wal %s: %v", e.Op, e.Err) }
func (e *AppendError) Unwrap() error { return e.Err }

// IsClean reports whether err (or any error in its chain) is an AppendError
// classified as FailureClean. Returns false for nil.
func IsClean(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureClean
	}
	return false
}

// IsAmbiguous reports whether err (or any error in its chain) is an
// AppendError classified as FailureAmbiguous. Returns false for nil.
func IsAmbiguous(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureAmbiguous
	}
	return false
}

// ErrClosed is wrapped in a clean AppendError when Append is called on a
// closed WAL. No I/O is attempted.
var ErrClosed = errors.New("wal: closed")

// ErrFatal is wrapped in a clean AppendError when Append is called on a WAL
// that has previously returned an ambiguous failure. The WAL latches into
// a fatal state on any ambiguous error so subsequent appends fail fast
// without compounding on-disk corruption — the caller MUST Close the WAL
// and reopen it to resume. The original ambiguous error is wrapped via
// fmt.Errorf("%w: %v", ErrFatal, originalErr) so callers can inspect both
// via errors.Is(err, ErrFatal) and the formatted message.
var ErrFatal = errors.New("wal: fatal error — WAL must be closed and reopened")

// appendInjector is a TEST-ONLY hook used by Task 24's integrity tests
// (internal/store/watchtower/integrity_test.go) to simulate clean and
// ambiguous Append failures without touching the filesystem.
//
// CONTRACT (narrow, failure-injection only):
//   - A non-nil return from the injector short-circuits Append: the
//     error is returned to the caller verbatim and, if it unwraps to
//     an *AppendError with Class == FailureAmbiguous, w.fatalErr is
//     latched identically to a real I/O-ambiguous failure so
//     subsequent Appends surface ErrFatal.
//   - A nil return means "skip the injection; continue with the real
//     write path." Tests that want to suppress I/O MUST return a
//     non-nil error.
//
// Ordering: the injector runs AFTER the clean-validation preflight
// checks (closed, fatal-latched, oversized-payload) so an installed
// hook cannot convert a validation rejection into an injected
// ambiguous latch — those checks would have returned a clean failure
// independently of any injector, and the injector MUST NOT be able
// to create WAL states unreachable by the real code path.
//
// PRODUCTION CODE MUST NOT CALL SetAppendInjector. The hook is
// exposed only because test-only filesystem fault injection (chmod
// 000, full-disk emulation) is flaky across CI platforms; a Go-level
// hook gives deterministic coverage of the clean-vs-ambiguous error
// classes the Store's transactional pattern relies on.
var (
	appendInjector   func() error
	appendInjectorMu sync.Mutex
)

// SetAppendInjector installs a test-only failure-injection hook. See
// the appendInjector package-level docstring for the full contract:
// non-nil return short-circuits Append; nil return continues to the
// real write path. Pass nil to remove a previously installed
// injector.
func SetAppendInjector(fn func() error) {
	appendInjectorMu.Lock()
	appendInjector = fn
	appendInjectorMu.Unlock()
}

// getAppendInjector returns the currently installed test-only hook, or
// nil when none is installed. Holds the mutex briefly so concurrent
// SetAppendInjector calls from test cleanup don't race the production
// Append path.
func getAppendInjector() func() error {
	appendInjectorMu.Lock()
	defer appendInjectorMu.Unlock()
	return appendInjector
}

// nonEmpty returns a if it's non-empty; otherwise b. Used by the
// identity-backfill path on Open to adopt caller-supplied fields
// only when the persisted field is empty.
func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// segmentsDirHasRecords reports whether segDir contains at least one
// segment with an actual user-record (RecordData) payload. Used by
// Open's identity-backfill and seed paths to refuse silent caller-
// identity adoption when the WAL already carries records — those
// records may have been chained under a different identity and must
// not be silently re-chained under the new caller's values (roborev
// #5985 High #2).
//
// FILENAME PRESENCE IS NOT ENOUGH (roborev #5989 Medium): the WAL
// supports header-only segments (e.g., the AppendLoss path opens a
// new segment for a loss marker on a fresh generation, and a close
// that happens before any data record lands leaves a header-only
// .seg file). A header-only segment carries no IntegrityRecord, so
// it has no identity to drift from; classifying it as "record-
// bearing" would incorrectly quarantine a benign upgrade. We instead
// scan each segment's frames via segmentHighSeqAndGen and report
// true only when hasUser=true (at least one RecordData record).
//
// maxPayload is the segment's maximum record payload size, derived
// from opts.SegmentSize - SegmentHeaderSize (same as w.maxRec).
//
// Returns (false, nil) when segDir does not yet exist (fresh
// directory, first open).
func segmentsDirHasRecords(segDir string, maxPayload int) (bool, error) {
	entries, err := os.ReadDir(segDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) && !strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		path := filepath.Join(segDir, name)
		_, hasUser, _, _, scanErr := segmentHighSeqAndGen(path, maxPayload)
		if scanErr != nil {
			// A corrupt/truncated segment is still evidence the WAL
			// was used at some point; err on the safe side and
			// treat as record-bearing so the caller quarantines
			// rather than silently adopting.
			return true, nil
		}
		if hasUser {
			return true, nil
		}
	}
	return false, nil
}

// recordBearingBackfillMismatch constructs an ErrIdentityMismatch for
// the roborev #5985 High #2 case: a WAL with existing records whose
// persisted identity is empty while the caller supplies non-empty
// values. The mismatched field is the first empty-persisted field
// the caller is trying to backfill (priority: session_id →
// key_fingerprint → context_digest) — this matches the priority of
// the full-identity-check path and keeps the operator-facing
// reporting deterministic.
func recordBearingBackfillMismatch(m Meta, opts Options) *ErrIdentityMismatch {
	e := &ErrIdentityMismatch{
		PersistedSessionID:      m.SessionID,
		ExpectedSessionID:       opts.SessionID,
		PersistedKeyFingerprint: m.KeyFingerprint,
		ExpectedKeyFingerprint:  opts.KeyFingerprint,
		PersistedContextDigest:  m.ContextDigest,
		ExpectedContextDigest:   opts.ContextDigest,
	}
	switch {
	case m.SessionID == "" && opts.SessionID != "":
		e.MismatchedField = "session_id"
	case m.KeyFingerprint == "" && opts.KeyFingerprint != "":
		e.MismatchedField = "key_fingerprint"
	case m.ContextDigest == "" && opts.ContextDigest != "":
		e.MismatchedField = "context_digest"
	default:
		// All persisted fields are present but the backfill code
		// called here with nothing to fill — shouldn't happen; fall
		// back to context_digest so the error is informative.
		e.MismatchedField = "context_digest"
	}
	return e
}

// recordOverhead is the per-record on-disk cost beyond the payload bytes
// themselves: an 8-byte frame header (uint32 length + uint32 CRC) plus the
// 12-byte (seq:int64 + gen:uint32) prefix this WAL adds to each record so
// recovery can read the high-watermark without parsing the protobuf payload.
const recordOverhead = 8 + 12

// sealedSuffix and inprogressSuffix are the on-disk filename suffixes for
// sealed and in-progress segment files, respectively. Centralized here so
// recover()'s parseSegmentIndex helper can switch on them without rebuilding
// the suffix string at each call site.
const (
	sealedSuffix     = segmentExt
	inprogressSuffix = segmentExt + inProgressSuffix
)

// WAL is the per-sink write-ahead log. Concurrency: AppendEvent serialization
// is the caller's responsibility (the WTP Store holds an outer lock); WAL's
// own internal mutex protects the segment switch but does not allow
// concurrent Append from multiple goroutines.
type WAL struct {
	opts   Options
	maxRec int

	mu         sync.Mutex
	current    *Segment
	segDir     string
	closed     bool
	fatalErr   error
	highSeq    uint64
	highGen    uint32
	nextIndex  uint64
	totalBytes int64
	// ackHighSeq mirrors Meta.AckHighWatermarkSeq so the overflow path can
	// distinguish sealed segments that the receiver already has (silent GC)
	// from sealed segments holding still-unacked data (must emit a
	// TransportLoss marker on drop). Loaded from meta.json at Open;
	// updated by MarkAcked (which also persists it). Seqs are NOT globally
	// monotonic across generations — see ackHighGen.
	ackHighSeq uint64
	ackHighGen uint32 // ack watermark generation; combined with ackHighSeq forms a (gen, seq) tuple
	ackPresent bool   // true once an ack has been persisted; zero values are NOT a valid watermark

	// perGenDataHighWater maps generation -> highest RecordData sequence on
	// disk for that generation. Required by Task 14a's WrittenDataHighWater
	// accessor: O(1) lookup on the recv hot path (every BatchAck +
	// ServerHeartbeat + SessionAck calls it via applyServerAckTuple). Per
	// the round-13 performance budget this map is the MANDATORY
	// implementation of WrittenDataHighWater (no fallback to per-call
	// segment scan).
	//
	// Populated at Open() via a single recovery scan of every segment file,
	// updated by every successful Append for a RecordData entry. Loss
	// markers and segment-header seeds (header-only generations) NEVER
	// contribute. An entry's absence from the map means the writer has not
	// emitted a RecordData for that generation; an entry's presence means
	// at least one RecordData has been durably written and not yet GC'd.
	//
	// GC-aware: when MarkAcked / overflow GC removes the LAST surviving
	// segment for a generation, the entry is deleted (so a fully-GC'd
	// generation reports ok=false rather than a stale max).
	//
	// Mutated only under w.mu.
	perGenDataHighWater map[uint32]uint64

	// perGenAnyReplayable is the set of generations for which AT LEAST ONE
	// payload — RecordData OR loss marker — has been durably written to a
	// segment whose header carries that generation. It is the guard the
	// transport's computeReplayPlan uses (round-16 Finding 2) to decide
	// whether to schedule a replay stage for an intermediate generation.
	//
	// perGenDataHighWater alone is insufficient: it is data-only, so a
	// generation that exists on disk but contains ONLY loss markers (e.g.
	// produced by overflow GC mid-session, with no subsequent Append before
	// disconnect) reports ok=false from WrittenDataHighWater and would be
	// silently dropped from the replay plan — leaving the server unaware of
	// the gap. perGenAnyReplayable closes that hole by tracking the
	// segment's generation key whenever any payload is written.
	//
	// Populated at Open() via a single recovery scan of every segment file
	// (header generation is keyed for any framed payload, including loss
	// markers and data records); updated by every successful Append for
	// RecordData, every AppendLoss / appendLossLocked for loss markers.
	// Header-only segments (segment header but no records) NEVER contribute
	// — segment headers alone do not constitute a replayable payload.
	//
	// GC-aware: pruned by prunePerGenMapsLocked when the LAST surviving
	// segment for a generation is removed, mirroring perGenDataHighWater.
	//
	// Mutated only under w.mu.
	perGenAnyReplayable map[uint32]struct{}

	// readers tracks open Reader instances so Append/AppendLoss can wake them
	// via notifyReaders, and Close can drop their file handles. Mutated only
	// under w.mu.
	readers []*Reader
}

// segmentEntry pairs a segment filename with its parsed numeric index so
// recovery can pick the numeric maximum (rather than the lexicographic
// maximum, which silently breaks once an index crosses 10^10).
type segmentEntry struct {
	name string
	idx  uint64
}

// Open opens or creates the WAL directory at opts.Dir. On open, all sealed
// segments are scanned and the highest (sequence, generation) is recovered.
// Any .INPROGRESS file is reopened for append.
func Open(opts Options) (*WAL, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal.Open: Dir required")
	}
	if opts.SegmentSize <= int64(SegmentHeaderSize) {
		return nil, fmt.Errorf("wal: SegmentSize %d must exceed SegmentHeaderSize %d",
			opts.SegmentSize, SegmentHeaderSize)
	}
	// Per-record cap is the segment budget minus the fixed segment header.
	// Both the framing layer and the segment writer use this to bound a
	// single record's payload; computing it once here keeps OpenSegment,
	// ReopenSegment, and ReadRecord aligned with the configured segment
	// size.
	maxRec := int(opts.SegmentSize - int64(SegmentHeaderSize))
	if maxRec <= 0 || uint64(maxRec) > MaxFramedPayload {
		return nil, fmt.Errorf("wal: SegmentSize %d invalid; need room for header+record within MaxFramedPayload",
			opts.SegmentSize)
	}
	// SyncDeferred is documented as a forward-compatible mode but the
	// periodic-sync hook is not yet implemented. Accepting it would let
	// successful appends linger in the bufio.Writer until Close, so a
	// crash would silently drop acknowledged records — exactly the
	// failure mode this WAL is built to prevent. Reject it explicitly
	// until the timer task is wired up; the failure is at Open time so
	// callers can adjust configuration before any events are written.
	if opts.SyncMode != SyncImmediate {
		return nil, errors.New("wal.Open: only SyncImmediate is implemented; SyncDeferred requires the periodic-sync timer hook")
	}
	segDir := filepath.Join(opts.Dir, "segments")
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir segments: %w", err)
	}
	w := &WAL{opts: opts, maxRec: maxRec, segDir: segDir, perGenDataHighWater: make(map[uint32]uint64), perGenAnyReplayable: make(map[uint32]struct{})}
	// Load the ack watermark BEFORE recover() so the overflow path (which
	// can fire on the very first Append after Open) sees a consistent
	// view: sealed segments fully covered by ack are silently GC'd, while
	// segments holding unacked records emit a TransportLoss marker on
	// drop. Missing meta.json is fine — a fresh WAL has nothing acked
	// yet (ackPresent stays false). Any other read error is fatal at
	// open time. Only honor the on-disk seq/gen when AckRecorded is true:
	// the zero value (gen=0, seq=0) is indistinguishable from a real ack
	// at that watermark, so silent GC must not be allowed to fire on it.
	if m, err := ReadMeta(opts.Dir); err == nil {
		if m.AckRecorded {
			w.ackHighSeq = m.AckHighWatermarkSeq
			w.ackHighGen = m.AckHighWatermarkGen
			w.ackPresent = true
		}
		// Identity check (Task 14a + roborev #5957 Medium #2). Only
		// validate when BOTH the on-disk value is non-empty AND the
		// caller-supplied value is non-empty. The "either side empty"
		// case is the v2-with-empty-identity migration: a pre-Task-14a
		// (or pre-ContextDigest) meta.json carried a subset of the
		// identity triple, OR the test caller deliberately omits a
		// field. In both, we adopt (don't error) — the next meta
		// write populates the field from opts. Checks run in priority
		// order: session_id → key_fingerprint → context_digest; on
		// simultaneous mismatch the earliest-priority field is
		// reported.
		if m.SessionID != "" && opts.SessionID != "" && m.SessionID != opts.SessionID {
			return nil, &ErrIdentityMismatch{
				MismatchedField:         "session_id",
				PersistedSessionID:      m.SessionID,
				ExpectedSessionID:       opts.SessionID,
				PersistedKeyFingerprint: m.KeyFingerprint,
				ExpectedKeyFingerprint:  opts.KeyFingerprint,
				PersistedContextDigest:  m.ContextDigest,
				ExpectedContextDigest:   opts.ContextDigest,
			}
		}
		if m.KeyFingerprint != "" && opts.KeyFingerprint != "" && m.KeyFingerprint != opts.KeyFingerprint {
			return nil, &ErrIdentityMismatch{
				MismatchedField:         "key_fingerprint",
				PersistedSessionID:      m.SessionID,
				ExpectedSessionID:       opts.SessionID,
				PersistedKeyFingerprint: m.KeyFingerprint,
				ExpectedKeyFingerprint:  opts.KeyFingerprint,
				PersistedContextDigest:  m.ContextDigest,
				ExpectedContextDigest:   opts.ContextDigest,
			}
		}
		if m.ContextDigest != "" && opts.ContextDigest != "" && m.ContextDigest != opts.ContextDigest {
			return nil, &ErrIdentityMismatch{
				MismatchedField:         "context_digest",
				PersistedSessionID:      m.SessionID,
				ExpectedSessionID:       opts.SessionID,
				PersistedKeyFingerprint: m.KeyFingerprint,
				ExpectedKeyFingerprint:  opts.KeyFingerprint,
				PersistedContextDigest:  m.ContextDigest,
				ExpectedContextDigest:   opts.ContextDigest,
			}
		}

		// Upgrade-path backfill (roborev #5976 Medium / #5985 High #2).
		// If the on-disk meta.json is missing any identity field that
		// the caller now supplies, rewrite it in place so subsequent
		// Opens can detect mismatches.
		//
		// SAFETY GATE: adopt-and-backfill is ONLY safe when the WAL
		// is empty. A record-bearing WAL whose persisted identity is
		// empty (because the file was created before this identity
		// field existed) cannot prove its records were chained under
		// the caller's identity — they might be from a different
		// AgentID / session. Silently backfilling would let stale
		// records replay under a new SessionInit advertising a
		// different digest. For record-bearing WALs we instead
		// return ErrIdentityMismatch so the Store-layer quarantine
		// path runs and the WAL is renamed out of the way.
		backfillNeeded := (m.SessionID == "" && opts.SessionID != "") ||
			(m.KeyFingerprint == "" && opts.KeyFingerprint != "") ||
			(m.ContextDigest == "" && opts.ContextDigest != "")
		if backfillNeeded {
			hasRecords, err := segmentsDirHasRecords(segDir, maxRec)
			if err != nil {
				return nil, fmt.Errorf("scan segments for backfill safety: %w", err)
			}
			if hasRecords {
				return nil, recordBearingBackfillMismatch(m, opts)
			}
			// Preserve ack state verbatim (AckRecorded, watermark,
			// and generation) so the backfill doesn't promote a
			// pre-ack seed meta to "ack recorded" or lose the
			// existing ack tuple.
			m.SessionID = nonEmpty(m.SessionID, opts.SessionID)
			m.KeyFingerprint = nonEmpty(m.KeyFingerprint, opts.KeyFingerprint)
			m.ContextDigest = nonEmpty(m.ContextDigest, opts.ContextDigest)
			if err := WriteMeta(opts.Dir, m); err != nil {
				return nil, fmt.Errorf("backfill identity meta: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read meta: %w", err)
	} else if opts.SessionID != "" || opts.KeyFingerprint != "" || opts.ContextDigest != "" {
		// No meta.json yet AND the caller supplied at least one
		// identity field. Seed meta only when the WAL is also
		// empty — a record-bearing WAL without meta is suspicious
		// (records exist but we have no identity to validate them
		// against) and MUST NOT adopt caller identity silently.
		// Same rationale as the backfill path above (roborev
		// #5985 High #2).
		hasRecords, err := segmentsDirHasRecords(segDir, maxRec)
		if err != nil {
			return nil, fmt.Errorf("scan segments for seed safety: %w", err)
		}
		if hasRecords {
			return nil, recordBearingBackfillMismatch(Meta{}, opts)
		}
		if err := WriteMeta(opts.Dir, Meta{
			AckRecorded:    false,
			SessionID:      opts.SessionID,
			KeyFingerprint: opts.KeyFingerprint,
			ContextDigest:  opts.ContextDigest,
		}); err != nil {
			return nil, fmt.Errorf("seed identity meta: %w", err)
		}
	}
	if err := w.recover(); err != nil {
		return nil, err
	}
	return w, nil
}

// parseSegmentIndex extracts the numeric index from a segment filename. It
// recognizes both the sealed (".seg") and in-progress (".seg.INPROGRESS")
// suffixes. Returns (0, false) for any other name.
//
// Implementation note: an earlier version used fmt.Sscanf("%010d", ...) which
// silently caps at 10 digits and would fail to recover indices ≥ 10^10. We
// strip the suffix and parse the remaining prefix as a uint64 instead.
func parseSegmentIndex(name string) (uint64, bool) {
	var prefix string
	switch {
	case strings.HasSuffix(name, inprogressSuffix):
		prefix = strings.TrimSuffix(name, inprogressSuffix)
	case strings.HasSuffix(name, sealedSuffix):
		prefix = strings.TrimSuffix(name, sealedSuffix)
	default:
		return 0, false
	}
	idx, err := strconv.ParseUint(prefix, 10, 64)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// pickMaxByIndex returns the entry with the largest numeric index, or false
// if entries is empty. Used by recover() to find the live (or last sealed)
// segment without relying on lexicographic order — once segment indices
// cross 10^10 (digit count changes), filename order stops matching numeric
// order and a sort.Strings()-based "last wins" picks the wrong segment.
func pickMaxByIndex(entries []segmentEntry) (segmentEntry, bool) {
	if len(entries) == 0 {
		return segmentEntry{}, false
	}
	max := entries[0]
	for _, e := range entries[1:] {
		if e.idx > max.idx {
			max = e
		}
	}
	return max, true
}

// isLossMarker reports whether payload is a synthetic TransportLoss record
// inserted by AppendLoss/appendLossLocked. Discriminates by the fixed
// LossMarkerSentinel prefix; ordinary records carry an arbitrary protobuf
// payload after their seq/gen framing, so the sentinel never collides.
//
// All scan paths (recover, segmentHighSeq, dropOldestLocked) MUST call this
// before parseSeqGen — the sentinel's first 8 bytes ("\x00WTPLOSS") would
// otherwise decode as seq ≈ 0x0057545050... which is a real-looking but
// utterly bogus high-watermark, defeating MarkAcked GC.
func isLossMarker(payload []byte) bool {
	return len(payload) >= len(LossMarkerSentinel) &&
		string(payload[:len(LossMarkerSentinel)]) == LossMarkerSentinel
}

func (w *WAL) recover() error {
	dirEntries, err := os.ReadDir(w.segDir)
	if err != nil {
		return fmt.Errorf("readdir segments: %w", err)
	}
	var sealed, inProgress []segmentEntry
	for _, e := range dirEntries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		switch {
		case strings.HasSuffix(name, inprogressSuffix):
			inProgress = append(inProgress, segmentEntry{name: name, idx: idx})
		case strings.HasSuffix(name, sealedSuffix):
			sealed = append(sealed, segmentEntry{name: name, idx: idx})
		}
	}
	// Sort by numeric index for deterministic processing (currently only the
	// "compute totalBytes" loop walks every entry; the live-segment picks
	// below use pickMaxByIndex, not the sort order).
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	sort.Slice(inProgress, func(i, j int) bool { return inProgress[i].idx < inProgress[j].idx })

	// Rebuild high-watermark (the segment file index, not the record seq) by
	// taking the numeric maximum across both sealed and inProgress.
	maxIdx := uint64(0)
	if e, ok := pickMaxByIndex(sealed); ok && e.idx >= maxIdx {
		maxIdx = e.idx
	}
	if e, ok := pickMaxByIndex(inProgress); ok && e.idx >= maxIdx {
		maxIdx = e.idx
	}
	w.nextIndex = maxIdx + 1

	// Scan the live (or last sealed) segment for the highest seq/gen seen.
	// scanForRecovery returns the offset of the first byte AFTER the last
	// known-good record, so a corrupt or truncated tail can be truncated
	// before we reopen the file for append. Returning the offset (and not
	// just the high-watermark) is what closes the "appending after a
	// corrupt tail" hole that recovery used to leave open.
	scanForRecovery := func(path string) (lastGood int64, scanErr error) {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		hdr, err := ReadSegmentHeader(f)
		if err != nil {
			return 0, err
		}
		// Seed the high-water generation from the header so an empty
		// segment still updates highGen. Real records will overwrite
		// these as the loop progresses.
		w.highGen = hdr.Generation
		// After reading the header, the cursor is at SegmentHeaderSize.
		// Track the offset of the first byte past the last successfully
		// decoded record so the caller can truncate any garbage tail.
		lastGood = int64(SegmentHeaderSize)
		for {
			payload, err := ReadRecord(f, w.maxRec)
			// Recovery treats a clean EOF, a truncated tail
			// (io.ErrUnexpectedEOF), a CRC mismatch, and a
			// structurally corrupt frame header (ErrCorruptFrame)
			// as the same "stop scanning" signal. The framing
			// layer wraps the underlying io errors with %w, so use
			// errors.Is so wrapping doesn't break the recovery loop.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
				errors.Is(err, ErrCRCMismatch) || errors.Is(err, ErrCorruptFrame) {
				return lastGood, nil
			}
			if err != nil {
				return lastGood, err
			}
			// Only advance lastGood after we have actually decoded
			// a record; this is the offset at which the next
			// record would begin.
			off, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return lastGood, err
			}
			lastGood = off
			// Loss markers carry the LossMarkerSentinel prefix instead
			// of an encodeSeqGenFrame, so feeding their bytes to
			// parseSeqGen would yield a junk seq (the sentinel bytes
			// decode as ~0x0057545050... = a huge number) and corrupt
			// the recovered high-watermark. Skip them for the
			// data-watermark seed below — they do not advance the
			// user-record stream — but DO seed perGenAnyReplayable
			// (round-16 Finding 2): a loss marker is itself a payload
			// the replayer must surface to the server, so its presence
			// alone makes the segment's generation replayable.
			if isLossMarker(payload) {
				w.perGenAnyReplayable[hdr.Generation] = struct{}{}
				continue
			}
			if seq, gen, ok := parseSeqGen(payload); ok {
				w.highSeq = seq
				w.highGen = gen
				// Seed perGenDataHighWater so WrittenDataHighWater is
				// O(1) at runtime. Only RecordData seqs land here —
				// loss markers and segment-header seeds are excluded
				// upstream (the loss-marker case is handled by the
				// continue above; header-only segments produce no
				// payloads at all).
				if cur, exists := w.perGenDataHighWater[gen]; !exists || seq > cur {
					w.perGenDataHighWater[gen] = seq
				}
				// A data record is a replayable payload too — seed
				// perGenAnyReplayable on the header generation so
				// recovery covers both kinds of payload uniformly.
				w.perGenAnyReplayable[hdr.Generation] = struct{}{}
			}
		}
	}

	// truncateLiveSegment chops the .INPROGRESS file at lastGood. Without
	// this, a recovered corrupt or truncated tail stays on disk; the next
	// Append writes after the bad bytes, and a future recovery scan stops
	// at the same bad tail — never reaching the newly appended records.
	truncateLiveSegment := func(path string, lastGood int64) error {
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if st.Size() == lastGood {
			return nil
		}
		if err := f.Truncate(lastGood); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		// Sync the parent directory too so the size change is durable
		// across crashes (the segment dir uses the cross-platform
		// fsync-parent-dir helper used elsewhere in this package).
		return syncDir(filepath.Dir(path))
	}

	if e, ok := pickMaxByIndex(inProgress); ok {
		// Reopen for append. Scan first to seed high-watermark, truncate
		// any corrupt tail, then reopen the writer at EOF.
		path := filepath.Join(w.segDir, e.name)
		lastGood, err := scanForRecovery(path)
		if err != nil {
			return err
		}
		if err := truncateLiveSegment(path, lastGood); err != nil {
			return fmt.Errorf("truncate live segment: %w", err)
		}
		seg, err := ReopenSegment(path, w.maxRec)
		if err != nil {
			return err
		}
		w.current = seg
		// Use the existing index, not a fresh one.
		w.nextIndex = seg.Index() + 1
	} else if e, ok := pickMaxByIndex(sealed); ok {
		// Last segment is sealed; scan it for high-watermark only. A
		// sealed segment with a corrupt tail is a deeper inconsistency
		// — we cannot rewrite a sealed file from inside recovery — but
		// at least the high-watermark is bounded by the last good
		// record so future generations don't reuse a seq.
		path := filepath.Join(w.segDir, e.name)
		if _, err := scanForRecovery(path); err != nil {
			return err
		}
	}

	// Compute total bytes for overflow tracking AFTER any truncation, so
	// the byte budget reflects the post-recovery on-disk size.
	for _, e := range sealed {
		st, err := os.Stat(filepath.Join(w.segDir, e.name))
		if err != nil {
			return err
		}
		w.totalBytes += st.Size()
	}
	for _, e := range inProgress {
		st, err := os.Stat(filepath.Join(w.segDir, e.name))
		if err != nil {
			return err
		}
		w.totalBytes += st.Size()
	}

	// Seed perGenDataHighWater across every segment on disk so the round-13
	// O(1) WrittenDataHighWater accessor reflects the full multi-generation
	// state, not just the last segment scanned by scanForRecovery above.
	// Only RecordData entries contribute; loss markers and header-only
	// segments are excluded by isLossMarker / no-payload, matching the
	// Append path's invariants. Also seed perGenAnyReplayable for any
	// segment carrying ANY payload (data record OR loss marker) so the
	// round-16 Finding 2 transport replay-plan accessor sees loss-only
	// generations as replayable; header-only segments are excluded.
	allSegments := make([]segmentEntry, 0, len(sealed)+len(inProgress))
	allSegments = append(allSegments, sealed...)
	allSegments = append(allSegments, inProgress...)
	for _, e := range allSegments {
		path := filepath.Join(w.segDir, e.name)
		hi, hasUser, segGen, hasAnyPayload, scanErr := segmentHighSeqAndGen(path, w.maxRec)
		if scanErr != nil {
			// Skip individual segment errors here — the active scan
			// path above already surfaced them on the live/last
			// segment, and the totalBytes loop above already covered
			// stat failures. A scan failure on an older sealed
			// segment leaves its perGenDataHighWater entry absent
			// (best-effort recovery).
			continue
		}
		if hasAnyPayload {
			w.perGenAnyReplayable[segGen] = struct{}{}
		}
		if !hasUser {
			continue
		}
		if cur, exists := w.perGenDataHighWater[segGen]; !exists || hi > cur {
			w.perGenDataHighWater[segGen] = hi
		}
	}
	return nil
}

// HighWatermark returns the highest sequence number the WAL has durably
// recorded, across both sealed segments and the live .INPROGRESS file. The
// value is the seq value itself (e.g. 4 after appending seqs 0..4), not a
// count.
func (w *WAL) HighWatermark() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highSeq
}

// HighGeneration returns the generation of the most recently appended record.
func (w *WAL) HighGeneration() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highGen
}

// HighWaterSequence returns the highest sequence the WAL has durably
// appended so far, across all generations. Alias for HighWatermark —
// provided with the Task-14a name so transport-layer code (replayer tail
// watermark, reader catch-up probe) can use the more explicit name without
// every call site having to comment that "HighWatermark is a sequence, not
// a byte count". Zero before any successful Append.
//
// Cross-generation: seqs restart at 0 on every generation roll, so a
// higher-generation seq=3 can logically dominate a lower-generation seq=99.
// HighWaterSequence does NOT reflect that ordering — it is strictly the
// raw highest seq ever appended. Callers that need cross-generation
// comparison should use the (gen, seq) tuple via HighGeneration +
// HighWaterSequence or the Meta.AckHighWatermarkGen / Seq pair.
func (w *WAL) HighWaterSequence() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highSeq
}

// WrittenDataHighWater returns the highest RecordData sequence durably
// written to disk for the given generation, or ok=false if no data-bearing
// record has ever been appended for that generation.
//
// O(1): backed by the in-memory perGenDataHighWater map which Append
// updates on every successful RecordData write and which Open seeds from
// a full-disk scan at startup. Loss markers (AppendLoss / overflow GC) do
// NOT update the map — they are not RecordData. Header-only segments (a
// segment opened for gen=N but closed before any RecordData was written)
// also do not update the map; WrittenDataHighWater(N) returns ok=false
// for those, matching the contract documented on the map field itself.
//
// Returns an error only if the underlying WAL has been closed; in steady
// state the result is (seq, true, nil) for every generation with data,
// (0, false, nil) for every other generation the caller might probe.
//
// Used by Task 15.1 / 17.X (transport replay-start cursor selection) to
// determine whether the server's reported high-watermark is a
// post-generation-roll or a post-GC regression; per Task 14b the
// replayer also filters Reader records to exactly the requested
// generation using this ceiling as the termination signal.
func (w *WAL) WrittenDataHighWater(gen uint32) (uint64, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, false, ErrClosed
	}
	seq, ok := w.perGenDataHighWater[gen]
	return seq, ok, nil
}

// HasDataBelowGeneration reports whether any RecordData has been durably
// written to disk for a generation strictly less than threshold. It is the
// guard the transport's first-apply ack validation uses (round-16 Finding 1)
// to detect when adopting (serverGen, serverSeq=0) would silently over-ack
// data in a lower generation: MarkAcked enforces lex order on (gen, seq),
// so persisting (G, 0) when local data exists at any (g < G) marks all of
// that lower-gen data as fully acked and reclaims it on the next GC pass.
//
// Adopting a higher-gen ack tuple is only safe when the WAL has no
// data-bearing record below that generation — either because the agent was
// truly cold (Open scan filled perGenDataHighWater with nothing) or because
// every lower-gen record has already been GC'd via a prior ack (the map
// entry was removed by prunePerGenMapsLocked when its last segment
// went away). Without this guard a server that legitimately advanced beyond
// our last on-disk position — e.g., after the agent restored from a
// snapshot whose WAL is older than the server's persisted state — would
// poison MarkAcked's predicate and destroy not-yet-delivered records.
//
// O(N) in the number of generations currently tracked by the in-memory
// map (which is bounded by the number of generations that have at least
// one un-GC'd data record on disk — usually 0–2). Callers can treat it as
// effectively constant on the recv hot path. Returns ErrClosed if the WAL
// has been closed; never returns any other error.
func (w *WAL) HasDataBelowGeneration(threshold uint32) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false, ErrClosed
	}
	for gen := range w.perGenDataHighWater {
		if gen < threshold {
			return true, nil
		}
	}
	return false, nil
}

// HasReplayableRecords reports whether the WAL holds AT LEAST ONE replayable
// payload — RecordData OR loss marker — in a segment whose header carries
// the requested generation. It is the guard the transport's
// computeReplayPlan uses (round-16 Finding 2) to decide whether to schedule
// a replay stage for an intermediate generation.
//
// WrittenDataHighWater alone is insufficient: it answers data-only, so a
// generation that exists on disk but contains ONLY loss markers (e.g.,
// produced by overflow GC mid-session, with no subsequent RecordData
// Append before disconnect) returns ok=false there and would be silently
// dropped from the replay plan — leaving the server unaware of the gap.
// HasReplayableRecords closes that hole by including loss-marker-only
// generations in the replay plan; the receiver then observes the gap on
// reconnect.
//
// Returns true when the in-memory perGenAnyReplayable set contains gen,
// false otherwise. The set entry is created when the very first payload
// (data or loss) for a generation is written, and removed when the LAST
// surviving segment for that generation is GC'd by
// prunePerGenMapsLocked. Header-only segments (segment header but no
// records) NEVER contribute — segment headers alone are not a replayable
// payload.
//
// O(1) under the WAL lock. Used by the reconnect/replay-plan computation,
// not the recv hot path. Returns ErrClosed if the WAL has been closed;
// never returns any other error.
func (w *WAL) HasReplayableRecords(gen uint32) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false, ErrClosed
	}
	_, ok := w.perGenAnyReplayable[gen]
	return ok, nil
}

// EarliestDataSequence returns the lowest RecordData sequence still on
// disk for the given generation, or ok=false if no data-bearing segment
// for that generation survives (either it was never opened, or every
// segment for it has been GC'd).
//
// Unlike WrittenDataHighWater, this accessor performs a per-call scan —
// it reads the segment directory, filters by header.Generation == gen,
// opens the numerically-smallest one and returns the first RecordData
// seq it finds. Header-only segments (gen header but no RecordData in
// the file) are silently skipped so the accessor falls through to the
// next segment for the same gen. Loss markers on-disk are ALSO skipped
// for the same reason the high-water does: loss is not RecordData.
//
// ENOENT on individual segment files is silently tolerated — GC can
// reclaim a segment between the ReadDir snapshot and the open, and
// reporting that race as an error would make the accessor incorrectly
// return a hard failure on steady-state concurrency. Every other I/O
// error (header corruption, permission denied, etc.) is surfaced.
//
// Returns an error only if the underlying WAL has been closed, or on
// unrecoverable I/O failure.
//
// Used by Task 15.1 / 17.X to answer "what's the oldest data we have
// for gen G on disk?" when computing the replay-start cursor after an
// ack-regression-by-GC is detected.
func (w *WAL) EarliestDataSequence(gen uint32) (uint64, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, false, ErrClosed
	}
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return 0, false, err
	}
	var candidates []segmentEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) && !strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, parseOK := parseSegmentIndex(name)
		if !parseOK {
			continue
		}
		candidates = append(candidates, segmentEntry{name: name, idx: idx})
	}
	// Numeric sort so we examine segments in append order. If a later-
	// indexed segment carries an earlier seq (impossible in steady state
	// within one generation, but the loop is defensive), we still return
	// the FIRST one we successfully decode — the contract is "earliest
	// surviving", not "minimum across all", and within a single generation
	// Append is monotonic in seq.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].idx < candidates[j].idx })
	for _, c := range candidates {
		path := filepath.Join(w.segDir, c.name)
		f, openErr := os.Open(path)
		if openErr != nil {
			if errors.Is(openErr, fs.ErrNotExist) {
				// Concurrent GC raced us between ReadDir and Open —
				// skip silently. The surviving segment for this gen
				// (if any) will appear later in the sorted list.
				continue
			}
			return 0, false, openErr
		}
		hdr, hdrErr := ReadSegmentHeader(f)
		if hdrErr != nil {
			_ = f.Close()
			return 0, false, hdrErr
		}
		if hdr.Generation != gen {
			_ = f.Close()
			continue
		}
		// Segment belongs to the requested gen. Walk its records looking
		// for the first RecordData. Loss markers are silently skipped;
		// header-only segments simply fall through to the next candidate.
		for {
			payload, readErr := ReadRecord(f, w.maxRec)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				// Corrupt or truncated frame — treat as "nothing here"
				// and advance. Losing the exact seq for one bad segment
				// is strictly better than refusing to serve a correct
				// answer from a later segment.
				break
			}
			if isLossMarker(payload) {
				continue
			}
			seq, _, seqOK := parseSeqGen(payload)
			if !seqOK {
				continue
			}
			_ = f.Close()
			return seq, true, nil
		}
		_ = f.Close()
	}
	return 0, false, nil
}

// failAmbiguousLocked latches the WAL into a fatal state and returns an
// AppendError classified as FailureAmbiguous. Callers MUST hold w.mu. After
// this call, every subsequent Append fails fast with a clean ErrFatal-wrapped
// error rather than running against the partially-mutated segment — that's
// what closes the "compound corruption" hole the previous code had open.
func (w *WAL) failAmbiguousLocked(op string, err error) error {
	if w.fatalErr == nil {
		w.fatalErr = err
	}
	return &AppendError{Class: FailureAmbiguous, Op: op, Err: err}
}

// Append writes a record with the given (seq, gen) and payload. See spec
// §"Append — clean vs ambiguous failure classification" for the failure
// taxonomy.
//
// The caller (WTP Store.AppendEvent) MUST follow this with audit.SinkChain.Commit
// on success, or audit.SinkChain.Fatal on ambiguous failure.
func (w *WAL) Append(seq int64, gen uint32, payload []byte) (AppendResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: ErrClosed}
	}
	// Latched fatal: any prior ambiguous failure must prevent further
	// appends so partial mutations don't compound. Surface as a clean
	// failure (no I/O attempted on this call) wrapping ErrFatal so the
	// caller's transactional pattern can detect the latch via errors.Is.
	if w.fatalErr != nil {
		return AppendResult{}, &AppendError{
			Class: FailureClean,
			Op:    "append",
			Err:   fmt.Errorf("%w: %v", ErrFatal, w.fatalErr),
		}
	}
	// The on-disk per-record cost is 8 (frame header) + 12 (seq/gen prefix)
	// + len(payload). Reject up-front if even a fresh segment couldn't fit
	// it after the 16-byte segment header; this is a clean failure because
	// no I/O has been attempted yet.
	if int64(recordOverhead+len(payload)) > w.opts.SegmentSize-int64(SegmentHeaderSize) {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: fmt.Errorf("payload %d exceeds segment budget", len(payload))}
	}
	// Test-only injector hook (see SetAppendInjector). Production code
	// MUST NOT install an injector — the hook is gated behind a
	// package-level variable that nil-production-callers leave
	// untouched.
	//
	// INJECTOR CONTRACT (narrow): the injector is a FAILURE-injection
	// hook only. When it returns a non-nil error, Append replaces its
	// remaining work with that error — an *AppendError classified as
	// FailureAmbiguous latches w.fatalErr identically to a real I/O-
	// ambiguous failure so subsequent Appends surface ErrFatal. When
	// the injector returns nil, Append falls through to the real write
	// path (this is intentional — tests that only want to simulate
	// failure do not have to reimplement the success path).
	//
	// Injector ordering: the injector fires AFTER the clean-validation
	// checks above (closed / fatal latched / oversized-payload). This
	// prevents an installed injector from converting a validation
	// rejection into an injected ambiguous latch — those checks would
	// have returned a clean failure independently of the injector, so
	// the real WAL cannot reach the latched state via that path and
	// neither should the test-only hook.
	if inj := getAppendInjector(); inj != nil {
		if injErr := inj(); injErr != nil {
			var ae *AppendError
			if errors.As(injErr, &ae) && ae.Class == FailureAmbiguous && w.fatalErr == nil {
				w.fatalErr = injErr
			}
			return AppendResult{}, injErr
		}
	}

	// Overflow reclamation, in two phases:
	//
	//  1. Drop sealed segments fully covered by the ack watermark. NO
	//     TransportLoss marker is emitted for these — the receiver
	//     already has those records, so injecting a marker would force
	//     it to spuriously surface a gap on replay.
	//
	//  2. If still over budget, fall back to dropping the oldest sealed
	//     segment unconditionally and emit a TransportLoss marker for
	//     any unacked records it carried. Loop until under budget OR
	//     no more sealed segments remain (in which case we accept the
	//     overage for one record).
	//
	// Both phases must fire BEFORE the segment-full roll below so we
	// never seal+open a new segment that immediately pushes us past
	// the cap.
	if w.totalBytes+int64(w.opts.SegmentSize) > w.opts.MaxTotalBytes {
		if _, err := w.gcAckedLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("overflow-gc-acked", err)
		}
		for w.totalBytes+int64(w.opts.SegmentSize) > w.opts.MaxTotalBytes {
			loss, dropped, hasUserRange, err := w.dropOldestLocked()
			if err != nil {
				return AppendResult{}, w.failAmbiguousLocked("overflow-gc", err)
			}
			if !dropped {
				// Nothing left to drop; proceed and accept the
				// overage. The dropped flag is the source of truth
				// here — we MUST NOT use ToSequence==0 as a
				// "nothing dropped" sentinel because a single-record
				// segment at seq=0 is a legitimate drop with
				// ToSequence==0.
				break
			}
			if !hasUserRange {
				// Dropped segment held only loss markers (or was
				// otherwise empty of user records). The file is
				// gone, but no additional marker is needed —
				// emitting one would manufacture a fake gap. Loop
				// and try the next sealed file.
				continue
			}
			// dropOldestLocked may have removed the oldest sealed
			// segment, but the live (.INPROGRESS) segment is excluded
			// from the sealed set, so w.current remains valid. Open
			// a fresh segment if there isn't one yet (recover-from-
			// empty case).
			if w.current == nil {
				seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
				if err != nil {
					return AppendResult{}, w.failAmbiguousLocked("overflow-open", err)
				}
				w.current = seg
			}
			if err := w.appendLossLocked(loss); err != nil {
				return AppendResult{}, w.failAmbiguousLocked("overflow-loss", err)
			}
		}
	}

	rolled := false
	// Generation roll: seal current segment, open a new one with the new gen.
	// This is the ONLY place that sets rolled=true. The fresh-WAL "first
	// record opens a segment" path below intentionally leaves rolled=false
	// so the very first Append doesn't claim a generation roll occurred.
	if w.current != nil && w.current.Generation() != gen {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("seal-on-gen-roll", err)
		}
		seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-on-gen-roll", err)
		}
		w.current = seg
		rolled = true
	}
	// Open the very first segment (fresh WAL or recovery left no live
	// segment). Mark with FlagGenInit since any first segment IS a new
	// generation, but do NOT set rolled — the boundary semantics only
	// apply when an existing segment was sealed for a generation change.
	if w.current == nil {
		seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-first", err)
		}
		w.current = seg
	}
	// Segment full → roll within the same generation. No FlagGenInit on
	// the new segment because the generation is unchanged.
	if w.current.Bytes()+int64(recordOverhead+len(payload)) > w.opts.SegmentSize {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("seal-on-full", err)
		}
		seg, err := w.openNewSegmentLocked(gen, 0)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-on-full", err)
		}
		w.current = seg
	}

	// The payload encodes its own (seq, gen) for recovery. Prepend a small
	// header here so we can recover seq/gen on replay without parsing the
	// protobuf payload.
	framed := encodeSeqGenFrame(seq, gen, payload)

	if err := w.current.WriteRecord(framed); err != nil {
		return AppendResult{}, w.failAmbiguousLocked("write-record", err)
	}
	if w.opts.SyncMode == SyncImmediate {
		if err := w.current.Sync(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("sync", err)
		}
	}

	w.highSeq = uint64(seq)
	w.highGen = gen
	// Maintain the round-13 per-gen, data-bearing high-water map so
	// WrittenDataHighWater(gen) is O(1) on the recv hot path. Loss markers
	// and segment-header seeds NEVER bump this map (only Append-of-RecordData
	// writes here; AppendLoss is intentionally excluded).
	if cur, exists := w.perGenDataHighWater[gen]; !exists || uint64(seq) > cur {
		w.perGenDataHighWater[gen] = uint64(seq)
	}
	// Maintain the round-16 per-gen any-replayable set so
	// HasReplayableRecords(gen) is O(1) on the reconnect path. Both
	// Append (this site) and AppendLoss/appendLossLocked seed this map
	// using the segment generation. They use the same key (gen here ==
	// w.current.Generation() at the point of write).
	w.perGenAnyReplayable[gen] = struct{}{}
	// totalBytes accounting: framed already includes the 12-byte seq/gen
	// prefix; the framing layer adds the 8-byte frame header on top.
	w.totalBytes += int64(8 + len(framed))
	w.notifyReaders()
	return AppendResult{GenerationRolled: rolled}, nil
}

func (w *WAL) sealCurrentLocked() error {
	if w.current == nil {
		return nil
	}
	if _, err := w.current.Seal(); err != nil {
		return err
	}
	w.current = nil
	return nil
}

func (w *WAL) openNewSegmentLocked(gen uint32, flags uint16) (*Segment, error) {
	idx := w.nextIndex
	w.nextIndex++
	return OpenSegment(w.segDir, idx, SegmentHeader{Version: SegmentVersion, Flags: flags, Generation: gen}, w.maxRec)
}

// Close seals the live segment (if any) without removing INPROGRESS — instead
// flushes and closes for clean reopen. The next Open will reopen the
// .INPROGRESS file. Also closes the file handles owned by every open Reader so
// the OS releases them promptly; subsequent Reader.Next calls observe the
// closure via the per-reader closed flag and surface an error.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	// Close reader file handles before our own segment to mirror the order
	// callers will see on a normal shutdown. Errors per-reader are swallowed
	// so one stuck handle doesn't block release of the rest; the WAL Close
	// contract surfaces only the live-segment close error.
	for _, r := range w.readers {
		r.closeFromWALLocked()
	}
	w.readers = nil
	if w.current != nil {
		if err := w.current.Close(); err != nil {
			return err
		}
		w.current = nil
	}
	return nil
}

// encodeSeqGenFrame prepends 12 bytes of (seq:int64 BE, gen:uint32 BE) to
// payload so a recovery scan can read seq+gen without parsing the protobuf.
func encodeSeqGenFrame(seq int64, gen uint32, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	for i := 0; i < 8; i++ {
		out[7-i] = byte(seq >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[11-i] = byte(gen >> (8 * i))
	}
	copy(out[12:], payload)
	return out
}

// parseSeqGen decodes the 12-byte (seq:uint64 BE, gen:uint32 BE) prefix
// emitted by encodeSeqGenFrame. The seq is returned as uint64 because the
// high-watermark fields are uint64; encodeSeqGenFrame always stores
// non-negative seq values, so the bit pattern is identical.
func parseSeqGen(framed []byte) (uint64, uint32, bool) {
	if len(framed) < 12 {
		return 0, 0, false
	}
	var seq uint64
	for i := 0; i < 8; i++ {
		seq |= uint64(framed[i]) << (8 * (7 - i))
	}
	var gen uint32
	for i := 0; i < 4; i++ {
		gen |= uint32(framed[8+i]) << (8 * (3 - i))
	}
	return seq, gen, true
}

// LossMarkerSentinel is a fixed byte string embedded in the framed payload of
// a synthetic TransportLoss record. Used by recovery and tests to identify
// loss markers without parsing the protobuf payload (which carries seq=0,
// gen=N for a marker — sentinels avoid ambiguity).
const LossMarkerSentinel = "\x00WTPLOSS\x00"

// LossRecord describes a synthetic TransportLoss inserted into the WAL stream.
type LossRecord struct {
	FromSequence uint64
	ToSequence   uint64
	Generation   uint32
	Reason       string // "overflow" | "crc_corruption"
}

// AppendLoss writes a synthetic TransportLoss record into the WAL stream so
// the transport's reader observes the gap inline. Always fsync'd. Used by the
// overflow path and the CRC-corruption recovery path.
//
// Respects the closed and latched-fatal contracts established in Task 12: a
// closed WAL returns FailureClean ErrClosed; a previously-latched fatal
// returns a clean ErrFatal-wrapped error without attempting I/O. Any I/O
// failure inside the lock is classified as ambiguous via failAmbiguousLocked
// so the WAL latches into the fatal state.
func (w *WAL) AppendLoss(loss LossRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return &AppendError{Class: FailureClean, Op: "append-loss", Err: ErrClosed}
	}
	if w.fatalErr != nil {
		return &AppendError{
			Class: FailureClean,
			Op:    "append-loss",
			Err:   fmt.Errorf("%w: %v", ErrFatal, w.fatalErr),
		}
	}
	if w.current == nil {
		seg, err := w.openNewSegmentLocked(loss.Generation, FlagGenInit)
		if err != nil {
			return w.failAmbiguousLocked("open-loss-segment", err)
		}
		w.current = seg
	}
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return w.failAmbiguousLocked("write-loss", err)
	}
	if err := w.current.Sync(); err != nil {
		return w.failAmbiguousLocked("sync-loss", err)
	}
	w.totalBytes += int64(8 + len(payload))
	// Seed perGenAnyReplayable on the SEGMENT generation (not loss.Generation):
	// the round-16 Finding 2 contract keys this map by the segment header
	// generation since that is the unit the GC pruner reasons about. When
	// w.current already exists, its generation may differ from
	// loss.Generation — the loss marker is still a payload that must be
	// surfaced from the segment's generation on reconnect.
	w.perGenAnyReplayable[w.current.Generation()] = struct{}{}
	w.notifyReaders()
	return nil
}

// encodeLossPayload encodes a LossRecord into the on-disk loss-marker layout:
//
//	offset  size  field
//	0       10    LossMarkerSentinel
//	10      8     FromSequence (uint64 BE)
//	18      8     ToSequence   (uint64 BE)
//	26      4     Generation   (uint32 BE)
//	30      N     Reason       (UTF-8, no terminator)
//
// Total length is 30 + len(reason) bytes. The Reason has no length prefix
// because the framing layer's record length implicitly bounds it.
func encodeLossPayload(l LossRecord) []byte {
	out := make([]byte, 10+8+8+4+len(l.Reason))
	copy(out[0:10], LossMarkerSentinel)
	for i := 0; i < 8; i++ {
		out[17-i] = byte(l.FromSequence >> (8 * i))
	}
	for i := 0; i < 8; i++ {
		out[25-i] = byte(l.ToSequence >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[29-i] = byte(l.Generation >> (8 * i))
	}
	copy(out[30:], l.Reason)
	return out
}

// decodeLossPayload is the inverse of encodeLossPayload. Returns ok=false if
// payload is too short to hold the fixed-size header (sentinel+seq+gen) or if
// the sentinel prefix does not match — in either case the caller MUST treat
// the bytes as a non-loss-marker record.
func decodeLossPayload(payload []byte) (LossRecord, bool) {
	if len(payload) < 30 {
		return LossRecord{}, false
	}
	if string(payload[:len(LossMarkerSentinel)]) != LossMarkerSentinel {
		return LossRecord{}, false
	}
	var loss LossRecord
	for i := 0; i < 8; i++ {
		loss.FromSequence |= uint64(payload[10+i]) << (8 * (7 - i))
	}
	for i := 0; i < 8; i++ {
		loss.ToSequence |= uint64(payload[18+i]) << (8 * (7 - i))
	}
	for i := 0; i < 4; i++ {
		loss.Generation |= uint32(payload[26+i]) << (8 * (3 - i))
	}
	if len(payload) > 30 {
		loss.Reason = string(payload[30:])
	}
	return loss, true
}

// MarkAcked records the highest-acked watermark (gen, seq) in meta.json and
// GCs sealed segments fully covered by it. The live (.INPROGRESS) segment
// is never removed.
//
// The watermark is a (generation, sequence) tuple because seqs restart at 0
// on each generation roll. Monotonicity is across the tuple (lex order):
// the watermark advances iff (gen, seq) is strictly greater than the current
// (ackHighGen, ackHighSeq). A caller passing an older tuple is silently
// ignored (the high-water value already on disk wins).
//
// Returns nil even if no segments were eligible for GC. Callers do not need
// to filter on whether progress was made.
//
// Filename ordering uses the numeric segment index (parseSegmentIndex), not
// lexicographic order on filenames — once an index crosses 10^10 the digit
// count changes and lex order silently picks the wrong "oldest" file. The
// current per-segment scan via segmentHighSeqAndGen is the safety check
// that prevents us from removing a segment whose tail records are still
// unacked.
func (w *WAL) MarkAcked(gen uint32, seq uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Persist the new ack watermark and mirror it on the in-memory WAL so
	// the overflow path's silent-GC pass (gcAckedLocked) can consult it
	// without a meta.json read on every Append. Use lex (gen, seq) compare
	// so MarkAcked is monotonic across generation rolls.
	advance := !w.ackPresent || gen > w.ackHighGen || (gen == w.ackHighGen && seq > w.ackHighSeq)
	if advance {
		w.ackHighGen = gen
		w.ackHighSeq = seq
		w.ackPresent = true
	}
	// Persist identity alongside the ack tuple so a WAL opened with Task-14a
	// identity options carries that identity into meta.json on the very next
	// MarkAcked call. The fields are read-only after first persistence (the
	// identity gate in Open enforces immutability), but writing them here is
	// load-bearing for the migration path: an older directory whose meta.json
	// has empty identity fields adopts the caller's values on the next ack
	// and from that point on the gate locks them in.
	if err := WriteMeta(w.opts.Dir, Meta{
		AckHighWatermarkSeq: w.ackHighSeq,
		AckHighWatermarkGen: w.ackHighGen,
		AckRecorded:         true,
		SessionID:           w.opts.SessionID,
		KeyFingerprint:      w.opts.KeyFingerprint,
		ContextDigest:       w.opts.ContextDigest,
	}); err != nil {
		return err
	}
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return err
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	removed := false
	for _, e := range sealed {
		path := filepath.Join(w.segDir, e.name)
		hi, hasUser, segGen, _, err := segmentHighSeqAndGen(path, w.maxRec)
		if err != nil {
			continue
		}
		if !w.segmentFullyAckedLocked(segGen, hi, hasUser) {
			continue
		}
		st, _ := os.Stat(path)
		if err := os.Remove(path); err == nil {
			if st != nil {
				w.totalBytes -= st.Size()
			}
			removed = true
		}
	}
	if removed {
		if err := syncDir(w.segDir); err != nil {
			return err
		}
		// Drop perGenDataHighWater AND perGenAnyReplayable entries for
		// any generation whose last surviving segment was just GC'd.
		// Without this WrittenDataHighWater would keep returning the
		// pre-GC value for data no longer on disk, and
		// HasReplayableRecords would over-report empty generations to
		// the replay-plan accessor.
		w.prunePerGenMapsLocked()
	}
	return nil
}

// segmentHighSeqAndGen returns the highest user-record sequence number, a
// flag indicating whether the segment held any non-loss-marker records, the
// segment's generation (read from the segment header), and a flag indicating
// whether the segment held ANY payload (RecordData OR loss marker). A scan
// is required because the WAL does not maintain a per-segment index. Used by
// MarkAcked GC and by overflow GC to identify safe-to-drop segments, and by
// the Open seed scan to populate perGenAnyReplayable (round-16 Finding 2).
//
// hasUser reports only RecordData records; hasAnyPayload also includes loss
// markers — the two flags together let the Open scan distinguish a fully
// header-only segment (both false, no replay stage needed) from a
// loss-only segment (hasUser=false, hasAnyPayload=true, replay stage IS
// needed so the receiver observes the gap).
//
// Errors during the read loop (truncation, CRC mismatch, corrupt frames)
// are treated as "stop scanning" so a partially-written segment still
// reports its highest known-good seq rather than failing outright; the
// caller decides whether that's safe to act on. Errors opening the file
// or parsing the header are propagated.
func segmentHighSeqAndGen(path string, maxPayload int) (hiSeq uint64, hasUser bool, gen uint32, hasAnyPayload bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false, 0, false, err
	}
	defer f.Close()
	hdr, err := ReadSegmentHeader(f)
	if err != nil {
		return 0, false, 0, false, err
	}
	gen = hdr.Generation
	for {
		payload, readErr := ReadRecord(f, maxPayload)
		if readErr == io.EOF {
			return hiSeq, hasUser, gen, hasAnyPayload, nil
		}
		if readErr != nil {
			return hiSeq, hasUser, gen, hasAnyPayload, nil
		}
		// Loss markers are sentinel-framed, not seq/gen-framed; feeding
		// their bytes to parseSeqGen would synthesize a junk seq from
		// the LossMarkerSentinel prefix and prevent MarkAcked from ever
		// freeing this segment. Skip them for hiSeq/hasUser — they do
		// not represent a user record and so contribute nothing to the
		// high-watermark — but mark hasAnyPayload (a loss marker IS a
		// replayable payload, the receiver must observe the gap).
		if isLossMarker(payload) {
			hasAnyPayload = true
			continue
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			hasUser = true
			hasAnyPayload = true
			if seq > hiSeq {
				hiSeq = seq
			}
		}
	}
}

// appendLossLocked writes a TransportLoss marker into the live segment and
// fsyncs it. Caller MUST hold w.mu and MUST have ensured w.current != nil.
// Used by the overflow path; AppendLoss is the public entry point that
// handles the closed/fatal/no-segment preconditions.
func (w *WAL) appendLossLocked(loss LossRecord) error {
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return err
	}
	if err := w.current.Sync(); err != nil {
		return err
	}
	w.totalBytes += int64(8 + len(payload))
	// Mirror AppendLoss: a loss marker is a replayable payload, so the
	// segment's generation joins perGenAnyReplayable. This is the overflow
	// path — an in-flight Append rolled segments and emitted a loss marker
	// for the dropped tail; the marker must surface to the receiver on
	// reconnect.
	w.perGenAnyReplayable[w.current.Generation()] = struct{}{}
	w.notifyReaders()
	return nil
}

// notifyReaders signals every open Reader that new records are available. The
// per-reader notify channel is single-buffered, so a non-blocking send drops
// the signal when the channel is full — readers coalesce notifications and
// must drain to io.EOF before waiting again. Caller MUST hold w.mu.
func (w *WAL) notifyReaders() {
	for _, r := range w.readers {
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
}

// dropOldestLocked drops the oldest sealed segment from disk. Returns:
//
//   - loss: the (FromSequence, ToSequence, Generation) range of user records
//     that were in the dropped segment. Zero values are valid when
//     hasUserRange is false (e.g. the segment held only a loss marker, or
//     the file was unreadable past its header).
//   - dropped: true if a file was actually removed; false if no sealed
//     segments existed to drop. The caller MUST consult this flag, NOT
//     loss.ToSequence, to decide whether reclamation made progress —
//     ToSequence==0 is a legitimate range end (a single-record segment at
//     seq=0) and conflating it with "nothing dropped" silently swallows
//     real reclamation work.
//   - hasUserRange: true if loss covers at least one real (non-loss-marker)
//     record, i.e. the caller should emit a TransportLoss marker. False
//     means the dropped segment was empty or held only loss markers — no
//     marker needed; loop and try again on the next sealed file.
//   - err: any I/O error encountered while removing the file.
//
// The live (.INPROGRESS) segment is excluded; we never drop the file we're
// writing to. Sort order is numeric (parsed segment index) so digit-count
// transitions past idx=10^10 don't silently misorder lex-sorted names.
//
// Caller MUST hold w.mu.
func (w *WAL) dropOldestLocked() (loss LossRecord, dropped bool, hasUserRange bool, err error) {
	entries, readErr := os.ReadDir(w.segDir)
	if readErr != nil {
		return LossRecord{}, false, false, readErr
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	if len(sealed) == 0 {
		return LossRecord{}, false, false, nil
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	oldest := sealed[0].name
	path := filepath.Join(w.segDir, oldest)
	f, openErr := os.Open(path)
	if openErr != nil {
		return LossRecord{}, false, false, openErr
	}
	hdr, _ := ReadSegmentHeader(f)
	var fromSeq, toSeq uint64
	first := true
	for {
		payload, readRecErr := ReadRecord(f, w.maxRec)
		if readRecErr == io.EOF || readRecErr != nil {
			break
		}
		// Skip loss markers; they do not represent user records and so
		// must not contribute to the (fromSeq, toSeq) range carried by
		// the new TransportLoss marker emitted for THIS drop. Without
		// this, parseSeqGen would synthesize a junk seq from the
		// LossMarkerSentinel prefix and inject it into the range.
		if isLossMarker(payload) {
			continue
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			if first {
				fromSeq = seq
				first = false
			}
			toSeq = seq
		}
	}
	f.Close()
	st, _ := os.Stat(path)
	if removeErr := os.Remove(path); removeErr != nil {
		return LossRecord{}, false, false, removeErr
	}
	if st != nil {
		w.totalBytes -= st.Size()
	}
	if syncErr := syncDir(w.segDir); syncErr != nil {
		// File is gone but the directory entry may not be durable.
		// Surface as ambiguous via the caller's failAmbiguousLocked.
		return LossRecord{}, true, false, syncErr
	}
	// Drop perGenDataHighWater AND perGenAnyReplayable for hdr.Generation
	// if this was the last segment for that generation. Overflow GC is
	// per-segment so we must re-scan the directory each time; the helper
	// handles the empty-set case cheaply.
	w.prunePerGenMapsLocked()
	// hasUserRange == !first: we observed at least one real record.
	hasUserRange = !first
	return LossRecord{FromSequence: fromSeq, ToSequence: toSeq, Generation: hdr.Generation, Reason: "overflow"}, true, hasUserRange, nil
}

// segmentFullyAckedLocked reports whether the segment described by
// (segGen, segHi, hasUser) is fully covered by the in-memory ack watermark.
// Caller MUST hold w.mu.
//
// Without an ack on record (ackPresent=false), nothing is reclaimable —
// even a segment whose only record is seq=0 must NOT be silently dropped.
// Loss-marker-only segments (hasUser=false) are reclaimable iff their
// generation is at-or-below the ack-watermark generation; their on-disk
// data is purely a re-derived gap notice and the receiver gains nothing
// from receiving it twice.
//
// For real user records, comparison is lex on (gen, seq). Seqs restart at 0
// on every generation roll, so a per-seq compare alone would silently let
// a watermark from gen=N reclaim later gen=N+1 records whose local seqs
// happen to fall in the same range.
func (w *WAL) segmentFullyAckedLocked(segGen uint32, segHi uint64, hasUser bool) bool {
	if !w.ackPresent {
		return false
	}
	if !hasUser {
		return segGen <= w.ackHighGen
	}
	if segGen < w.ackHighGen {
		return true
	}
	if segGen == w.ackHighGen && segHi <= w.ackHighSeq {
		return true
	}
	return false
}

// prunePerGenMapsLocked drops perGenDataHighWater AND perGenAnyReplayable
// entries for any generation that no longer has a surviving segment on disk.
// Invoked by every GC path (MarkAcked, gcAckedLocked, dropOldestLocked) after
// at least one segment was removed — without this the maps would leak stale
// entries for fully-GC'd generations:
//   - WrittenDataHighWater(oldGen) would keep returning a value for data
//     that no longer exists on disk.
//   - HasReplayableRecords(oldGen) would keep reporting true for a
//     generation that has no remaining segments, causing the round-16
//     transport replay-plan accessor to schedule an empty stage.
//
// Both maps share the same surviving-generation set, so they are pruned
// together to keep the GC contract atomic and the cost amortised. Rather
// than track the GC'd file set across every removal path, we take the
// simpler tack of reading the post-GC directory listing once and computing
// the set of surviving generations via segment header reads. The O(segments)
// cost amortises well against GC passes that typically remove several
// segments at a time, and avoids the invariant-fragile approach of threading
// per-GC-path bookkeeping through three call sites. Caller MUST hold w.mu.
func (w *WAL) prunePerGenMapsLocked() {
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		// Directory-read failure here is not fatal: the map entries are a
		// positive cache, and a stale entry is only user-visible if a
		// subsequent Open cannot re-seed it — which will not happen,
		// because Open's scan path consults the same directory. Skip
		// pruning and let the next GC retry.
		return
	}
	surviving := make(map[uint32]struct{})
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) && !strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		if _, ok := parseSegmentIndex(name); !ok {
			continue
		}
		path := filepath.Join(w.segDir, name)
		// Use ReadSegmentHeader rather than segmentHighSeqAndGen here —
		// we only need the generation, and a full scan per GC pass would
		// turn pruning into an O(n) disk walk per generation.
		f, openErr := os.Open(path)
		if openErr != nil {
			continue
		}
		hdr, hdrErr := ReadSegmentHeader(f)
		_ = f.Close()
		if hdrErr != nil {
			continue
		}
		surviving[hdr.Generation] = struct{}{}
	}
	for gen := range w.perGenDataHighWater {
		if _, stillOnDisk := surviving[gen]; !stillOnDisk {
			delete(w.perGenDataHighWater, gen)
		}
	}
	for gen := range w.perGenAnyReplayable {
		if _, stillOnDisk := surviving[gen]; !stillOnDisk {
			delete(w.perGenAnyReplayable, gen)
		}
	}
}

// gcAckedLocked removes every sealed segment fully covered by the (gen, seq)
// ack watermark. No TransportLoss marker is emitted for these drops because
// the receiver already has the data. Bails immediately if no ack has been
// recorded (ackPresent=false): a fresh WAL must NOT silently reclaim its
// seq=0 segment merely because the zero-value ackHighSeq matches.
//
// Stops at the first segment that is not fully acked. Segment indices are
// numerically monotonic, and within a single index range generations are
// also monotonic (a generation roll opens a new segment with a higher
// index). So once a segment is not fully acked under lex (gen, seq) order,
// no later sealed segment can be either — early break is safe.
//
// Returns the number of segments removed. Errors during a single segment's
// scan or removal are surfaced to the caller; ack-driven GC is best-effort
// and any I/O failure inside the lock should latch the WAL via
// failAmbiguousLocked at the call site.
//
// Caller MUST hold w.mu.
func (w *WAL) gcAckedLocked() (int, error) {
	if !w.ackPresent {
		return 0, nil
	}
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return 0, err
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	if len(sealed) == 0 {
		return 0, nil
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	removed := 0
	for _, e := range sealed {
		path := filepath.Join(w.segDir, e.name)
		hi, hasUser, segGen, _, scanErr := segmentHighSeqAndGen(path, w.maxRec)
		if scanErr != nil {
			// segmentHighSeqAndGen surfaces only open/header errors;
			// scan-loop errors are swallowed. Treat as fatal here:
			// we cannot decide safely whether to drop this file.
			return removed, scanErr
		}
		if !w.segmentFullyAckedLocked(segGen, hi, hasUser) {
			break
		}
		st, _ := os.Stat(path)
		if rmErr := os.Remove(path); rmErr != nil {
			return removed, rmErr
		}
		if st != nil {
			w.totalBytes -= st.Size()
		}
		removed++
	}
	if removed > 0 {
		if err := syncDir(w.segDir); err != nil {
			return removed, err
		}
		// Drop perGenDataHighWater AND perGenAnyReplayable entries for
		// generations whose last segment was just reclaimed by
		// ack-driven GC.
		w.prunePerGenMapsLocked()
	}
	return removed, nil
}
