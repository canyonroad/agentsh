package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

var _ EventStore = (*IntegrityStore)(nil)

// IntegrityOptions configures disk-backed integrity chain management.
type IntegrityOptions struct {
	LogPath        string
	Algorithm      string
	KeyFingerprint string
	Now            func() time.Time
}

// FatalIntegrityError indicates that the signed log append succeeded but the
// sidecar state could not be persisted, leaving the chain in a fatal state.
type FatalIntegrityError struct {
	Op  string
	Err error
}

func (e *FatalIntegrityError) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *FatalIntegrityError) Unwrap() error { return e.Err }

// ErrIntegrityFatal is returned by AppendEvent after a prior fatal integrity
// error has been latched. Once set, no further writes are allowed.
var ErrIntegrityFatal = errors.New("integrity store is in fatal state; no further writes allowed")

// IntegrityStore wraps an EventStore and adds integrity metadata to events.
type IntegrityStore struct {
	mu             sync.Mutex
	inner          EventStore
	chain          *audit.IntegrityChain
	logPath        string
	sidecarPath    string
	algorithm      string
	keyFingerprint string
	now            func() time.Time
	fatal          bool // sticky; set on first FatalIntegrityError
	pendingFlush   bool
	flushTick      *time.Ticker
	stopFlush      chan struct{}
	flushDone      chan struct{}
	closeOnce      sync.Once
}

type visibleChainState struct {
	expectedSequence int64
	expectedPrevHash string
	seeded           bool
	verifiedEntries  int
}

type rotationBoundaryPayload struct {
	Fields struct {
		PriorLogArchivedTo string `json:"prior_log_archived_to"`
		PriorChainSummary  *struct {
			LastSequence  int64  `json:"last_sequence_seen_in_log"`
			LastEntryHash string `json:"last_entry_hash_seen_in_log"`
		} `json:"prior_chain_summary"`
	} `json:"fields"`
}

// NewIntegrityStore wraps an existing store with integrity chain persistence.
func NewIntegrityStore(inner EventStore, chain *audit.IntegrityChain, opts IntegrityOptions) (*IntegrityStore, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Algorithm == "" {
		opts.Algorithm = "hmac-sha256"
	}
	if opts.KeyFingerprint == "" && chain != nil {
		opts.KeyFingerprint = chain.KeyFingerprint()
	}

	store := &IntegrityStore{
		inner:          inner,
		chain:          chain,
		logPath:        opts.LogPath,
		sidecarPath:    audit.SidecarPath(opts.LogPath),
		algorithm:      opts.Algorithm,
		keyFingerprint: opts.KeyFingerprint,
		now:            opts.Now,
	}
	if err := store.bootstrap(); err != nil {
		return nil, err
	}

	// Disable per-write sync on inner store — FlushSync handles it.
	type syncController interface{ SetSyncOnWrite(bool) }
	if sc, ok := inner.(syncController); ok {
		sc.SetSyncOnWrite(false)
	}

	store.stopFlush = make(chan struct{})
	store.flushDone = make(chan struct{})
	store.flushTick = time.NewTicker(100 * time.Millisecond)
	go store.runFlushLoop()

	return store, nil
}

func (s *IntegrityStore) bootstrap() error {
	files, err := audit.DiscoverRotationSet(s.logPath)
	if err != nil {
		return err
	}

	sidecar, sidecarErr := audit.ReadSidecar(s.sidecarPath)
	lastFile, lastLine, lastErr := audit.ReadLastNonEmptyLine(files)

	switch {
	case sidecarErr == nil:
		if sidecar.KeyFingerprint != s.keyFingerprint {
			return fmt.Errorf("audit integrity chain: key fingerprint mismatch")
		}
		if err := s.validateVisibleChain(files); err != nil {
			return err
		}
		return s.resumeFromSidecar(sidecar, lastFile, lastLine, lastErr)
	case errors.Is(sidecarErr, audit.ErrSidecarNotFound):
		return s.bootstrapWithoutSidecar(files, lastFile, lastLine, lastErr, "sidecar_missing", "sidecar missing; starting fresh chain")
	case errors.Is(sidecarErr, audit.ErrSidecarCorrupt):
		if errors.Is(lastErr, os.ErrNotExist) {
			return fmt.Errorf("audit integrity chain mismatch: sidecar corrupt with no visible audit log")
		}
		return s.bootstrapWithoutSidecar(files, lastFile, lastLine, lastErr, "sidecar_corrupt", "sidecar corrupt; starting fresh chain")
	default:
		return fmt.Errorf("read audit integrity sidecar: %w", sidecarErr)
	}
}

func (s *IntegrityStore) validateVisibleChain(files []audit.LogFile) error {
	state := visibleChainState{}

	for _, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("open %s: %w", file.Path, err)
		}

		lineNo := 0
		reader := bufio.NewReader(f)
		for {
			rawLine, readErr := reader.ReadBytes('\n')
			if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = f.Close()
				return fmt.Errorf("scan %s: %w", file.Path, readErr)
			}

			lineNo++
			line := bytes.TrimSpace(rawLine)
			if len(line) == 0 {
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}

			entry, err := audit.ParseIntegrityEntry(line)
			if err != nil || entry.Integrity == nil {
				// A parse error on the last line of the active file (readErr == io.EOF,
				// meaning no trailing newline) indicates a truncated write from a prior
				// crash. Skip it here; recoverFromSidecarGap will truncate the file.
				if errors.Is(readErr, io.EOF) && !file.IsBackup {
					break
				}
				if err != nil {
					_ = f.Close()
					return fmt.Errorf("audit log corrupted at %s:%d: %w", file.Path, lineNo, err)
				}
				_ = f.Close()
				return fmt.Errorf("unsigned line at %s:%d", file.Path, lineNo)
			}
			if entry.Integrity.FormatVersion < audit.IntegrityFormatVersion {
				_ = f.Close()
				return fmt.Errorf("legacy audit log detected in %s", file.Path)
			}
			if entry.Integrity.FormatVersion > audit.IntegrityFormatVersion {
				_ = f.Close()
				return fmt.Errorf("unsupported audit integrity format_version %d in %s", entry.Integrity.FormatVersion, file.Path)
			}

			rotationBoundary := entry.Type == "integrity_chain_rotated" &&
				entry.Integrity.Sequence == 0 &&
				entry.Integrity.PrevHash == ""

			if rotationBoundary {
				if err := validateRotationBoundary(entry.CanonicalPayload, state, file.IsBackup); err != nil {
					_ = f.Close()
					return fmt.Errorf("rotation boundary at %s:%d: %w", file.Path, lineNo, err)
				}
			} else {
				if !state.seeded {
					if file.IsBackup && state.verifiedEntries == 0 {
						state.expectedSequence = entry.Integrity.Sequence
						state.expectedPrevHash = entry.Integrity.PrevHash
					} else {
						state.expectedSequence = 0
						state.expectedPrevHash = ""
					}
					state.seeded = true
				}
				if entry.Integrity.Sequence != state.expectedSequence {
					_ = f.Close()
					return fmt.Errorf("audit integrity chain mismatch: sequence mismatch at %s:%d: expected %d, got %d", file.Path, lineNo, state.expectedSequence, entry.Integrity.Sequence)
				}
				if entry.Integrity.PrevHash != state.expectedPrevHash {
					_ = f.Close()
					return fmt.Errorf("audit integrity chain mismatch: chain broken at %s:%d: expected prev_hash %q, got %q", file.Path, lineNo, state.expectedPrevHash, entry.Integrity.PrevHash)
				}
			}

			ok, err := s.chain.VerifyHash(
				entry.Integrity.FormatVersion,
				entry.Integrity.Sequence,
				entry.Integrity.PrevHash,
				entry.CanonicalPayload,
				entry.Integrity.EntryHash,
			)
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("audit integrity chain mismatch: verify entry at %s:%d: %w", file.Path, lineNo, err)
			}
			if !ok {
				_ = f.Close()
				return fmt.Errorf("audit integrity chain mismatch: invalid entry at %s:%d", file.Path, lineNo)
			}

			state.expectedSequence = entry.Integrity.Sequence + 1
			state.expectedPrevHash = entry.Integrity.EntryHash
			state.seeded = true
			state.verifiedEntries++
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		_ = f.Close()
	}

	return nil
}

func validateRotationBoundary(payload []byte, state visibleChainState, visibleOriginIsBackup bool) error {
	var event rotationBoundaryPayload
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("parse rotation payload: %w", err)
	}

	if state.verifiedEntries == 0 {
		if !visibleOriginIsBackup &&
			event.Fields.PriorChainSummary != nil &&
			event.Fields.PriorLogArchivedTo == "" {
			return errors.New("visible origin omits prior history before rotation boundary")
		}
		return nil
	}
	if event.Fields.PriorChainSummary == nil {
		return fmt.Errorf("missing prior_chain_summary")
	}

	wantSequence := state.expectedSequence - 1
	if got := event.Fields.PriorChainSummary.LastSequence; got != wantSequence {
		return fmt.Errorf("prior_chain_summary.last_sequence_seen_in_log = %d, want %d", got, wantSequence)
	}
	if got := event.Fields.PriorChainSummary.LastEntryHash; got != state.expectedPrevHash {
		return fmt.Errorf("prior_chain_summary.last_entry_hash_seen_in_log = %q, want %q", got, state.expectedPrevHash)
	}
	return nil
}

func (s *IntegrityStore) resumeFromSidecar(sidecar audit.SidecarState, lastFile audit.LogFile, lastLine []byte, lastErr error) error {
	if lastErr != nil {
		return fmt.Errorf("audit integrity chain mismatch: %w", lastErr)
	}

	entry, err := audit.ParseIntegrityEntry(lastLine)
	if err != nil || entry.Integrity == nil {
		// Malformed last entry: could be a truncated partial write from a crash.
		// Attempt gap recovery, which will truncate the file and recover valid entries.
		advanced, recoverErr := s.recoverFromSidecarGap(sidecar, lastFile)
		if recoverErr != nil {
			return recoverErr
		}
		if advanced {
			return nil
		}
		return fmt.Errorf("audit integrity chain mismatch: malformed last entry in %s", lastFile.Path)
	}

	// Case 1: sidecar exactly matches last entry — normal resume.
	if sidecar.Sequence == entry.Integrity.Sequence && sidecar.PrevHash == entry.Integrity.EntryHash {
		ok, err := s.chain.VerifyHash(
			entry.Integrity.FormatVersion,
			entry.Integrity.Sequence,
			entry.Integrity.PrevHash,
			entry.CanonicalPayload,
			entry.Integrity.EntryHash,
		)
		if err != nil {
			return fmt.Errorf("audit integrity chain mismatch: verify last entry: %w", err)
		}
		if !ok {
			return fmt.Errorf("audit integrity chain mismatch: invalid last entry in %s", lastFile.Path)
		}
		if err := s.chain.Restore(sidecar.Sequence, sidecar.PrevHash); err != nil {
			return fmt.Errorf("restore integrity chain: %w", err)
		}
		return nil
	}

	// Case 2: sidecar is behind — crash recovery (seq+N from deferred sync).
	if sidecar.Sequence < entry.Integrity.Sequence {
		advanced, err := s.recoverFromSidecarGap(sidecar, lastFile)
		if err != nil {
			return err
		}
		if advanced {
			return nil
		}
	}

	return fmt.Errorf("audit integrity chain mismatch: sidecar does not match %s", lastFile.Path)
}

// recoverFromSidecarGap walks the audit log from the sidecar position forward,
// verifying each entry forms a valid chain continuation. On success, advances
// the sidecar to the last verified entry. Also handles truncated last lines
// from crash-during-Write by truncating the file back to the last complete line.
func (s *IntegrityStore) recoverFromSidecarGap(sidecar audit.SidecarState, lastFile audit.LogFile) (bool, error) {
	f, err := os.Open(lastFile.Path)
	if err != nil {
		return false, fmt.Errorf("open %s for recovery: %w", lastFile.Path, err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var lastVerified *audit.ParsedEntry
	var lastGoodOffset int64
	var currentOffset int64
	expectedSeq := sidecar.Sequence + 1
	expectedPrev := sidecar.PrevHash

	for {
		rawLine, readErr := reader.ReadBytes('\n')
		lineLen := int64(len(rawLine))

		if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return false, fmt.Errorf("read %s for recovery: %w", lastFile.Path, readErr)
		}

		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			currentOffset += lineLen
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		entry, parseErr := audit.ParseIntegrityEntry(line)
		if parseErr != nil || entry.Integrity == nil {
			// Truncated last line from crash-during-Write. This is safe to
			// truncate because validateVisibleChain (which runs before this)
			// already verified all complete lines; only a trailing partial
			// line without a newline can reach here.
			if err := truncateFile(lastFile.Path, lastGoodOffset); err != nil {
				slog.Warn("failed to truncate partial line during recovery",
					"path", lastFile.Path, "error", err)
			}
			break
		}

		currentOffset += lineLen

		// Skip entries at or before the sidecar position
		if entry.Integrity.Sequence <= sidecar.Sequence {
			lastGoodOffset = currentOffset
			continue
		}

		// Verify chain link
		if entry.Integrity.Sequence != expectedSeq || entry.Integrity.PrevHash != expectedPrev {
			return false, fmt.Errorf("audit integrity chain mismatch: chain broken during recovery at seq %d", entry.Integrity.Sequence)
		}

		ok, err := s.chain.VerifyHash(
			entry.Integrity.FormatVersion,
			entry.Integrity.Sequence,
			entry.Integrity.PrevHash,
			entry.CanonicalPayload,
			entry.Integrity.EntryHash,
		)
		if err != nil {
			return false, fmt.Errorf("audit integrity chain mismatch: verify entry seq %d: %w", entry.Integrity.Sequence, err)
		}
		if !ok {
			return false, fmt.Errorf("audit integrity chain mismatch: invalid HMAC at seq %d", entry.Integrity.Sequence)
		}

		expectedSeq = entry.Integrity.Sequence + 1
		expectedPrev = entry.Integrity.EntryHash
		lastVerified = &entry
		lastGoodOffset = currentOffset

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if lastVerified == nil {
		return false, nil
	}

	if err := s.chain.Restore(lastVerified.Integrity.Sequence, lastVerified.Integrity.EntryHash); err != nil {
		return false, fmt.Errorf("restore integrity chain: %w", err)
	}
	slog.Warn("audit integrity: sidecar behind, advancing after crash recovery",
		"sidecar_seq", sidecar.Sequence,
		"log_seq", lastVerified.Integrity.Sequence,
		"events_recovered", lastVerified.Integrity.Sequence-sidecar.Sequence,
	)
	return true, audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
		Sequence:       lastVerified.Integrity.Sequence,
		PrevHash:       lastVerified.Integrity.EntryHash,
		KeyFingerprint: s.keyFingerprint,
		UpdatedAt:      s.now().UTC(),
	})
}

// truncateFile truncates a file to the given size (removing a partial trailing line).
func truncateFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

func (s *IntegrityStore) bootstrapWithoutSidecar(files []audit.LogFile, lastFile audit.LogFile, lastLine []byte, lastErr error, reasonCode, reason string) error {
	if errors.Is(lastErr, os.ErrNotExist) {
		return s.appendRotationBoundary("initial", "initial chain creation", nil)
	}
	if lastErr != nil {
		return lastErr
	}

	entry, err := audit.ParseIntegrityEntry(lastLine)
	if err != nil {
		return fmt.Errorf("audit log corrupted at last line: %w", err)
	}
	if entry.Integrity == nil || entry.Integrity.FormatVersion < audit.IntegrityFormatVersion {
		return fmt.Errorf("legacy audit log detected in %s", lastFile.Path)
	}
	if entry.Integrity.FormatVersion > audit.IntegrityFormatVersion {
		return fmt.Errorf("unsupported audit integrity format_version %d in %s", entry.Integrity.FormatVersion, lastFile.Path)
	}

	// If the last entry is already a rotation boundary we wrote (verifiable
	// with our key, at sequence 0), the previous bootstrap attempt wrote the
	// log entry but failed to persist the sidecar. Validate the visible chain
	// first, then resume from it instead of appending a duplicate.
	if entry.Type == "integrity_chain_rotated" && entry.Integrity.Sequence == 0 {
		ok, verifyErr := s.chain.VerifyHash(
			entry.Integrity.FormatVersion,
			entry.Integrity.Sequence,
			entry.Integrity.PrevHash,
			entry.CanonicalPayload,
			entry.Integrity.EntryHash,
		)
		if verifyErr == nil && ok {
			if err := s.validateVisibleChain(files); err != nil {
				return err
			}
			if err := s.chain.Restore(entry.Integrity.Sequence, entry.Integrity.EntryHash); err != nil {
				return fmt.Errorf("restore integrity chain: %w", err)
			}
			return audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
				Sequence:       entry.Integrity.Sequence,
				PrevHash:       entry.Integrity.EntryHash,
				KeyFingerprint: s.keyFingerprint,
				UpdatedAt:      s.now().UTC(),
			})
		}
	}

	ok, err := s.chain.VerifyHash(
		entry.Integrity.FormatVersion,
		entry.Integrity.Sequence,
		entry.Integrity.PrevHash,
		entry.CanonicalPayload,
		entry.Integrity.EntryHash,
	)
	if err != nil {
		return fmt.Errorf("audit integrity chain mismatch: verify last entry: %w", err)
	}
	if !ok {
		return fmt.Errorf("audit integrity chain mismatch: invalid last entry in %s", lastFile.Path)
	}
	if err := s.validateVisibleChain(files); err != nil {
		return err
	}

	return s.appendRotationBoundary(reasonCode, reason, map[string]any{
		"last_sequence_seen_in_log":   entry.Integrity.Sequence,
		"last_entry_hash_seen_in_log": entry.Integrity.EntryHash,
	})
}

func (s *IntegrityStore) appendRotationBoundary(reasonCode, reason string, priorSummary map[string]any) error {
	rw, ok := s.inner.(RawWriter)
	if !ok {
		return fmt.Errorf("integrity store requires RawWriter for rotation boundary events")
	}

	ev := types.Event{
		Type:      "integrity_chain_rotated",
		Timestamp: s.now().UTC(),
		Fields: map[string]any{
			"reason":              reason,
			"reason_code":         reasonCode,
			"prior_chain_summary": priorSummary,
			"new_chain": map[string]any{
				"format_version":  audit.IntegrityFormatVersion,
				"sequence":        0,
				"key_fingerprint": s.keyFingerprint,
			},
		},
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("integrity marshal rotation boundary: %w", err)
	}
	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		return fmt.Errorf("integrity wrap rotation boundary: %w", err)
	}
	if err := rw.WriteRaw(context.Background(), wrapped); err != nil {
		return err
	}

	state := s.chain.State()
	return audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: s.keyFingerprint,
		UpdatedAt:      s.now().UTC(),
	})
}

// AppendEvent marshals the event, wraps it with HMAC integrity metadata,
// and writes the signed bytes via RawWriter if the inner store supports it.
// Falls back to unsigned inner.AppendEvent otherwise.
func (s *IntegrityStore) AppendEvent(ctx context.Context, ev types.Event) error {
	rw, ok := s.inner.(RawWriter)
	if !ok {
		return s.inner.AppendEvent(ctx, ev)
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("integrity marshal: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fatal {
		return ErrIntegrityFatal
	}

	prevState := s.chain.State()
	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		return fmt.Errorf("integrity wrap: %w", err)
	}
	if err := rw.WriteRaw(ctx, wrapped); err != nil {
		type partialWriter interface{ IsPartialWrite() bool }
		if pw, ok := err.(partialWriter); ok && pw.IsPartialWrite() {
			// Data may be partially on disk — chain state is now ambiguous.
			s.fatal = true
			return &FatalIntegrityError{Op: "write audit log", Err: err}
		}
		// Clean failure: no bytes hit disk, safe to roll back chain state.
		if restoreErr := s.chain.Restore(prevState.Sequence, prevState.PrevHash); restoreErr != nil {
			return fmt.Errorf("restore integrity chain after write failure: %w", restoreErr)
		}
		return err
	}

	s.pendingFlush = true
	return nil
}

// FlushSync flushes buffered writes to durable storage and updates the sidecar.
// Safe to call concurrently with AppendEvent — the chain mutex is held only
// briefly to snapshot state, then released before slow I/O.
func (s *IntegrityStore) FlushSync() error {
	s.mu.Lock()
	if !s.pendingFlush || s.fatal {
		s.mu.Unlock()
		return nil
	}
	state := s.chain.State()
	s.pendingFlush = false
	s.mu.Unlock()

	if syncer, ok := s.inner.(Syncer); ok {
		if err := syncer.Sync(); err != nil {
			s.mu.Lock()
			s.fatal = true
			s.mu.Unlock()
			return &FatalIntegrityError{Op: "sync audit log", Err: err}
		}
	}

	if err := audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: s.keyFingerprint,
		UpdatedAt:      s.now().UTC(),
	}); err != nil {
		s.mu.Lock()
		s.fatal = true
		s.mu.Unlock()
		return &FatalIntegrityError{Op: "write audit integrity sidecar", Err: err}
	}
	return nil
}

func (s *IntegrityStore) runFlushLoop() {
	defer close(s.flushDone)
	for {
		select {
		case <-s.flushTick.C:
			if err := s.FlushSync(); err != nil {
				slog.Error("audit flush failed", "error", err)
			}
		case <-s.stopFlush:
			s.flushTick.Stop()
			return
		}
	}
}

// QueryEvents delegates to the inner store.
func (s *IntegrityStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return s.inner.QueryEvents(ctx, q)
}

// Close stops the flush loop, performs a final flush, and closes the inner store.
// Safe to call multiple times.
func (s *IntegrityStore) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if s.stopFlush != nil {
			close(s.stopFlush)
			<-s.flushDone
		}
		if err := s.FlushSync(); err != nil {
			slog.Error("final audit flush failed", "error", err)
		}
		closeErr = s.inner.Close()
	})
	return closeErr
}

// Chain returns the integrity chain for state management.
func (s *IntegrityStore) Chain() *audit.IntegrityChain {
	return s.chain
}
