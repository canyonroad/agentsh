package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return s.bootstrapWithoutSidecar(files, lastFile, lastLine, lastErr)
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
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("audit log corrupted at %s:%d: %w", file.Path, lineNo, err)
			}
			if entry.Integrity == nil {
				_ = f.Close()
				return fmt.Errorf("unsigned line at %s:%d", file.Path, lineNo)
			}
			if entry.Integrity.FormatVersion < audit.IntegrityFormatVersion {
				_ = f.Close()
				return fmt.Errorf("legacy audit log detected in %s", file.Path)
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
		return fmt.Errorf("audit integrity chain mismatch: malformed last entry in %s", lastFile.Path)
	}

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
		s.chain.Restore(sidecar.Sequence, sidecar.PrevHash)
		return nil
	}

	if sidecar.Sequence+1 == entry.Integrity.Sequence &&
		entry.Integrity.PrevHash == sidecar.PrevHash {
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
		if ok {
			s.chain.Restore(entry.Integrity.Sequence, entry.Integrity.EntryHash)
			return audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
				Sequence:       entry.Integrity.Sequence,
				PrevHash:       entry.Integrity.EntryHash,
				KeyFingerprint: s.keyFingerprint,
				UpdatedAt:      s.now().UTC(),
			})
		}
	}

	return fmt.Errorf("audit integrity chain mismatch: sidecar does not match %s", lastFile.Path)
}

func (s *IntegrityStore) bootstrapWithoutSidecar(files []audit.LogFile, lastFile audit.LogFile, lastLine []byte, lastErr error) error {
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

	return s.appendRotationBoundary("sidecar_missing", "sidecar missing; starting fresh chain", map[string]any{
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

	prevState := s.chain.State()
	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		return fmt.Errorf("integrity wrap: %w", err)
	}
	if err := rw.WriteRaw(ctx, wrapped); err != nil {
		type partialWriter interface{ IsPartialWrite() bool }
		if pw, ok := err.(partialWriter); !ok || !pw.IsPartialWrite() {
			s.chain.Restore(prevState.Sequence, prevState.PrevHash)
		}
		return err
	}

	state := s.chain.State()
	if err := audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: s.keyFingerprint,
		UpdatedAt:      s.now().UTC(),
	}); err != nil {
		return &FatalIntegrityError{Op: "write audit integrity sidecar", Err: err}
	}
	return nil
}

// QueryEvents delegates to the inner store.
func (s *IntegrityStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return s.inner.QueryEvents(ctx, q)
}

// Close closes the inner store.
func (s *IntegrityStore) Close() error {
	return s.inner.Close()
}

// Chain returns the integrity chain for state management.
func (s *IntegrityStore) Chain() *audit.IntegrityChain {
	return s.chain
}
