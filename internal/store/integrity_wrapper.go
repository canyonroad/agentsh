package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		return s.resumeFromSidecar(sidecar, lastFile, lastLine, lastErr)
	case errors.Is(sidecarErr, audit.ErrSidecarNotFound):
		return s.bootstrapWithoutSidecar(lastFile, lastLine, lastErr)
	default:
		return s.bootstrapWithoutSidecar(lastFile, lastLine, lastErr)
	}
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

func (s *IntegrityStore) bootstrapWithoutSidecar(lastFile audit.LogFile, lastLine []byte, lastErr error) error {
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
