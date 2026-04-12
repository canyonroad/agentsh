package audit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrSidecarNotFound indicates that no persisted integrity state exists yet.
var ErrSidecarNotFound = errors.New("integrity sidecar not found")

// ErrSidecarCorrupt indicates that the persisted sidecar exists but is malformed.
var ErrSidecarCorrupt = errors.New("integrity sidecar corrupt")

// SidecarState stores the last durable audit chain state alongside the log.
type SidecarState struct {
	FormatVersion  int       `json:"format_version"`
	Sequence       int64     `json:"sequence"`
	PrevHash       string    `json:"prev_hash"`
	KeyFingerprint string    `json:"key_fingerprint"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type sidecarStateDisk struct {
	FormatVersion  *int       `json:"format_version"`
	Sequence       *int64     `json:"sequence"`
	PrevHash       *string    `json:"prev_hash"`
	KeyFingerprint *string    `json:"key_fingerprint"`
	UpdatedAt      *time.Time `json:"updated_at"`
}

// SidecarPath returns the integrity sidecar path for an audit log.
func SidecarPath(logPath string) string {
	return logPath + ".chain"
}

// ReadSidecar loads and validates persisted integrity state.
func ReadSidecar(path string) (SidecarState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SidecarState{}, ErrSidecarNotFound
	}
	if err != nil {
		return SidecarState{}, fmt.Errorf("read sidecar: %w", err)
	}

	var disk sidecarStateDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return SidecarState{}, wrapSidecarCorrupt(fmt.Errorf("parse sidecar: %w", err))
	}
	switch {
	case disk.FormatVersion == nil || *disk.FormatVersion <= 0:
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: missing or invalid format_version"))
	case disk.Sequence == nil:
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: missing sequence"))
	case disk.PrevHash == nil:
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: missing prev_hash"))
	case disk.KeyFingerprint == nil || *disk.KeyFingerprint == "":
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: missing key_fingerprint"))
	}

	state := SidecarState{
		FormatVersion:  *disk.FormatVersion,
		Sequence:       *disk.Sequence,
		PrevHash:       *disk.PrevHash,
		KeyFingerprint: *disk.KeyFingerprint,
	}
	if disk.UpdatedAt != nil {
		state.UpdatedAt = *disk.UpdatedAt
	}

	switch {
	case state.FormatVersion > IntegrityFormatVersion:
		return SidecarState{}, wrapSidecarCorrupt(fmt.Errorf("parse sidecar: unsupported format_version %d", state.FormatVersion))
	case state.Sequence < -1:
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: invalid sequence"))
	case state.Sequence < 0 && state.PrevHash != "":
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: negative sequence with non-empty prev_hash"))
	case state.Sequence >= 0 && state.PrevHash == "":
		return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: persisted sequence requires non-empty prev_hash"))
	case state.PrevHash != "":
		if _, err := hex.DecodeString(state.PrevHash); err != nil {
			return SidecarState{}, wrapSidecarCorrupt(errors.New("parse sidecar: invalid prev_hash"))
		}
	}

	return state, nil
}

func wrapSidecarCorrupt(err error) error {
	return fmt.Errorf("%w: %v", ErrSidecarCorrupt, err)
}

// WriteSidecar atomically persists integrity state next to the audit log.
func WriteSidecar(path string, state SidecarState) error {
	state.FormatVersion = IntegrityFormatVersion
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal sidecar: %w", err)
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("open temp sidecar: %w", err)
	}

	tmpPath := tmpFile.Name()
	cleanupTemp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmpFile.Write(append(data, '\n')); err != nil {
		cleanupTemp()
		return fmt.Errorf("write temp sidecar: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanupTemp()
		return fmt.Errorf("sync temp sidecar: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp sidecar: %w", err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename sidecar: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync sidecar dir: %w", err)
	}
	return nil
}
