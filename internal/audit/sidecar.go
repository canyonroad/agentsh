package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrSidecarNotFound indicates that no persisted integrity state exists yet.
var ErrSidecarNotFound = errors.New("integrity sidecar not found")

// SidecarState stores the last durable audit chain state alongside the log.
type SidecarState struct {
	FormatVersion  int       `json:"format_version"`
	Sequence       int64     `json:"sequence"`
	PrevHash       string    `json:"prev_hash"`
	KeyFingerprint string    `json:"key_fingerprint"`
	UpdatedAt      time.Time `json:"updated_at"`
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

	var state SidecarState
	if err := json.Unmarshal(data, &state); err != nil {
		return SidecarState{}, fmt.Errorf("parse sidecar: %w", err)
	}

	switch {
	case state.FormatVersion <= 0:
		return SidecarState{}, errors.New("parse sidecar: missing or invalid format_version")
	case state.FormatVersion > IntegrityFormatVersion:
		return SidecarState{}, fmt.Errorf("parse sidecar: unsupported format_version %d", state.FormatVersion)
	case state.KeyFingerprint == "":
		return SidecarState{}, errors.New("parse sidecar: missing key_fingerprint")
	case state.Sequence < -1:
		return SidecarState{}, errors.New("parse sidecar: invalid sequence")
	case state.Sequence < 0 && state.PrevHash != "":
		return SidecarState{}, errors.New("parse sidecar: negative sequence with non-empty prev_hash")
	case state.Sequence > 0 && state.PrevHash == "":
		return SidecarState{}, errors.New("parse sidecar: positive sequence with empty prev_hash")
	}

	return state, nil
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
