package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Meta is the persistent state for a WAL directory. Spec §"meta.json schema".
type Meta struct {
	FormatVersion       int    `json:"format_version"`
	AckHighWatermarkSeq uint64 `json:"ack_high_watermark_seq"`
	AckHighWatermarkGen uint32 `json:"ack_high_watermark_gen"`
	SessionID           string `json:"session_id"`
	KeyFingerprint      string `json:"key_fingerprint"`
}

const metaFormatVersion = 1
const metaFileName = "meta.json"

// ReadMeta loads meta.json from dir. Returns os.ErrNotExist if absent.
func ReadMeta(dir string) (Meta, error) {
	p := filepath.Join(dir, metaFileName)
	data, err := os.ReadFile(p)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("parse meta.json: %w", err)
	}
	if m.FormatVersion != metaFormatVersion {
		return Meta{}, fmt.Errorf("meta.json format_version %d unsupported (want %d)", m.FormatVersion, metaFormatVersion)
	}
	return m, nil
}

// WriteMeta atomically writes meta.json: temp file + rename + fsync(parent).
func WriteMeta(dir string, m Meta) error {
	m.FormatVersion = metaFormatVersion
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	tmp := filepath.Join(dir, metaFileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write meta tmp: %w", err)
	}
	if err := atomicRename(tmp, filepath.Join(dir, metaFileName)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename meta: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync meta dir: %w", err)
	}
	return nil
}
