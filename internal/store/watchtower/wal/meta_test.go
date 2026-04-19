package wal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMeta_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Meta{AckHighWatermarkSeq: 42, AckHighWatermarkGen: 7, SessionID: "01HX", KeyFingerprint: "sha256:abcd"}
	if err := WriteMeta(dir, m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AckHighWatermarkSeq != 42 || got.SessionID != "01HX" {
		t.Errorf("meta did not round-trip: %+v", got)
	}
	if got.FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", got.FormatVersion)
	}
}

func TestMeta_ReadMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadMeta(dir)
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want os.IsNotExist", err)
	}
}

// TestMeta_OverwritePreservesAtomicRename pins the durability contract for
// the overwrite path: the second WriteMeta must not leak the .tmp file (it
// was renamed) and ReadMeta must observe the new contents. This regressed
// when WriteMeta wrote the temp via os.WriteFile without an explicit Sync —
// rename made the *name* durable but contents could come back truncated.
func TestMeta_OverwritePreservesAtomicRename(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMeta(dir, Meta{AckHighWatermarkSeq: 1, SessionID: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMeta(dir, Meta{AckHighWatermarkSeq: 99, SessionID: "second"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "meta.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("meta.json.tmp should not exist after successful overwrite, err = %v", err)
	}
	got, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AckHighWatermarkSeq != 99 || got.SessionID != "second" {
		t.Errorf("overwrite did not take effect: %+v", got)
	}
}
