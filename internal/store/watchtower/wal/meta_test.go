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

// TestMeta_OverwritePreservesAtomicRename is a smoke test for the overwrite
// path: a second WriteMeta replaces the first, ReadMeta sees the new
// contents, and no .tmp leaks behind. It cannot distinguish "rename without
// fsync" from "fsync + rename" — that requires crash injection — but it
// catches gross regressions in the overwrite path (e.g., partial rename or
// stale-tmp leaks).
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
