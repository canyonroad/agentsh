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
	if got.FormatVersion != 2 {
		t.Errorf("FormatVersion = %d, want 2", got.FormatVersion)
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

// TestMeta_LegacyV1ReadInfersAckRecorded regresses the round-3 finding that
// pre-v2 meta.json files (no ack_recorded field) would decode as AckRecorded=false,
// causing Open to ignore an already-persisted (gen, seq) watermark and treat
// the WAL as if no ack had ever been recorded. The fix infers AckRecorded=true
// for v1 files because pre-v2 only MarkAcked wrote meta.json — its existence
// implies an ack was persisted.
func TestMeta_LegacyV1ReadInfersAckRecorded(t *testing.T) {
	dir := t.TempDir()
	// Hand-write a v1 meta.json with no ack_recorded field — exactly the
	// shape an older binary would have left on disk.
	raw := []byte(`{"format_version":1,"ack_high_watermark_seq":42,"ack_high_watermark_gen":7,"session_id":"s1","key_fingerprint":"k1"}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMeta(dir)
	if err != nil {
		t.Fatalf("ReadMeta legacy v1: %v", err)
	}
	if !m.AckRecorded {
		t.Errorf("legacy v1 meta.json must read back as AckRecorded=true (its existence implied an ack); got false")
	}
	if m.AckHighWatermarkSeq != 42 || m.AckHighWatermarkGen != 7 {
		t.Errorf("watermark not preserved across legacy read: got (gen=%d, seq=%d), want (7, 42)",
			m.AckHighWatermarkGen, m.AckHighWatermarkSeq)
	}
	if m.SessionID != "s1" || m.KeyFingerprint != "k1" {
		t.Errorf("legacy fields not preserved: got SessionID=%q, KeyFingerprint=%q", m.SessionID, m.KeyFingerprint)
	}
}

// TestMeta_UnknownFormatVersionRejected pins the version-gate behavior:
// ReadMeta must surface a clear error for any future format version it
// doesn't know how to read, rather than silently decoding it under v2 rules.
func TestMeta_UnknownFormatVersionRejected(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"format_version":99}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMeta(dir); err == nil {
		t.Fatal("ReadMeta with unknown format_version=99 must fail")
	}
}
