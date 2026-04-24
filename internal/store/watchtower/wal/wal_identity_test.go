package wal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWAL_OpenWritesIdentity verifies that a WAL opened with identity options
// persists those values into meta.json on the next MarkAcked-driven WriteMeta.
// Without the Step-3 fix (MarkAcked's Meta literal includes SessionID and
// KeyFingerprint from w.opts), the assertion on the persisted SessionID
// fails because the meta on disk holds the empty string.
func TestWAL_OpenWritesIdentity(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(1, 1); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AckHighWatermarkSeq != 1 || got.AckHighWatermarkGen != 1 || !got.AckRecorded {
		t.Errorf("ack tuple did not persist: %+v", got)
	}
	if got.SessionID != "s1" {
		t.Errorf("SessionID did not persist: got %q, want %q", got.SessionID, "s1")
	}
	if got.KeyFingerprint != "k1" {
		t.Errorf("KeyFingerprint did not persist: got %q, want %q", got.KeyFingerprint, "k1")
	}
}

// TestWAL_OpenWithMatchingIdentitySucceeds confirms that re-opening a WAL
// directory with identity values matching the persisted meta.json is the
// steady-state production path: no error, no quarantine.
func TestWAL_OpenWithMatchingIdentitySucceeds(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatalf("re-open with matching identity must succeed, got err=%v", err)
	}
	defer w2.Close()
}

// TestWAL_OpenWithMismatchedSessionIDReturnsErrIdentityMismatch covers the
// primary case the identity gate exists to detect: a WAL directory was written
// with one daemon's installation identity, then a different daemon (different
// SessionID) opens it. The WAL MUST refuse to mutate.
func TestWAL_OpenWithMismatchedSessionIDReturnsErrIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s2",
		KeyFingerprint: "k1",
	})
	if err == nil {
		w2.Close()
		t.Fatal("expected ErrIdentityMismatch on mismatched SessionID, got nil")
	}
	if w2 != nil {
		t.Errorf("returned *WAL must be nil on mismatch, got non-nil")
	}
	var mismatch *ErrIdentityMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("err is not *ErrIdentityMismatch: %v", err)
	}
	if mismatch.MismatchedField != "session_id" {
		t.Errorf("MismatchedField = %q, want %q", mismatch.MismatchedField, "session_id")
	}
	if mismatch.PersistedSessionID != "s1" || mismatch.ExpectedSessionID != "s2" {
		t.Errorf("session pair: persisted=%q expected=%q; want persisted=s1 expected=s2",
			mismatch.PersistedSessionID, mismatch.ExpectedSessionID)
	}
	if mismatch.PersistedKeyFingerprint != "k1" || mismatch.ExpectedKeyFingerprint != "k1" {
		t.Errorf("key pair: persisted=%q expected=%q; want both=k1",
			mismatch.PersistedKeyFingerprint, mismatch.ExpectedKeyFingerprint)
	}
	msg := err.Error()
	if !contains(msg, "session_id") || !contains(msg, "s1") || !contains(msg, "s2") {
		t.Errorf("error message missing field/pair: %q", msg)
	}
}

// TestWAL_OpenWithMismatchedKeyFingerprintReturnsErrIdentityMismatch mirrors
// the SessionID case: matching SessionID but mismatching KeyFingerprint must
// also raise the identity gate.
func TestWAL_OpenWithMismatchedKeyFingerprintReturnsErrIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k2",
	})
	if err == nil {
		w2.Close()
		t.Fatal("expected ErrIdentityMismatch on mismatched KeyFingerprint, got nil")
	}
	if w2 != nil {
		t.Errorf("returned *WAL must be nil on mismatch, got non-nil")
	}
	var mismatch *ErrIdentityMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("err is not *ErrIdentityMismatch: %v", err)
	}
	if mismatch.MismatchedField != "key_fingerprint" {
		t.Errorf("MismatchedField = %q, want %q", mismatch.MismatchedField, "key_fingerprint")
	}
	if mismatch.PersistedKeyFingerprint != "k1" || mismatch.ExpectedKeyFingerprint != "k2" {
		t.Errorf("key pair: persisted=%q expected=%q; want persisted=k1 expected=k2",
			mismatch.PersistedKeyFingerprint, mismatch.ExpectedKeyFingerprint)
	}
	if mismatch.PersistedSessionID != "s1" || mismatch.ExpectedSessionID != "s1" {
		t.Errorf("session pair: persisted=%q expected=%q; want both=s1",
			mismatch.PersistedSessionID, mismatch.ExpectedSessionID)
	}
	msg := err.Error()
	if !contains(msg, "key_fingerprint") || !contains(msg, "k1") || !contains(msg, "k2") {
		t.Errorf("error message missing field/pair: %q", msg)
	}
}

// TestWAL_OpenWithEmptyPersistedIdentityAdoptsCallerIdentity covers the
// pre-Task-14a migration path: a meta.json was written with empty SessionID /
// KeyFingerprint by an older binary. Open MUST adopt the caller-supplied
// identity (no error), and the next MarkAcked-driven WriteMeta MUST persist
// the new identity. The negative sub-case asserts the immutability invariant
// kicks in once the identity is adopted: a third Open with a different
// SessionID errors.
func TestWAL_OpenWithEmptyPersistedIdentityAdoptsCallerIdentity(t *testing.T) {
	dir := t.TempDir()
	// Hand-write a v2 meta.json with empty identity fields — exactly the
	// shape a hypothetical post-v2 / pre-Task-14a binary would have left.
	raw := []byte(`{"format_version":2,"ack_high_watermark_seq":42,"ack_high_watermark_gen":7,"ack_recorded":true,"session_id":"","key_fingerprint":""}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatalf("Open with empty persisted identity must succeed (migration), got %v", err)
	}
	// Append + MarkAcked so MarkAcked persists the adopted identity.
	if _, err := w.Append(8, 8, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(8, 8); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "s1" || got.KeyFingerprint != "k1" {
		t.Errorf("identity not adopted: SessionID=%q KeyFingerprint=%q; want s1/k1",
			got.SessionID, got.KeyFingerprint)
	}

	// Negative sub-case: a third Open with a different SessionID must error.
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s2",
		KeyFingerprint: "k1",
	})
	if err == nil {
		w2.Close()
		t.Fatal("third Open with different SessionID must error after identity adopted")
	}
	var mismatch *ErrIdentityMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("err is not *ErrIdentityMismatch: %v", err)
	}
	if mismatch.MismatchedField != "session_id" {
		t.Errorf("MismatchedField = %q, want %q", mismatch.MismatchedField, "session_id")
	}
}

// TestWAL_OpenWithEmptyCallerIdentityDoesNotValidate covers back-compat for
// callers that don't pass identity at all (e.g., existing tests in this
// package). The persisted identity may be non-empty (left by a prior Task-14a
// caller); Open MUST NOT error in that case — empty caller identity skips the
// validation entirely.
func TestWAL_OpenWithEmptyCallerIdentityDoesNotValidate(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.MarkAcked(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Re-open with no identity options — must succeed (back-compat).
	w2, err := Open(Options{
		Dir:           dir,
		SegmentSize:   4 * 1024,
		MaxTotalBytes: 64 * 1024,
		SyncMode:      SyncImmediate,
	})
	if err != nil {
		t.Fatalf("Open with empty caller identity must succeed against any persisted identity, got %v", err)
	}
	defer w2.Close()
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestWAL_OpenContextDigestMatchAdopts verifies that reopening a WAL
// whose persisted context_digest matches the caller's opts proceeds
// without quarantine. Baseline for the context_digest identity check
// added in roborev #5945/5957 Medium #2.
func TestWAL_OpenContextDigestMatchAdopts(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-abc",
	})
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	_ = w.Close()

	// Reopen with the SAME context_digest — no quarantine expected.
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-abc",
	})
	if err != nil {
		t.Errorf("reopen with matching context_digest: %v", err)
	}
	if w2 != nil {
		_ = w2.Close()
	}
}

// TestWAL_OpenContextDigestMismatchReturnsIdentityErr verifies that a
// divergent context_digest is caught as ErrIdentityMismatch with the
// MismatchedField set to "context_digest" and both persisted+expected
// digests populated.
func TestWAL_OpenContextDigestMismatchReturnsIdentityErr(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-first",
	})
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	_ = w.Close()

	_, err = Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-second",
	})
	if err == nil {
		t.Fatal("reopen with mismatched context_digest returned nil; want ErrIdentityMismatch")
	}
	var idErr *ErrIdentityMismatch
	if !errors.As(err, &idErr) {
		t.Fatalf("want *ErrIdentityMismatch, got %T: %v", err, err)
	}
	if idErr.MismatchedField != "context_digest" {
		t.Errorf("MismatchedField = %q, want %q", idErr.MismatchedField, "context_digest")
	}
	if idErr.PersistedContextDigest != "ctx-first" || idErr.ExpectedContextDigest != "ctx-second" {
		t.Errorf("digests = (%q, %q), want (%q, %q)",
			idErr.PersistedContextDigest, idErr.ExpectedContextDigest,
			"ctx-first", "ctx-second")
	}
}

// TestWAL_OpenEmptyPersistedContextDigestBackfills regresses roborev
// #5976 Medium: if an existing WAL's meta.json predates the
// context_digest field (empty persisted), Open MUST rewrite meta
// in-place so the caller's value is persisted immediately. Without
// this, a subsequent reopen under a DIFFERENT context_digest would
// see empty-vs-non-empty (adopt) instead of mismatching, and records
// from the old identity would silently replay under the new
// SessionInit.
func TestWAL_OpenEmptyPersistedContextDigestBackfills(t *testing.T) {
	dir := t.TempDir()
	// Seed an existing meta.json WITHOUT context_digest (simulates a
	// pre-upgrade file).
	if err := WriteMeta(dir, Meta{
		SessionID:      "s1",
		KeyFingerprint: "k1",
	}); err != nil {
		t.Fatalf("seed pre-upgrade meta: %v", err)
	}

	// Open with a context_digest — MUST backfill.
	w, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-upgrade",
	})
	if err != nil {
		t.Fatalf("Open with backfill: %v", err)
	}
	_ = w.Close()

	m, err := ReadMeta(dir)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if m.ContextDigest != "ctx-upgrade" {
		t.Errorf("persisted ContextDigest = %q, want %q — backfill regressed", m.ContextDigest, "ctx-upgrade")
	}

	// A later reopen under a DIFFERENT digest MUST now be caught
	// as a mismatch (not silently adopted).
	_, err = Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s1",
		KeyFingerprint: "k1",
		ContextDigest:  "ctx-drift",
	})
	if err == nil {
		t.Fatal("reopen with drifted context_digest returned nil; backfill did not persist")
	}
	var idErr *ErrIdentityMismatch
	if !errors.As(err, &idErr) {
		t.Fatalf("want *ErrIdentityMismatch, got %T: %v", err, err)
	}
	if idErr.MismatchedField != "context_digest" {
		t.Errorf("MismatchedField = %q, want %q", idErr.MismatchedField, "context_digest")
	}
}

// TestWAL_HeaderOnlySegmentDoesNotBlockIdentityBackfill regresses
// roborev #5989 Medium: segmentsDirHasRecords must distinguish
// header-only / loss-only segments from record-bearing ones.
// Scenario: a WAL ends up with a segment that carries no RecordData
// (e.g., only a loss marker, or a header-only segment from a
// generation roll). On reopen under the same caller identity, the
// backfill path MUST adopt the caller's identity rather than
// incorrectly quarantining a benign upgrade.
func TestWAL_HeaderOnlySegmentDoesNotBlockIdentityBackfill(t *testing.T) {
	dir := t.TempDir()

	// Phase 1: open a WAL WITHOUT identity (simulates a
	// pre-ContextDigest WAL), write ONLY a loss marker (no
	// RecordData), and close.
	w1, err := Open(Options{
		Dir:           dir,
		SegmentSize:   4 * 1024,
		MaxTotalBytes: 64 * 1024,
		SyncMode:      SyncImmediate,
	})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := w1.AppendLoss(LossRecord{
		FromSequence: 1,
		ToSequence:   5,
		Generation:   1,
		Reason:       "crc_corruption",
	}); err != nil {
		t.Fatalf("AppendLoss: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Phase 2: reopen WITH identity. The segment on disk has no
	// RecordData (only a loss marker). segmentsDirHasRecords MUST
	// report hasUser=false, so the backfill path adopts caller
	// identity — NOT quarantines.
	w2, err := Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s-upgrade",
		KeyFingerprint: "k-upgrade",
		ContextDigest:  "ctx-upgrade",
	})
	if err != nil {
		t.Fatalf("reopen with new identity (loss-marker-only WAL should NOT quarantine): %v", err)
	}
	_ = w2.Close()

	m, err := ReadMeta(dir)
	if err != nil {
		t.Fatalf("ReadMeta after reopen: %v", err)
	}
	if m.SessionID != "s-upgrade" || m.KeyFingerprint != "k-upgrade" || m.ContextDigest != "ctx-upgrade" {
		t.Errorf("identity backfill after loss-only segment failed: got (%q, %q, %q)",
			m.SessionID, m.KeyFingerprint, m.ContextDigest)
	}
}

// TestWAL_RecordBearingSegmentBlocksIdentityBackfill is the
// complementary positive-case regression for roborev #5985 High #2:
// a segment carrying actual RecordData with missing identity meta
// MUST refuse the backfill and surface ErrIdentityMismatch.
func TestWAL_RecordBearingSegmentBlocksIdentityBackfill(t *testing.T) {
	dir := t.TempDir()

	// Phase 1: open WITHOUT identity, write a real data record,
	// close. Simulates a pre-identity WAL that actually carries
	// chained records.
	w1, err := Open(Options{
		Dir:           dir,
		SegmentSize:   4 * 1024,
		MaxTotalBytes: 64 * 1024,
		SyncMode:      SyncImmediate,
	})
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := w1.Append(1, 1, []byte("legacy-record")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Phase 2: reopen WITH identity. Records exist but carry no
	// identity — refuse the backfill (they may belong to a
	// different session/agent).
	_, err = Open(Options{
		Dir:            dir,
		SegmentSize:    4 * 1024,
		MaxTotalBytes:  64 * 1024,
		SyncMode:       SyncImmediate,
		SessionID:      "s-new",
		KeyFingerprint: "k-new",
		ContextDigest:  "ctx-new",
	})
	if err == nil {
		t.Fatal("reopen with record-bearing WAL + new identity silently adopted; want ErrIdentityMismatch")
	}
	var idErr *ErrIdentityMismatch
	if !errors.As(err, &idErr) {
		t.Fatalf("want *ErrIdentityMismatch, got %T: %v", err, err)
	}
}
