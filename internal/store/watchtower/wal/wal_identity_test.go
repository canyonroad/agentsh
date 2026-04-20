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
