package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSidecarRoundTrip(t *testing.T) {
	t.Parallel()

	path := SidecarPath(filepath.Join(t.TempDir(), "audit.log"))
	want := SidecarState{
		FormatVersion:  IntegrityFormatVersion,
		Sequence:       17,
		PrevHash:       "abcd1234",
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
		UpdatedAt:      time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}

	if err := WriteSidecar(path, want); err != nil {
		t.Fatalf("WriteSidecar() error = %v", err)
	}

	got, err := ReadSidecar(path)
	if err != nil {
		t.Fatalf("ReadSidecar() error = %v", err)
	}

	if got.FormatVersion != want.FormatVersion {
		t.Fatalf("FormatVersion = %d, want %d", got.FormatVersion, want.FormatVersion)
	}
	if got.Sequence != want.Sequence {
		t.Fatalf("Sequence = %d, want %d", got.Sequence, want.Sequence)
	}
	if got.PrevHash != want.PrevHash {
		t.Fatalf("PrevHash = %q, want %q", got.PrevHash, want.PrevHash)
	}
	if got.KeyFingerprint != want.KeyFingerprint {
		t.Fatalf("KeyFingerprint = %q, want %q", got.KeyFingerprint, want.KeyFingerprint)
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("UpdatedAt = %s, want %s", got.UpdatedAt, want.UpdatedAt)
	}
}

func TestReadSidecar_NotFound(t *testing.T) {
	t.Parallel()

	_, err := ReadSidecar(filepath.Join(t.TempDir(), "missing.chain"))
	if !errors.Is(err, ErrSidecarNotFound) {
		t.Fatalf("ReadSidecar() error = %v, want %v", err, ErrSidecarNotFound)
	}
}

func TestReadSidecar_RejectsInvalidState(t *testing.T) {
	t.Parallel()

	updatedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name       string
		state      map[string]any
		wantSubstr string
	}{
		{
			name: "missing_format_version",
			state: map[string]any{
				"sequence":        int64(17),
				"prev_hash":       "abcd1234",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "format_version",
		},
		{
			name: "future_format_version",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion + 1,
				"sequence":        int64(17),
				"prev_hash":       "abcd1234",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "format_version",
		},
		{
			name: "negative_format_version",
			state: map[string]any{
				"format_version":  -1,
				"sequence":        int64(17),
				"prev_hash":       "abcd1234",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "format_version",
		},
		{
			name: "missing_key_fingerprint",
			state: map[string]any{
				"format_version": IntegrityFormatVersion,
				"sequence":       int64(17),
				"prev_hash":      "abcd1234",
				"updated_at":     updatedAt,
			},
			wantSubstr: "key_fingerprint",
		},
		{
			name: "missing_sequence",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"prev_hash":       "abcd1234",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "sequence",
		},
		{
			name: "missing_prev_hash",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"sequence":        int64(17),
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "prev_hash",
		},
		{
			name: "negative_sequence_with_prev_hash",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"sequence":        int64(-1),
				"prev_hash":       "abcd1234",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "sequence",
		},
		{
			name: "sequence_below_minus_one",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"sequence":        int64(-2),
				"prev_hash":       "",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "sequence",
		},
		{
			name: "positive_sequence_with_empty_prev_hash",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"sequence":        int64(0),
				"prev_hash":       "",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "prev_hash",
		},
		{
			name: "invalid_prev_hash",
			state: map[string]any{
				"format_version":  IntegrityFormatVersion,
				"sequence":        int64(2),
				"prev_hash":       "not-hex!!!",
				"key_fingerprint": "sha256:00112233445566778899aabbccddeeff",
				"updated_at":      updatedAt,
			},
			wantSubstr: "prev_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "audit.log.chain")
			data, err := json.Marshal(tt.state)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}

			_, err = ReadSidecar(path)
			if err == nil {
				t.Fatal("ReadSidecar() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("ReadSidecar() error = %v, want substring %q", err, tt.wantSubstr)
			}
		})
	}
}

func TestWriteSidecar_FillsDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log.chain")
	if err := WriteSidecar(path, SidecarState{
		FormatVersion:  0,
		Sequence:       -1,
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
	}); err != nil {
		t.Fatalf("WriteSidecar() error = %v", err)
	}

	got, err := ReadSidecar(path)
	if err != nil {
		t.Fatalf("ReadSidecar() error = %v", err)
	}

	if got.FormatVersion != IntegrityFormatVersion {
		t.Fatalf("FormatVersion = %d, want %d", got.FormatVersion, IntegrityFormatVersion)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt is zero, want auto-filled timestamp")
	}
}

func TestWriteSidecar_CleansUpTempFileOnRenameFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log.chain")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("os.Mkdir(%q) error = %v", path, err)
	}

	err := WriteSidecar(path, SidecarState{
		Sequence:       0,
		PrevHash:       "",
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
	})
	if err == nil {
		t.Fatal("WriteSidecar() error = nil, want rename failure")
	}

	matches, err := filepath.Glob(filepath.Join(dir, "audit.log.chain.tmp.*"))
	if err != nil {
		t.Fatalf("filepath.Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp sidecar files = %v, want none", matches)
	}
}

func TestWriteSidecar_OverwritesExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log.chain")
	first := SidecarState{
		Sequence:       0,
		PrevHash:       "",
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
		UpdatedAt:      time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	second := SidecarState{
		Sequence:       3,
		PrevHash:       "abcdef0123456789",
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
		UpdatedAt:      time.Date(2026, time.January, 2, 4, 5, 6, 0, time.UTC),
	}

	if err := WriteSidecar(path, first); err != nil {
		t.Fatalf("WriteSidecar(first) error = %v", err)
	}
	if err := WriteSidecar(path, second); err != nil {
		t.Fatalf("WriteSidecar(second) error = %v", err)
	}

	got, err := ReadSidecar(path)
	if err != nil {
		t.Fatalf("ReadSidecar() error = %v", err)
	}
	if got.Sequence != second.Sequence {
		t.Fatalf("Sequence = %d, want %d", got.Sequence, second.Sequence)
	}
	if got.PrevHash != second.PrevHash {
		t.Fatalf("PrevHash = %q, want %q", got.PrevHash, second.PrevHash)
	}
}
