package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRotationSet_OrdersOldestFirst(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "audit.log")
	for _, path := range []string{base, base + ".1", base + ".2"} {
		if err := os.WriteFile(path, []byte(path+"\n"), 0o600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
	}

	got, err := DiscoverRotationSet(base)
	if err != nil {
		t.Fatalf("DiscoverRotationSet() error = %v", err)
	}

	want := []LogFile{
		{Path: base + ".2", Index: 2, IsBackup: true},
		{Path: base + ".1", Index: 1, IsBackup: true},
		{Path: base, Index: 0, IsBackup: false},
	}

	if len(got) != len(want) {
		t.Fatalf("len(DiscoverRotationSet()) = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DiscoverRotationSet()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDiscoverRotationSet_RejectsMissingIntermediateBackup(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "audit.log")
	for _, path := range []string{base, base + ".1", base + ".3"} {
		if err := os.WriteFile(path, []byte(path+"\n"), 0o600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", path, err)
		}
	}

	if _, err := DiscoverRotationSet(base); err == nil {
		t.Fatal("DiscoverRotationSet() error = nil, want error for missing intermediate backup")
	}
}

func TestReadLastNonEmptyLine_SearchesNewestFirst(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "audit.log")
	backup := base + ".1"
	if err := os.WriteFile(backup, []byte("older-entry\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", backup, err)
	}
	if err := os.WriteFile(base, []byte("\nnewest-entry\n\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base, err)
	}

	files := []LogFile{
		{Path: backup, Index: 1, IsBackup: true},
		{Path: base, Index: 0, IsBackup: false},
	}

	gotFile, gotLine, err := ReadLastNonEmptyLine(files)
	if err != nil {
		t.Fatalf("ReadLastNonEmptyLine() error = %v", err)
	}

	if gotFile.Path != base {
		t.Fatalf("ReadLastNonEmptyLine() file = %+v, want base file", gotFile)
	}
	if string(gotLine) != "newest-entry" {
		t.Fatalf("ReadLastNonEmptyLine() line = %q, want %q", gotLine, "newest-entry")
	}
}

func TestNewScanner_AllowsLargeTokens(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	line := bytes.Repeat([]byte("x"), 128*1024)
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open() error = %v", err)
	}
	defer file.Close()

	scanner := NewScanner(file)
	if !scanner.Scan() {
		t.Fatalf("scanner.Scan() = false, err = %v", scanner.Err())
	}
	if len(scanner.Bytes()) != len(line) {
		t.Fatalf("len(scanner.Bytes()) = %d, want %d", len(scanner.Bytes()), len(line))
	}
}

func TestParseIntegrityEntry_ExtractsIntegrityAndCanonicalPayload(t *testing.T) {
	t.Parallel()

	line := []byte(`{"z":"last","type":"event","integrity":{"format_version":2,"sequence":17,"prev_hash":"abcd1234","entry_hash":"deadbeef"},"a":"first"}`)

	got, err := ParseIntegrityEntry(line)
	if err != nil {
		t.Fatalf("ParseIntegrityEntry() error = %v", err)
	}

	if got.Type != "event" {
		t.Fatalf("Type = %q, want %q", got.Type, "event")
	}
	if got.Integrity == nil {
		t.Fatal("Integrity = nil, want metadata")
	}
	if got.Integrity.FormatVersion != IntegrityFormatVersion {
		t.Fatalf("Integrity.FormatVersion = %d, want %d", got.Integrity.FormatVersion, IntegrityFormatVersion)
	}
	if got.Integrity.Sequence != 17 {
		t.Fatalf("Integrity.Sequence = %d, want 17", got.Integrity.Sequence)
	}
	if got.Integrity.PrevHash != "abcd1234" {
		t.Fatalf("Integrity.PrevHash = %q, want %q", got.Integrity.PrevHash, "abcd1234")
	}
	if got.Integrity.EntryHash != "deadbeef" {
		t.Fatalf("Integrity.EntryHash = %q, want %q", got.Integrity.EntryHash, "deadbeef")
	}

	wantPayload, err := json.Marshal(map[string]any{
		"a":    "first",
		"type": "event",
		"z":    "last",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(got.CanonicalPayload) != string(wantPayload) {
		t.Fatalf("CanonicalPayload = %s, want %s", got.CanonicalPayload, wantPayload)
	}
}
