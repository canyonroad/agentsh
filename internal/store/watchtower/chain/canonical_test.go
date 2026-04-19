package chain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEncodeCanonical_KeyOrder(t *testing.T) {
	rec := IntegrityRecord{
		FormatVersion:  2,
		Sequence:       42,
		Generation:     7,
		PrevHash:       "deadbeef",
		EventHash:      "cafef00d",
		ContextDigest:  "0123456789abcdef",
		KeyFingerprint: "sha256:aabbccdd",
	}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"context_digest":"0123456789abcdef","event_hash":"cafef00d","format_version":2,"generation":7,"key_fingerprint":"sha256:aabbccdd","prev_hash":"deadbeef","sequence":42}`
	if string(got) != want {
		t.Errorf("EncodeCanonical mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestEncodeCanonical_NoWhitespace(t *testing.T) {
	rec := IntegrityRecord{FormatVersion: 2}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(got, " \t\n\r") {
		t.Errorf("encoder emitted whitespace: %q", got)
	}
}

func TestEncodeCanonical_AsciiEscapeNonAscii(t *testing.T) {
	rec := IntegrityRecord{PrevHash: "héllo"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	// 'é' is U+00E9; canonical form must escape it as \u00e9 (lowercase hex).
	if !strings.Contains(string(got), `"prev_hash":"h\u00e9llo"`) {
		t.Errorf("non-ASCII not escaped: %s", got)
	}
}

func TestEncodeCanonical_NoScientificNotation(t *testing.T) {
	// Sequence is uint64; 1e15 must render as decimal, not 1000000000000000e0 etc.
	rec := IntegrityRecord{Sequence: 1_000_000_000_000_000}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"sequence":1000000000000000`) {
		t.Errorf("number not decimal: %s", got)
	}
	for _, marker := range []string{"e+", "e-", "E+", "E-"} {
		if strings.Contains(string(got), marker) {
			t.Errorf("number used scientific notation (marker %q): %s", marker, got)
		}
	}
}

func TestEncodeCanonical_Uint64Max(t *testing.T) {
	rec := IntegrityRecord{Sequence: ^uint64(0)} // 18446744073709551615
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"sequence":18446744073709551615`) {
		t.Errorf("uint64 max not preserved: %s", got)
	}
}

func TestEncodeCanonical_StringEscapes(t *testing.T) {
	// Verify the JSON-mandated escapes for backslash, quote, control chars.
	rec := IntegrityRecord{PrevHash: "a\\b\"c\nd\te"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	want := `"prev_hash":"a\\b\"c\nd\te"`
	if !strings.Contains(string(got), want) {
		t.Errorf("escapes wrong:\ngot:  %s\nwant: substring %s", got, want)
	}
}

func TestEncodeCanonical_SurrogatePair(t *testing.T) {
	// U+1F600 GRINNING FACE → must encode as surrogate pair \uD83D\uDE00.
	rec := IntegrityRecord{PrevHash: "\U0001F600"}
	got, err := EncodeCanonical(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"prev_hash":"\ud83d\ude00"`) {
		t.Errorf("surrogate pair wrong: %s", got)
	}
}

func TestEncodeCanonical_InvalidUTF8Rejected(t *testing.T) {
	// 0x80 is a continuation byte with no leading byte — invalid UTF-8.
	rec := IntegrityRecord{PrevHash: "valid-prefix\x80invalid"}
	_, err := EncodeCanonical(rec)
	if err == nil {
		t.Fatal("expected ErrInvalidUTF8 for invalid UTF-8 in PrevHash; got nil")
	}
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8, got %v", err)
	}
	// Ensure all four string fields are validated, not just the first.
	rec2 := IntegrityRecord{ContextDigest: "good", EventHash: "good", KeyFingerprint: "k\x80", PrevHash: "good"}
	_, err = EncodeCanonical(rec2)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8 for KeyFingerprint, got %v", err)
	}
}

func TestComputeContextDigest_InvalidUTF8Rejected(t *testing.T) {
	ctx := SessionContext{AgentID: "ok", SessionID: "s\x80bad"}
	_, err := ComputeContextDigest(ctx)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8, got %v", err)
	}
}
