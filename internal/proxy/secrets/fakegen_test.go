package secrets

import (
	"errors"
	"testing"
)

func TestParseFormat_ValidFormats(t *testing.T) {
	tests := []struct {
		format  string
		prefix  string
		randLen int
	}{
		{"ghp_{rand:36}", "ghp_", 36},
		{"sk-{rand:48}", "sk-", 48},
		{"{rand:40}", "", 40},
		{"AKIA{rand:32}", "AKIA", 32},
		{"xoxb-{rand:100}", "xoxb-", 100},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			prefix, randLen, err := ParseFormat(tt.format)
			if err != nil {
				t.Fatalf("ParseFormat(%q) returned error: %v", tt.format, err)
			}
			if prefix != tt.prefix {
				t.Errorf("prefix = %q, want %q", prefix, tt.prefix)
			}
			if randLen != tt.randLen {
				t.Errorf("randLen = %d, want %d", randLen, tt.randLen)
			}
		})
	}
}

func TestParseFormat_InvalidFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"empty", ""},
		{"no_placeholder", "ghp_abcdef"},
		{"double_placeholder", "{rand:10}{rand:10}"},
		{"placeholder_not_at_end", "{rand:10}suffix"},
		{"zero_count", "{rand:0}"},
		{"negative_count", "{rand:-5}"},
		{"non_numeric_count", "{rand:abc}"},
		{"missing_count", "{rand:}"},
		{"missing_colon", "{rand10}"},
		{"below_entropy_minimum", "AKIA{rand:16}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseFormat(tt.format)
			if err == nil {
				t.Errorf("ParseFormat(%q) should have returned error", tt.format)
			}
		})
	}
}

func TestParseFormat_EntropyMinimum(t *testing.T) {
	_, _, err := ParseFormat("{rand:23}")
	if err == nil {
		t.Error("ParseFormat with randLen=23 should return ErrFakeEntropyTooLow")
	}

	_, _, err = ParseFormat("{rand:24}")
	if err != nil {
		t.Errorf("ParseFormat with randLen=24 should succeed, got: %v", err)
	}
}

func TestGenerateFake_HappyPath(t *testing.T) {
	fake, err := GenerateFake("ghp_{rand:36}", 40)
	if err != nil {
		t.Fatalf("GenerateFake returned error: %v", err)
	}
	if len(fake) != 40 {
		t.Errorf("len(fake) = %d, want 40", len(fake))
	}
	if string(fake[:4]) != "ghp_" {
		t.Errorf("prefix = %q, want %q", string(fake[:4]), "ghp_")
	}
	for i := 4; i < len(fake); i++ {
		c := fake[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("non-base62 char at position %d: %c", i, c)
		}
	}
}

func TestGenerateFake_NoPrefix(t *testing.T) {
	fake, err := GenerateFake("{rand:40}", 40)
	if err != nil {
		t.Fatalf("GenerateFake returned error: %v", err)
	}
	if len(fake) != 40 {
		t.Errorf("len(fake) = %d, want 40", len(fake))
	}
}

func TestGenerateFake_LengthMismatch(t *testing.T) {
	_, err := GenerateFake("ghp_{rand:36}", 50)
	if !errors.Is(err, ErrFakeLengthMismatch) {
		t.Errorf("expected ErrFakeLengthMismatch, got: %v", err)
	}
}

func TestGenerateFake_TwoCalls_ProduceDifferentOutput(t *testing.T) {
	f1, err := GenerateFake("{rand:40}", 40)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := GenerateFake("{rand:40}", 40)
	if err != nil {
		t.Fatal(err)
	}
	if string(f1) == string(f2) {
		t.Error("two GenerateFake calls produced identical output")
	}
}
