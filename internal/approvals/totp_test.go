package approvals

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}

	// Verify it's valid base32
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not valid base32: %v", err)
	}

	// Verify 20 bytes (160-bit) per RFC 4226
	if len(decoded) != 20 {
		t.Errorf("decoded secret length = %d, want 20", len(decoded))
	}

	// Verify uniqueness
	secret2, _ := GenerateTOTPSecret()
	if secret == secret2 {
		t.Error("GenerateTOTPSecret() returned same secret twice")
	}
}

func TestValidateTOTPCode(t *testing.T) {
	// Generate a fresh secret for testing
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	// Generate a valid code using the otp library
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate test code: %v", err)
	}

	tests := []struct {
		name   string
		code   string
		want   bool
	}{
		{"valid code", code, true},
		{"invalid code", "000000", false},
		{"wrong length", "12345", false},
		{"non-numeric", "abcdef", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateTOTPCode(tt.code, secret)
			if got != tt.want {
				t.Errorf("ValidateTOTPCode(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestFormatTOTPURI(t *testing.T) {
	uri := FormatTOTPURI("session-12345678-abcd", "JBSWY3DPEHPK3PXP")

	// Should truncate session ID to 8 chars
	if !strings.Contains(uri, "agentsh:session-") {
		t.Errorf("URI should contain truncated session ID, got: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("URI should contain secret, got: %s", uri)
	}
	if !strings.Contains(uri, "issuer=agentsh") {
		t.Errorf("URI should contain issuer, got: %s", uri)
	}
}
