package approvals

import (
	"encoding/base32"
	"testing"
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
