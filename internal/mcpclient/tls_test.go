package mcpclient

import (
	"testing"
)

func TestValidateTLSFingerprint_Format(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{"valid sha256", "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", false},
		{"empty is ok", "", false},
		{"missing prefix", "a1b2c3d4e5f6", true},
		{"wrong prefix", "md5:abc123", true},
		{"wrong hex length", "sha256:tooshort", true},
		{"invalid hex chars", "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSFingerprint(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTLSFingerprint(%q) error = %v, wantErr %v", tt.fingerprint, err, tt.wantErr)
			}
		})
	}
}
