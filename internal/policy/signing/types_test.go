package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestKeyID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := KeyID(pub)
	if len(kid) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(kid))
	}
	// Deterministic
	if kid != KeyID(pub) {
		t.Fatal("expected deterministic key ID")
	}
}

func TestSigFileValidate(t *testing.T) {
	tests := []struct {
		name    string
		sig     SigFile
		wantErr string
	}{
		{"valid", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, ""},
		{"bad version", SigFile{Version: 2, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "unsupported version"},
		{"bad algorithm", SigFile{Version: 1, Algorithm: "rsa", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "unsupported algorithm"},
		{"missing key_id", SigFile{Version: 1, Algorithm: "ed25519", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA"}, "missing key_id"},
		{"missing signature", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z"}, "missing signature"},
		{"missing signed_at", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", Signature: "AAAA"}, "missing signed_at"},
		{"non-empty cert_chain", SigFile{Version: 1, Algorithm: "ed25519", KeyID: "abc", SignedAt: "2026-01-01T00:00:00Z", Signature: "AAAA", CertChain: []string{"x"}}, "unsupported_cert_chain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}
