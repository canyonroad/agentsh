package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestWarnIfCredentialOverPlaintext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		token    string
		insecure bool
		wantWarn bool
	}{
		{"cred + insecure warns", "kid.secret", true, true},
		{"cred + secure silent", "kid.secret", false, false},
		{"no cred + insecure silent", "", true, false},
		{"no cred + secure silent", "", false, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			warnIfCredentialOverPlaintext(logger, tc.token, tc.insecure)
			got := strings.Contains(buf.String(), "plaintext")
			if got != tc.wantWarn {
				t.Fatalf("warn emitted = %v, want %v (log=%q)", got, tc.wantWarn, buf.String())
			}
			if strings.Contains(buf.String(), tc.token) && tc.token != "" {
				t.Fatalf("WARN leaked the credential: %q", buf.String())
			}
		})
	}
}
