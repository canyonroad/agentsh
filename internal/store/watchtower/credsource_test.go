package watchtower

import (
	"context"
	"strings"
	"testing"
)

func TestCredLogID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, token, want string
		wantPrefix        bool
	}{
		{name: "kid.secret returns kid", token: "inst-abc.SUPERSECRETVALUE", want: "inst-abc"},
		{name: "multi-dot splits on first", token: "kid1.a.b.c", want: "kid1"},
		{name: "legacy no-dot hashes", token: "plainlegacytoken", want: "sha256:", wantPrefix: true},
		{name: "leading dot hashes", token: ".secret", want: "sha256:", wantPrefix: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := credLogID(tc.token)
			if strings.Contains(got, "SECRET") || got == tc.token && tc.wantPrefix {
				t.Fatalf("credLogID leaked the secret: %q", got)
			}
			if tc.wantPrefix {
				if !strings.HasPrefix(got, tc.want) {
					t.Fatalf("got %q, want prefix %q", got, tc.want)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewStaticCredentialSource(t *testing.T) {
	t.Parallel()
	if NewStaticCredentialSource("") != nil {
		t.Fatal("empty token must yield a nil CredentialSource")
	}
	src := NewStaticCredentialSource("kid.secret")
	if src == nil {
		t.Fatal("non-empty token must yield a source")
	}
	got, err := src.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "kid.secret" {
		t.Fatalf("Bearer: got %q, want %q", got, "kid.secret")
	}
}
