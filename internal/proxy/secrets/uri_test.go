package secrets

import (
	"errors"
	"testing"
)

func TestParseRef_HappyPath_AllSchemes(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want SecretRef
	}{
		{
			name: "keyring",
			uri:  "keyring://agentsh/vault_token",
			want: SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault_token"},
		},
		{
			name: "vault with field",
			uri:  "vault://kv/data/github#token",
			want: SecretRef{Scheme: "vault", Host: "kv", Path: "data/github", Field: "token"},
		},
		{
			name: "aws-sm",
			uri:  "aws-sm://prod/api-keys/anthropic",
			want: SecretRef{Scheme: "aws-sm", Host: "prod", Path: "api-keys/anthropic"},
		},
		{
			name: "gcp-sm",
			uri:  "gcp-sm://projects/123/secrets/x/versions/latest",
			want: SecretRef{Scheme: "gcp-sm", Host: "projects", Path: "123/secrets/x/versions/latest"},
		},
		{
			name: "azure-kv",
			uri:  "azure-kv://corp-vault/anthropic-key",
			want: SecretRef{Scheme: "azure-kv", Host: "corp-vault", Path: "anthropic-key"},
		},
		{
			name: "op",
			uri:  "op://Personal/Stripe/credential",
			want: SecretRef{Scheme: "op", Host: "Personal", Path: "Stripe/credential"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRef(tc.uri)
			if err != nil {
				t.Fatalf("ParseRef(%q) returned error: %v", tc.uri, err)
			}
			if got.Scheme != tc.want.Scheme || got.Host != tc.want.Host ||
				got.Path != tc.want.Path || got.Field != tc.want.Field {
				t.Errorf("ParseRef(%q)\n got: %+v\nwant: %+v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestParseRef_EmptyString(t *testing.T) {
	_, err := ParseRef("")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_NoScheme(t *testing.T) {
	_, err := ParseRef("noscheme")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"noscheme\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_UnsupportedScheme(t *testing.T) {
	cases := []string{
		"http://example.com/path",
		"file:///etc/passwd",
		"vault2://kv/x",
		"ftp://server/path",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			_, err := ParseRef(uri)
			if !errors.Is(err, ErrUnsupportedScheme) {
				t.Errorf("ParseRef(%q) = %v, want wrapping ErrUnsupportedScheme", uri, err)
			}
		})
	}
}

func TestParseRef_NoHost(t *testing.T) {
	_, err := ParseRef("vault:///path")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef(\"vault:///path\") = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_QueryStringRejected(t *testing.T) {
	_, err := ParseRef("keyring://agentsh/token?version=2")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef with query = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_UserInfoRejected(t *testing.T) {
	_, err := ParseRef("keyring://user:pass@host/path")
	if !errors.Is(err, ErrInvalidURI) {
		t.Errorf("ParseRef with userinfo = %v, want wrapping ErrInvalidURI", err)
	}
}

func TestParseRef_WithFragment(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/github#token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Field != "token" {
		t.Errorf("Field = %q, want %q", ref.Field, "token")
	}
}

func TestParseRef_PathWithMultipleSlashes(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/path/to/secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Path != "data/path/to/secret" {
		t.Errorf("Path = %q, want %q", ref.Path, "data/path/to/secret")
	}
}

func TestParseRef_PathWithEncodedChars(t *testing.T) {
	ref, err := ParseRef("vault://kv/data/team%20a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Path != "data/team a" {
		t.Errorf("Path = %q, want %q (net/url should have decoded %%20 to space)", ref.Path, "data/team a")
	}
}

func TestSecretRef_String_RoundTrip(t *testing.T) {
	cases := []string{
		"keyring://agentsh/vault_token",
		"vault://kv/data/github#token",
		"aws-sm://prod/api-keys/anthropic",
		"op://Personal/Stripe/credential",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			ref, err := ParseRef(uri)
			if err != nil {
				t.Fatalf("ParseRef(%q) error: %v", uri, err)
			}
			got := ref.String()
			if got != uri {
				t.Errorf("String() = %q, want %q", got, uri)
			}
			// Parse the re-rendered URI and verify field-by-field
			// equality. SecretRef has a Metadata map[string]string
			// field which makes the struct not comparable with ==
			// (Go rejects struct equality when any field is a map);
			// compare fields individually instead.
			ref2, err := ParseRef(got)
			if err != nil {
				t.Fatalf("re-parse error: %v", err)
			}
			if ref2.Scheme != ref.Scheme || ref2.Host != ref.Host ||
				ref2.Path != ref.Path || ref2.Field != ref.Field {
				t.Errorf("round-trip changed the ref: %+v -> %+v", ref, ref2)
			}
		})
	}
}

func TestSecretRef_String_NoPath(t *testing.T) {
	ref := SecretRef{Scheme: "keyring", Host: "agentsh"}
	if got := ref.String(); got != "keyring://agentsh" {
		t.Errorf("String() = %q, want %q", got, "keyring://agentsh")
	}
}

func TestSecretRef_String_WithField(t *testing.T) {
	ref := SecretRef{Scheme: "vault", Host: "kv", Path: "data/x", Field: "token"}
	if got := ref.String(); got != "vault://kv/data/x#token" {
		t.Errorf("String() = %q, want %q", got, "vault://kv/data/x#token")
	}
}
