package secrets

import (
	"fmt"
	"net/url"
	"strings"
)

// supportedSchemes is the closed set of v1 URI schemes. Anything
// outside this set is rejected with ErrUnsupportedScheme.
var supportedSchemes = map[string]struct{}{
	"vault":    {},
	"aws-sm":   {},
	"gcp-sm":   {},
	"azure-kv": {},
	"op":       {},
	"keyring":  {},
}

// ParseRef parses a secret reference URI of the form
//
//	scheme://host[/path][#field]
//
// and returns a SecretRef. The fragment, if present, becomes
// SecretRef.Field. The path's leading slash is stripped.
//
// ParseRef does not validate per-provider semantics — it only
// validates the URI grammar and that the scheme is one of the six
// known schemes. Each provider validates its own SecretRef inside
// its Fetch implementation.
//
// Errors are always wrappable with errors.Is against ErrInvalidURI
// or ErrUnsupportedScheme.
func ParseRef(uri string) (SecretRef, error) {
	if uri == "" {
		return SecretRef{}, fmt.Errorf("%w: empty", ErrInvalidURI)
	}

	u, err := url.Parse(uri)
	if err != nil {
		return SecretRef{}, fmt.Errorf("%w: %s", ErrInvalidURI, err)
	}

	if u.Scheme == "" {
		return SecretRef{}, fmt.Errorf("%w: missing scheme", ErrInvalidURI)
	}
	if _, ok := supportedSchemes[u.Scheme]; !ok {
		return SecretRef{}, fmt.Errorf("%w: %q", ErrUnsupportedScheme, u.Scheme)
	}
	if u.Host == "" {
		return SecretRef{}, fmt.Errorf("%w: missing host", ErrInvalidURI)
	}
	if u.RawQuery != "" {
		return SecretRef{}, fmt.Errorf("%w: query strings not allowed", ErrInvalidURI)
	}
	if u.User != nil {
		return SecretRef{}, fmt.Errorf("%w: userinfo not allowed", ErrInvalidURI)
	}

	return SecretRef{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   strings.TrimPrefix(u.Path, "/"),
		Field:  u.Fragment,
	}, nil
}

// String renders a SecretRef back to its canonical URI form.
// ParseRef(r.String()) round-trips for any SecretRef that ParseRef
// accepts.
func (r SecretRef) String() string {
	var b strings.Builder
	b.WriteString(r.Scheme)
	b.WriteString("://")
	b.WriteString(r.Host)
	if r.Path != "" {
		b.WriteByte('/')
		b.WriteString(r.Path)
	}
	if r.Field != "" {
		b.WriteByte('#')
		b.WriteString(r.Field)
	}
	return b.String()
}
