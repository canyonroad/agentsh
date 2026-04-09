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

	// Reject %2F in the path. RawPath is only populated when the original
	// path contained escape sequences; if it contains %2F, we cannot
	// distinguish a literal '/' in a segment name from a path separator,
	// so we refuse it.
	if u.RawPath != "" && strings.Contains(strings.ToLower(u.RawPath), "%2f") {
		return SecretRef{}, fmt.Errorf("%w: literal '/' in path segment (%%2F) not supported", ErrInvalidURI)
	}

	return SecretRef{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   strings.TrimPrefix(u.Path, "/"),
		Field:  u.Fragment,
	}, nil
}

// String renders a SecretRef back to its URI form. It uses net/url's
// own escaping, so characters that would normally need percent-encoding
// in the path or fragment (e.g. spaces) are escaped on output.
//
// Round-trip property: for any SecretRef produced by ParseRef,
// ParseRef(r.String()) returns a ref that is semantically equal to r.
// The literal bytes of r.String() may differ from the original URI
// (for example, capitalization of hex escapes may change, or an empty
// fragment may be dropped), but the parsed fields will match.
//
// String does not validate the ref: constructing an invalid SecretRef
// by hand and calling String may produce a URI that ParseRef rejects.
func (r SecretRef) String() string {
	u := url.URL{
		Scheme: r.Scheme,
		Host:   r.Host,
	}
	if r.Path != "" {
		u.Path = "/" + strings.TrimPrefix(r.Path, "/")
	}
	if r.Field != "" {
		u.Fragment = r.Field
	}
	return u.String()
}
