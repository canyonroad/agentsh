package secrets

import "errors"

// ErrNotFound is returned when a Fetch targets a secret that does
// not exist in the backend. Callers should branch on
// errors.Is(err, ErrNotFound) to honor policy like on_missing.
var ErrNotFound = errors.New("secrets: not found")

// ErrUnauthorized is returned when the backend rejects the
// provider's own credentials (bad token, expired lease, etc.).
// Distinct from ErrKeyringUnavailable, which means the backend
// itself is unreachable.
var ErrUnauthorized = errors.New("secrets: unauthorized")

// ErrInvalidURI is returned by ParseRef when a URI is syntactically
// malformed (empty string, bad scheme delimiter, missing host,
// query string present, userinfo present). Also returned by a
// provider's Fetch when a SecretRef is missing required semantic
// pieces for that backend.
var ErrInvalidURI = errors.New("secrets: invalid URI")

// ErrUnsupportedScheme is returned by ParseRef when the URI scheme
// is syntactically valid but not one of the six v1 schemes (vault,
// aws-sm, gcp-sm, azure-kv, op, keyring).
var ErrUnsupportedScheme = errors.New("secrets: unsupported scheme")

// ErrFieldNotSupported is returned by a provider when a SecretRef
// carries a non-empty Field but the provider's backend stores
// scalar values only (e.g. OS keyring entries are single-valued,
// unlike Vault KV-v2 entries which are field-addressable).
var ErrFieldNotSupported = errors.New("secrets: field not supported")

// ErrKeyringUnavailable is returned by the keyring provider's New
// constructor when the OS keyring backend cannot be reached at all
// (D-Bus not running, Keychain access denied at the OS level,
// Windows Credential Manager subsystem unavailable). It is a hard
// error; the operator must either set up the keyring or use a
// different provider.
var ErrKeyringUnavailable = errors.New("secrets: keyring unavailable")

// ErrCyclicDependency is returned by NewRegistry when the provider
// dependency graph contains a cycle. The error message lists all
// configs that could not be resolved (cycle members and their
// downstream dependents).
var ErrCyclicDependency = errors.New("secrets: cyclic provider dependency")
