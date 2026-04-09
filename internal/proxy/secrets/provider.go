package secrets

import (
	"context"
	"time"
)

// SecretProvider is implemented by every secret backend.
//
// The daemon constructs one provider per backend at session start,
// calls Fetch zero or more times, and calls Close exactly once at
// session end. Implementations MUST be safe for concurrent use by
// multiple goroutines.
type SecretProvider interface {
	// Name returns the provider's stable identifier used in audit
	// events and error messages (e.g. "keyring", "vault").
	Name() string

	// Fetch retrieves a single secret identified by ref.
	//
	// The returned SecretValue's Value buffer is owned by the
	// caller; the provider does not retain a reference. The
	// caller is responsible for calling SecretValue.Zero when
	// the value is no longer needed.
	//
	// Errors MUST be wrappable with errors.Is against the
	// sentinels in this package: ErrNotFound when the secret
	// does not exist, ErrUnauthorized when the backend rejects
	// the provider's credentials, ErrInvalidURI when the ref
	// is missing required semantic pieces for this backend,
	// ErrFieldNotSupported when the ref carries a Field the
	// backend cannot honor, or a wrapped transport error for
	// anything else.
	Fetch(ctx context.Context, ref SecretRef) (SecretValue, error)

	// Close releases any resources held by the provider. Safe to
	// call multiple times; subsequent calls are no-ops. After
	// Close returns, Fetch MUST return a non-nil error.
	Close() error
}

// SecretRef identifies one secret in one provider.
//
// Callers should construct SecretRef via ParseRef rather than
// building literals, except in tests. Going through ParseRef
// guarantees consistent validation.
type SecretRef struct {
	// Scheme is the URI scheme: "keyring", "vault", "aws-sm",
	// "gcp-sm", "azure-kv", or "op".
	Scheme string

	// Host is the URI host component. Interpreted per-provider:
	// for keyring it is the OS keyring service name; for vault
	// it is the mount point; etc.
	Host string

	// Path is the URI path with its leading slash trimmed.
	// Interpreted per-provider. Path must not contain a leading
	// slash; callers that construct SecretRef by hand are
	// responsible for stripping it.
	Path string

	// Field is the optional URI fragment (everything after "#").
	// Empty if the URI had no fragment. Providers that cannot
	// honor a Field (e.g. keyring) return ErrFieldNotSupported
	// when it is non-empty.
	Field string

	// Metadata holds provider-specific hints. Reserved for v2;
	// v1 providers do not read it. Included now so adding it
	// later is not a public-API churn.
	Metadata map[string]string
}

// SecretValue is the result of a successful Fetch.
//
// The Value field holds the raw secret bytes. The caller owns
// this buffer and should call SecretValue.Zero when done.
type SecretValue struct {
	// Value is the secret material. Caller-owned.
	Value []byte

	// TTL is the remaining lifetime of the secret as reported by
	// the backend. Zero means no lease information is available
	// (not "expires immediately").
	TTL time.Duration

	// LeaseID is the backend-specific lease identifier. Empty if
	// the secret is not leased.
	LeaseID string

	// Version is the backend-specific version string. Empty if
	// the secret is not versioned.
	Version string

	// FetchedAt is the local wall-clock time the provider
	// retrieved the secret. Set by the provider.
	FetchedAt time.Time
}

// Zero overwrites the secret bytes with zeros and clears the
// lease and version fields. After Zero returns, the SecretValue
// holds no secret material. Idempotent; safe to call on a
// zero-value SecretValue.
func (sv *SecretValue) Zero() {
	for i := range sv.Value {
		sv.Value[i] = 0
	}
	sv.Value = nil
	sv.LeaseID = ""
	sv.Version = ""
}

// ProviderConfig is the marker interface that every provider's
// config struct must satisfy. The registry — to be added in a
// later plan — type-switches on ProviderConfig to dispatch to the
// right constructor at policy-load time.
//
// Types outside package secrets satisfy ProviderConfig by
// embedding ProviderConfigMarker. Embedding is required because
// Go's unexported-method sealing does not work across package
// boundaries: an unexported method's identity is qualified by
// the declaring package, so a type in another package cannot
// directly implement a sealed interface from this one. Embedding
// ProviderConfigMarker gives the outer type a promoted
// providerConfig() method whose identity lives in package
// secrets, which is what satisfies the interface.
//
// The seal is strong-by-convention: anyone can embed
// ProviderConfigMarker, but doing so is a deliberate opt-in, and
// the registry only dispatches on config types it already knows
// about.
type ProviderConfig interface {
	providerConfig()
}

// ProviderConfigMarker is a zero-size struct that provider config
// types embed to satisfy ProviderConfig. Example usage:
//
//	type Config struct {
//	    secrets.ProviderConfigMarker
//	    // provider-specific fields...
//	}
//
// Do not remove providerConfig() even if a linter flags it
// "unused" — its sole purpose is to seal ProviderConfig through
// method promotion to embedders of ProviderConfigMarker.
type ProviderConfigMarker struct{}

func (ProviderConfigMarker) providerConfig() {}
