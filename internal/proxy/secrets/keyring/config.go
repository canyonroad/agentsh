package keyring

import secrets "github.com/agentsh/agentsh/internal/proxy/secrets"

// Config configures the keyring provider.
//
// Config satisfies secrets.ProviderConfig by embedding
// secrets.ProviderConfigMarker. The marker embedding is the only
// way for a type outside package secrets to satisfy the sealed
// ProviderConfig interface, because Go qualifies unexported method
// identities by their declaring package.
//
// Apart from the embedded marker, Config is currently empty: every
// keyring entry is identified entirely by its SecretRef (host =
// service, path = user). A later plan may add fields like a default
// service prefix or a per-OS backend selector.
type Config struct {
	secrets.ProviderConfigMarker
}

// TypeName returns "keyring". Used by the registry to map
// keyring:// URI scheme refs to this provider.
func (Config) TypeName() string { return "keyring" }

// Compile-time assertions. These fail to build if Provider or
// Config ever drift away from the interfaces they're expected to
// satisfy.
var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
