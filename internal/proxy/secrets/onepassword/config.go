package onepassword

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Config configures the 1Password Connect provider.
// It overrides Dependencies() to support auth chaining when APIKeyRef is set.
type Config struct {
	secrets.ProviderConfigMarker

	// ServerURL is the 1Password Connect server URL. Required.
	ServerURL string

	// APIKey is the literal Connect API key. Mutually exclusive with APIKeyRef.
	APIKey string

	// APIKeyRef is a chained reference to another provider. Mutually exclusive with APIKey.
	APIKeyRef *secrets.SecretRef
}

func (Config) TypeName() string { return "op" }

// Dependencies returns the APIKeyRef if set (and APIKey is empty).
func (c Config) Dependencies() []secrets.SecretRef {
	if c.APIKeyRef != nil && c.APIKey == "" {
		return []secrets.SecretRef{*c.APIKeyRef}
	}
	return nil
}

var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
