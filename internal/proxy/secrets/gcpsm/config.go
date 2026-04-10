package gcpsm

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Config configures the GCP Secret Manager provider.
type Config struct {
	secrets.ProviderConfigMarker
	ProjectID string
}

func (Config) TypeName() string { return "gcp-sm" }

var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
