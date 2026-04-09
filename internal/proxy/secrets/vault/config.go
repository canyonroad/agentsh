package vault

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Config configures the Vault provider.
type Config struct {
	secrets.ProviderConfigMarker

	// Address is the Vault server address (e.g. "https://vault.corp.internal").
	// Required.
	Address string

	// Namespace is the Vault enterprise namespace. Empty for open-source
	// Vault and OpenBao.
	Namespace string

	// Auth configures how the provider authenticates to Vault.
	Auth AuthConfig
}

// TypeName returns "vault". Used by the registry to map vault://
// URI scheme refs to this provider.
func (Config) TypeName() string { return "vault" }

// Dependencies returns the *Ref fields relevant to the configured
// Auth.Method that need resolution from other providers before this
// provider can be constructed. A ref is only included when the
// corresponding literal field is empty — if both are set, the
// constructor will reject the config during validation.
func (c Config) Dependencies() []secrets.SecretRef {
	var deps []secrets.SecretRef
	switch c.Auth.Method {
	case "token":
		if c.Auth.TokenRef != nil && c.Auth.Token == "" {
			deps = append(deps, *c.Auth.TokenRef)
		}
	case "approle":
		if c.Auth.RoleIDRef != nil && c.Auth.RoleID == "" {
			deps = append(deps, *c.Auth.RoleIDRef)
		}
		if c.Auth.SecretIDRef != nil && c.Auth.SecretID == "" {
			deps = append(deps, *c.Auth.SecretIDRef)
		}
	case "kubernetes":
		// No chained refs — uses service account token file.
	}
	return deps
}

// AuthConfig configures how the provider authenticates to Vault.
type AuthConfig struct {
	// Method is the auth method: "token", "approle", or "kubernetes".
	Method string

	// Token auth. Exactly one of Token (literal) or TokenRef (chained)
	// must be set when Method == "token".
	Token    string
	TokenRef *secrets.SecretRef

	// AppRole auth. Each of RoleID/RoleIDRef and SecretID/SecretIDRef
	// is a literal-or-ref pair. Exactly one form per field must be set
	// when Method == "approle".
	RoleID      string
	RoleIDRef   *secrets.SecretRef
	SecretID    string
	SecretIDRef *secrets.SecretRef

	// Kubernetes auth.
	KubeRole      string // required when Method == "kubernetes"
	KubeMountPath string // default "kubernetes"
	KubeTokenPath string // default "/var/run/secrets/kubernetes.io/serviceaccount/token"
}

// Compile-time assertion that Config satisfies ProviderConfig.
var _ secrets.ProviderConfig = Config{}

// Note: The SecretProvider compile-time assertion for *Provider will be
// added in Task 5 when Provider is defined.
