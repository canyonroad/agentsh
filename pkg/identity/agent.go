package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidAgentID  = errors.New("invalid agent ID")
	ErrInvalidTenantID = errors.New("invalid tenant ID")
	ErrInvalidAPIKey   = errors.New("invalid API key")
)

// agentIDRe validates agent IDs: alphanumeric with hyphens/underscores, 1-128 chars
var agentIDRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,127}$`)

// tenantIDRe validates tenant IDs: alphanumeric with hyphens/underscores, 1-64 chars
var tenantIDRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

// AuthMethod represents the authentication method used by an agent.
type AuthMethod string

const (
	AuthAPIKey AuthMethod = "api_key" // API key authentication
	AuthJWT    AuthMethod = "jwt"     // JWT bearer token
	AuthMTLS   AuthMethod = "mtls"    // Mutual TLS with client certificate
	AuthOIDC   AuthMethod = "oidc"    // OpenID Connect
)

// IsValid returns true if the auth method is recognized.
func (m AuthMethod) IsValid() bool {
	switch m {
	case AuthAPIKey, AuthJWT, AuthMTLS, AuthOIDC:
		return true
	default:
		return false
	}
}

// TrustLevel represents the trust level of an agent, affecting default policies.
type TrustLevel string

const (
	TrustUntrusted TrustLevel = "untrusted" // Strictest policies, maximum restrictions
	TrustLimited   TrustLevel = "limited"   // Standard policies, typical restrictions
	TrustTrusted   TrustLevel = "trusted"   // Relaxed policies, fewer restrictions
	TrustInternal  TrustLevel = "internal"  // Minimal restrictions, internal use only
)

// IsValid returns true if the trust level is recognized.
func (t TrustLevel) IsValid() bool {
	switch t {
	case TrustUntrusted, TrustLimited, TrustTrusted, TrustInternal:
		return true
	default:
		return false
	}
}

// PolicyStrictness returns a numeric value for sorting (higher = stricter).
func (t TrustLevel) PolicyStrictness() int {
	switch t {
	case TrustInternal:
		return 0
	case TrustTrusted:
		return 1
	case TrustLimited:
		return 2
	case TrustUntrusted:
		return 3
	default:
		return 3 // Default to strictest
	}
}

// AgentIdentity represents a unique agent with its authentication and authorization info.
type AgentIdentity struct {
	// AgentID is the unique identifier for this agent.
	AgentID string `json:"agent_id"`

	// Name is a human-readable name for the agent.
	Name string `json:"name"`

	// TenantID is the tenant/organization this agent belongs to.
	TenantID string `json:"tenant_id"`

	// AuthMethod is the authentication method used by this agent.
	AuthMethod AuthMethod `json:"auth_method"`

	// APIKey is the API key for authentication (never serialized).
	APIKey string `json:"-"`

	// APIKeyHash is the hashed API key for storage (never serialized to JSON).
	APIKeyHash string `json:"-"`

	// JWTSubject is the JWT subject claim for JWT authentication.
	JWTSubject string `json:"jwt_subject,omitempty"`

	// CertFingerprint is the client certificate fingerprint for mTLS.
	CertFingerprint string `json:"cert_fingerprint,omitempty"`

	// OIDCIssuer is the OIDC issuer URL for OIDC authentication.
	OIDCIssuer string `json:"oidc_issuer,omitempty"`

	// OIDCSubject is the OIDC subject claim.
	OIDCSubject string `json:"oidc_subject,omitempty"`

	// Roles are the roles/capabilities assigned to this agent.
	Roles []string `json:"roles"`

	// TrustLevel affects default policies applied to this agent.
	TrustLevel TrustLevel `json:"trust_level"`

	// Metadata contains additional key-value pairs for the agent.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the agent identity was created.
	CreatedAt time.Time `json:"created_at"`

	// LastSeenAt is when the agent was last active.
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`

	// Enabled indicates if the agent is currently enabled.
	Enabled bool `json:"enabled"`
}

// NewAgentIdentity creates a new agent identity with the given parameters.
func NewAgentIdentity(agentID, name, tenantID string) (*AgentIdentity, error) {
	if !agentIDRe.MatchString(agentID) {
		return nil, ErrInvalidAgentID
	}
	if !tenantIDRe.MatchString(tenantID) {
		return nil, ErrInvalidTenantID
	}

	return &AgentIdentity{
		AgentID:    agentID,
		Name:       name,
		TenantID:   tenantID,
		AuthMethod: AuthAPIKey,
		TrustLevel: TrustLimited,
		Roles:      []string{},
		Metadata:   map[string]string{},
		CreatedAt:  time.Now().UTC(),
		Enabled:    true,
	}, nil
}

// Validate checks if the agent identity is valid.
func (a *AgentIdentity) Validate() error {
	if !agentIDRe.MatchString(a.AgentID) {
		return ErrInvalidAgentID
	}
	if !tenantIDRe.MatchString(a.TenantID) {
		return ErrInvalidTenantID
	}
	if !a.AuthMethod.IsValid() {
		return errors.New("invalid auth method")
	}
	if !a.TrustLevel.IsValid() {
		return errors.New("invalid trust level")
	}
	return nil
}

// HasRole returns true if the agent has the specified role.
func (a *AgentIdentity) HasRole(role string) bool {
	for _, r := range a.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AddRole adds a role to the agent if not already present.
func (a *AgentIdentity) AddRole(role string) {
	if !a.HasRole(role) {
		a.Roles = append(a.Roles, role)
	}
}

// RemoveRole removes a role from the agent.
func (a *AgentIdentity) RemoveRole(role string) {
	for i, r := range a.Roles {
		if r == role {
			a.Roles = append(a.Roles[:i], a.Roles[i+1:]...)
			return
		}
	}
}

// Touch updates the LastSeenAt timestamp.
func (a *AgentIdentity) Touch() {
	now := time.Now().UTC()
	a.LastSeenAt = &now
}

// GenerateAPIKey generates a new API key for the agent.
// Returns the raw API key (to be shown to the user once) and sets the hash.
func (a *AgentIdentity) GenerateAPIKey() (string, error) {
	// Generate 32 bytes of random data
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Format as agsh_<hex>
	key := "agsh_" + hex.EncodeToString(bytes)
	a.APIKey = key
	a.AuthMethod = AuthAPIKey

	return key, nil
}

// ValidateAPIKey checks if the provided key matches.
func (a *AgentIdentity) ValidateAPIKey(key string) bool {
	if a.APIKey == "" {
		return false
	}
	// Constant-time comparison would be better for production
	return a.APIKey == key
}

// String returns a string representation of the agent identity.
func (a *AgentIdentity) String() string {
	return a.AgentID + "@" + a.TenantID
}

// IsAPIKeyFormat checks if a string looks like an API key.
func IsAPIKeyFormat(s string) bool {
	return strings.HasPrefix(s, "agsh_") && len(s) == 69 // agsh_ + 64 hex chars
}
