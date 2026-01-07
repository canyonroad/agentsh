package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCClaims contains the validated claims from an OIDC token.
type OIDCClaims struct {
	Subject    string    // The subject (sub) claim
	OperatorID string    // Mapped operator ID (from configured claim)
	Groups     []string  // User groups (from configured claim)
	Email      string    // Email address if present
	ExpiresAt  time.Time // Token expiration time
}

// cachedToken stores a validated token with its expiration.
type cachedToken struct {
	claims    *OIDCClaims
	expiresAt time.Time
}

// OIDCAuth provides OIDC JWT validation.
type OIDCAuth struct {
	verifier       *oidc.IDTokenVerifier
	issuer         string
	audience       string
	claimMappings  config.OIDCClaimMappings
	allowedGroups  []string
	groupPolicyMap map[string]string

	mu    sync.RWMutex
	cache map[string]*cachedToken
}

// NewOIDCAuth creates a new OIDC authenticator.
// It connects to the OIDC provider to fetch the JWKS for token validation.
func NewOIDCAuth(ctx context.Context, issuer, clientID, audience string, mappings config.OIDCClaimMappings, allowedGroups []string, groupPolicyMap map[string]string) (*OIDCAuth, error) {
	if issuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("OIDC client_id is required")
	}

	// Create OIDC provider (fetches discovery document)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("create OIDC provider: %w", err)
	}

	// Configure the verifier
	verifierConfig := &oidc.Config{
		ClientID: clientID,
	}

	// If audience is explicitly set, use it for validation
	if audience != "" {
		verifierConfig.ClientID = audience
	}

	verifier := provider.Verifier(verifierConfig)

	// Apply defaults to claim mappings
	if mappings.OperatorID == "" {
		mappings.OperatorID = "sub"
	}
	if mappings.Groups == "" {
		mappings.Groups = "groups"
	}

	return &OIDCAuth{
		verifier:       verifier,
		issuer:         issuer,
		audience:       audience,
		claimMappings:  mappings,
		allowedGroups:  allowedGroups,
		groupPolicyMap: groupPolicyMap,
		cache:          make(map[string]*cachedToken),
	}, nil
}

// ValidateToken validates a JWT token and returns the extracted claims.
// Validated tokens are cached until their expiration time.
func (a *OIDCAuth) ValidateToken(ctx context.Context, token string) (*OIDCClaims, error) {
	// Check cache first
	a.mu.RLock()
	if cached, ok := a.cache[token]; ok {
		if time.Now().Before(cached.expiresAt) {
			a.mu.RUnlock()
			return cached.claims, nil
		}
	}
	a.mu.RUnlock()

	// Verify the token
	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// Extract all claims into a map
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("extract claims: %w", err)
	}

	// Build OIDCClaims from raw claims
	claims := &OIDCClaims{
		Subject:   idToken.Subject,
		ExpiresAt: idToken.Expiry,
	}

	// Extract operator ID from configured claim
	if a.claimMappings.OperatorID == "sub" {
		claims.OperatorID = idToken.Subject
	} else if val, ok := rawClaims[a.claimMappings.OperatorID]; ok {
		claims.OperatorID = fmt.Sprintf("%v", val)
	} else {
		claims.OperatorID = idToken.Subject // fallback to sub
	}

	// Extract groups from configured claim
	if groupsRaw, ok := rawClaims[a.claimMappings.Groups]; ok {
		switch g := groupsRaw.(type) {
		case []interface{}:
			for _, v := range g {
				if s, ok := v.(string); ok {
					claims.Groups = append(claims.Groups, s)
				}
			}
		case []string:
			claims.Groups = g
		}
	}

	// Extract email if present
	if email, ok := rawClaims["email"].(string); ok {
		claims.Email = email
	}

	// Check if user is in allowed groups (if configured)
	if len(a.allowedGroups) > 0 {
		allowed := false
		for _, userGroup := range claims.Groups {
			for _, allowedGroup := range a.allowedGroups {
				if userGroup == allowedGroup {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("user not in allowed groups")
		}
	}

	// Cache the validated token
	a.mu.Lock()
	a.cache[token] = &cachedToken{
		claims:    claims,
		expiresAt: idToken.Expiry,
	}
	// Clean up expired entries (simple cleanup, could be improved with TTL-based eviction)
	now := time.Now()
	for k, v := range a.cache {
		if now.After(v.expiresAt) {
			delete(a.cache, k)
		}
	}
	a.mu.Unlock()

	return claims, nil
}

// PolicyForGroups returns the policy name for the user's groups.
// It returns the first matching policy from the group-to-policy map.
// If no match is found, it returns an empty string.
func (a *OIDCAuth) PolicyForGroups(groups []string) string {
	if a == nil || a.groupPolicyMap == nil {
		return ""
	}

	for _, group := range groups {
		if policy, ok := a.groupPolicyMap[group]; ok {
			return policy
		}
	}
	return ""
}

// RoleForClaims determines the role based on claims.
func (o *OIDCAuth) RoleForClaims(claims *OIDCClaims) string {
	if claims == nil {
		return "agent"
	}
	// Check for admin groups
	for _, g := range claims.Groups {
		if strings.Contains(strings.ToLower(g), "admin") {
			return "admin"
		}
	}
	return "agent"
}

// Issuer returns the configured OIDC issuer URL.
func (a *OIDCAuth) Issuer() string {
	return a.issuer
}

// ClearCache clears the token cache. Useful for testing.
func (a *OIDCAuth) ClearCache() {
	a.mu.Lock()
	a.cache = make(map[string]*cachedToken)
	a.mu.Unlock()
}
