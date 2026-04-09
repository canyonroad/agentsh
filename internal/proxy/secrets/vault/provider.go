package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	approleauth "github.com/hashicorp/vault/api/auth/approle"
	kubeauth "github.com/hashicorp/vault/api/auth/kubernetes"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Provider is a Vault-backed secrets.SecretProvider using KV v2.
//
// Provider is safe for concurrent Fetch and Close. Close waits for
// any in-flight Fetch to finish before returning, so the contract
// "after Close returns, Fetch returns an error" holds even under
// concurrent access.
//
// Concurrency design mirrors keyring.Provider:
//   - closed is an atomic flag checked lock-free on the Fetch fast
//     path.
//   - mu is an RWMutex held for read by Fetch for its entire duration
//     (including the Vault HTTP call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu         sync.RWMutex
	closed     atomic.Bool
	client     *vaultapi.Client
	ownedToken bool // true if we created the token via AppRole/K8s
}

// New constructs a Vault provider.
//
// Steps:
//  1. Validate the config.
//  2. Resolve any chained auth refs via resolver.
//  3. Create the vault/api client.
//  4. Authenticate.
//  5. Verify connectivity via token lookup-self.
//  6. Zero resolved secrets.
func New(ctx context.Context, cfg Config, resolver secrets.RefResolver) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	token, roleID, secretID, err := resolveAuthRefs(ctx, cfg.Auth, resolver)
	if err != nil {
		return nil, fmt.Errorf("vault: resolving auth refs: %w", err)
	}

	// Create vault/api client.
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.Address
	vaultCfg.Timeout = 30 * time.Second

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: creating client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	// Authenticate.
	var ownedToken bool
	switch cfg.Auth.Method {
	case "token":
		client.SetToken(token)

	case "approle":
		appRoleAuth, authErr := approleauth.NewAppRoleAuth(roleID, &approleauth.SecretID{FromString: secretID})
		if authErr != nil {
			return nil, fmt.Errorf("vault: creating approle auth: %w", authErr)
		}
		authSecret, authErr := client.Auth().Login(ctx, appRoleAuth)
		if authErr != nil {
			return nil, fmt.Errorf("approle login: %w", mapAuthError(authErr))
		}
		if authSecret == nil || authSecret.Auth == nil {
			return nil, fmt.Errorf("%w: approle login returned nil auth", secrets.ErrUnauthorized)
		}
		ownedToken = true

	case "kubernetes":
		mountPath := cfg.Auth.KubeMountPath
		if mountPath == "" {
			mountPath = "kubernetes"
		}
		tokenPath := cfg.Auth.KubeTokenPath
		if tokenPath == "" {
			// Default Kubernetes service account token path. This is a
			// Linux-only path because Kubernetes auth is used exclusively
			// inside Kubernetes pods (which run Linux). Callers on other
			// platforms must set KubeTokenPath explicitly.
			tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
		kubeAuth, authErr := kubeauth.NewKubernetesAuth(
			cfg.Auth.KubeRole,
			kubeauth.WithServiceAccountTokenPath(tokenPath),
			kubeauth.WithMountPath(mountPath),
		)
		if authErr != nil {
			return nil, fmt.Errorf("vault: creating kubernetes auth: %w", authErr)
		}
		authSecret, authErr := client.Auth().Login(ctx, kubeAuth)
		if authErr != nil {
			return nil, fmt.Errorf("kubernetes login: %w", mapAuthError(authErr))
		}
		if authSecret == nil || authSecret.Auth == nil {
			return nil, fmt.Errorf("%w: kubernetes login returned nil auth", secrets.ErrUnauthorized)
		}
		ownedToken = true

	default:
		return nil, fmt.Errorf("vault: unsupported auth method %q", cfg.Auth.Method)
	}

	// Verify connectivity. If this fails after AppRole/K8s login,
	// revoke the freshly issued token to prevent leaks.
	_, err = client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		if ownedToken {
			_ = client.Auth().Token().RevokeSelf("")
		}
		return nil, fmt.Errorf("token lookup-self: %w", mapAuthError(err))
	}

	// Clear resolved credential variables. Note: Go strings are immutable,
	// so we cannot wipe their backing memory. We clear the variables to
	// prevent accidental reuse; the SecretValue.Zero() calls in
	// resolveAuthRefs handle the byte-level wiping of the resolver output.
	token = ""
	roleID = ""
	secretID = ""

	return &Provider{
		client:     client,
		ownedToken: ownedToken,
	}, nil
}

// Name returns "vault". Used in audit events.
func (p *Provider) Name() string { return "vault" }

// Fetch retrieves a secret from Vault KV v2.
//
// The SecretRef must have:
//   - Scheme == "vault"
//   - Host    (the KV v2 mount name)
//   - Path    (the secret path within the mount)
//   - Field   (optional) selects one key from the data map
//
// If Field is empty and the data map has exactly one key, the single
// value is auto-resolved. If Field is empty and the map has zero or
// more than one key, ErrInvalidURI is returned.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	// Lock-free closed check first, so a closed provider always
	// reports an error regardless of the caller's context state.
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("vault: provider closed")
	}

	// Honor an already-canceled context before mutex acquisition.
	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Validate ref fields before touching the client, so that
	// zero-value providers (nil client) still report validation
	// errors correctly.
	if ref.Scheme != "vault" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault URI missing mount (host)", secrets.ErrInvalidURI)
	}
	if ref.Path == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault URI missing secret path", secrets.ErrInvalidURI)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Re-check closed after acquiring RLock to close the TOCTOU gap.
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("vault: provider closed")
	}

	// The KV v2 helper adds the "data/" prefix internally, so callers
	// should pass the logical path (e.g. "github", not "data/github").
	// However, the parent spec and existing ParseRef tests use the
	// "data/" form, so we strip it for compatibility.
	path := ref.Path
	if strings.HasPrefix(path, "data/") {
		path = strings.TrimPrefix(path, "data/")
	}

	kvSecret, err := p.client.KVv2(ref.Host).Get(ctx, path)
	if err != nil {
		return secrets.SecretValue{}, mapVaultError(err)
	}

	data := kvSecret.Data
	if data == nil {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault returned nil data", secrets.ErrNotFound)
	}

	// Field extraction.
	var rawVal interface{}
	if ref.Field != "" {
		val, ok := data[ref.Field]
		if !ok {
			return secrets.SecretValue{}, fmt.Errorf("%w: field %q not found in vault secret", secrets.ErrNotFound, ref.Field)
		}
		rawVal = val
	} else {
		switch len(data) {
		case 0:
			return secrets.SecretValue{}, fmt.Errorf("%w: vault secret has no fields and no field specified", secrets.ErrInvalidURI)
		case 1:
			for _, v := range data {
				rawVal = v
			}
		default:
			return secrets.SecretValue{}, fmt.Errorf("%w: vault secret has %d fields; specify #field in the URI", secrets.ErrInvalidURI, len(data))
		}
	}

	// Build version string from metadata.
	var version string
	if kvSecret.VersionMetadata != nil {
		version = strconv.Itoa(kvSecret.VersionMetadata.Version)
	}

	// Extract lease info from the raw secret if available.
	var ttl time.Duration
	var leaseID string
	if kvSecret.Raw != nil {
		if kvSecret.Raw.LeaseDuration > 0 {
			ttl = time.Duration(kvSecret.Raw.LeaseDuration) * time.Second
		}
		leaseID = kvSecret.Raw.LeaseID
	}

	return secrets.SecretValue{
		Value:     toBytes(rawVal),
		TTL:       ttl,
		LeaseID:   leaseID,
		Version:   version,
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider as closed and, if we own the token,
// revokes it. Safe to call concurrently — all callers block until
// shutdown completes, then subsequent calls are no-ops.
func (p *Provider) Close() error {
	// Set the closed flag so Fetch rejects new calls immediately.
	p.closed.Store(true)

	// Acquire write lock to wait for any in-flight Fetch to finish.
	p.mu.Lock()
	defer p.mu.Unlock()

	// Only do cleanup once (idempotent).
	if p.client == nil {
		return nil
	}

	var revokeErr error
	if p.ownedToken {
		revokeErr = p.client.Auth().Token().RevokeSelf("")
		if revokeErr != nil {
			revokeErr = fmt.Errorf("vault: revoking owned token: %w", revokeErr)
		}
	}
	p.client = nil
	return revokeErr
}

// validateConfig validates the Config at construction time.
func validateConfig(cfg Config) error {
	if cfg.Address == "" {
		return fmt.Errorf("vault: address is required")
	}
	switch cfg.Auth.Method {
	case "token":
		if cfg.Auth.Token != "" && cfg.Auth.TokenRef != nil {
			return fmt.Errorf("vault: token and token_ref are mutually exclusive")
		}
		if cfg.Auth.Token == "" && cfg.Auth.TokenRef == nil {
			return fmt.Errorf("vault: token or token_ref is required for token auth")
		}
	case "approle":
		if cfg.Auth.RoleID != "" && cfg.Auth.RoleIDRef != nil {
			return fmt.Errorf("vault: role_id and role_id_ref are mutually exclusive")
		}
		if cfg.Auth.RoleID == "" && cfg.Auth.RoleIDRef == nil {
			return fmt.Errorf("vault: role_id or role_id_ref is required for approle auth")
		}
		if cfg.Auth.SecretID != "" && cfg.Auth.SecretIDRef != nil {
			return fmt.Errorf("vault: secret_id and secret_id_ref are mutually exclusive")
		}
		if cfg.Auth.SecretID == "" && cfg.Auth.SecretIDRef == nil {
			return fmt.Errorf("vault: secret_id or secret_id_ref is required for approle auth")
		}
	case "kubernetes":
		if cfg.Auth.KubeRole == "" {
			return fmt.Errorf("vault: kube_role is required for kubernetes auth")
		}
	case "":
		return fmt.Errorf("vault: auth method is required")
	default:
		return fmt.Errorf("vault: unsupported auth method %q", cfg.Auth.Method)
	}
	return nil
}

// resolveAuthRefs resolves any chained SecretRef fields in the auth
// config via the provided resolver. Literal values are returned
// as-is. Resolved values are zeroed after extraction.
func resolveAuthRefs(ctx context.Context, auth AuthConfig, resolver secrets.RefResolver) (token, roleID, secretID string, err error) {
	// Check if auth chaining is needed but no resolver was provided.
	needsResolver := (auth.TokenRef != nil && auth.Token == "") ||
		(auth.RoleIDRef != nil && auth.RoleID == "") ||
		(auth.SecretIDRef != nil && auth.SecretID == "")
	if needsResolver && resolver == nil {
		return "", "", "", fmt.Errorf("vault: auth config uses chained refs but no resolver was provided")
	}

	switch auth.Method {
	case "token":
		if auth.Token != "" {
			token = auth.Token
		} else if auth.TokenRef != nil {
			sv, resolveErr := resolver(ctx, *auth.TokenRef)
			if resolveErr != nil {
				return "", "", "", fmt.Errorf("resolving token ref: %w", resolveErr)
			}
			token = string(sv.Value)
			sv.Zero()
		}

	case "approle":
		if auth.RoleID != "" {
			roleID = auth.RoleID
		} else if auth.RoleIDRef != nil {
			sv, resolveErr := resolver(ctx, *auth.RoleIDRef)
			if resolveErr != nil {
				return "", "", "", fmt.Errorf("resolving role_id ref: %w", resolveErr)
			}
			roleID = string(sv.Value)
			sv.Zero()
		}
		if auth.SecretID != "" {
			secretID = auth.SecretID
		} else if auth.SecretIDRef != nil {
			sv, resolveErr := resolver(ctx, *auth.SecretIDRef)
			if resolveErr != nil {
				return "", "", "", fmt.Errorf("resolving secret_id ref: %w", resolveErr)
			}
			secretID = string(sv.Value)
			sv.Zero()
		}

	case "kubernetes":
		// No chained refs; uses service account token file.
	}
	return token, roleID, secretID, nil
}

// mapVaultError translates a vault/api error to the appropriate
// secrets sentinel error.
func mapVaultError(err error) error {
	// The KV v2 helper returns ErrSecretNotFound when the secret
	// path does not exist (nil response from Logical().Read).
	if errors.Is(err, vaultapi.ErrSecretNotFound) {
		return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
	}

	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s", secrets.ErrNotFound, respErr.Error())
		case http.StatusForbidden:
			return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, respErr.Error())
		}
	}
	return fmt.Errorf("vault: %w", err)
}

// mapAuthError is like mapVaultError but also treats HTTP 400 as
// ErrUnauthorized, since Vault auth endpoints return 400 for bad
// credentials (e.g. invalid AppRole role_id/secret_id).
func mapAuthError(err error) error {
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusBadRequest, http.StatusForbidden:
			return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, respErr.Error())
		}
	}
	return fmt.Errorf("vault: %w", err)
}

// toBytes converts a value to []byte. Strings are converted
// directly; everything else is JSON-marshaled.
func toBytes(v interface{}) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(fmt.Sprintf("%v", v))
	}
	return b
}
