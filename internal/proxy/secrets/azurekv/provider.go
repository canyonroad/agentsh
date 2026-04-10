package azurekv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// kvClient is the subset of the Azure Key Vault API that the
// provider uses. The real *azsecrets.Client satisfies it;
// tests inject a mock.
type kvClient interface {
	GetSecret(ctx context.Context, name string, version string,
		options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// Provider is an Azure Key Vault-backed secrets.SecretProvider.
//
// Provider is safe for concurrent Fetch and Close. Close waits for
// any in-flight Fetch to finish before returning, so the contract
// "after Close returns, Fetch returns an error" holds even under
// concurrent access.
//
// Concurrency design mirrors keyring.Provider and vault.Provider:
//   - closed is an atomic flag checked lock-free on the Fetch fast
//     path.
//   - mu is an RWMutex held for read by Fetch for its entire duration
//     (including the Azure HTTP call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
	client kvClient
}

// testFetchPreLockHook is a test-only seam invoked (when non-nil)
// between Fetch's fast-path closed check and its RLock acquisition.
var testFetchPreLockHook func()

// testFetchPostRLockHook is a test-only seam invoked (when non-nil)
// immediately after Fetch has acquired its RLock and re-verified closed.
var testFetchPostRLockHook func()

// testClosePreLockHook is a test-only seam invoked (when non-nil)
// after Close has stored the closed flag and before it acquires
// the exclusive Lock.
var testClosePreLockHook func()

// New constructs an Azure Key Vault provider.
//
// Steps:
//  1. Validate the config (vault_url required).
//  2. Create the Key Vault client using DefaultAzureCredential.
//  3. Probe connectivity via a dummy GetSecret call.
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("azure-kv: vault_url is required")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kv: creating credential: %w", err)
	}

	client, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kv: creating client: %w", err)
	}

	// Probe connectivity: GetSecret on a nonexistent secret.
	// Auth errors are fatal. Context errors are fatal. NotFound is
	// success (proves auth works). Other errors are non-fatal.
	_, probeErr := client.GetSecret(ctx, "agentsh-probe-nonexistent", "", nil)
	if probeErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var respErr *azcore.ResponseError
		if errors.As(probeErr, &respErr) {
			switch respErr.StatusCode {
			case 401, 403:
				return nil, fmt.Errorf("%w: azure-kv connectivity probe: %s", secrets.ErrUnauthorized, probeErr.Error())
			case 404:
				// NotFound is success -- proves auth works.
			default:
				// Other HTTP errors are non-fatal.
			}
		}
		// Non-ResponseError failures are non-fatal.
	}

	return &Provider{client: client}, nil
}

// newFromClient constructs a Provider with an injected kvClient.
// Used by tests to bypass Azure SDK initialization.
func newFromClient(client kvClient) *Provider {
	return &Provider{client: client}
}

// Name returns "azure-kv". Used in audit events.
func (p *Provider) Name() string { return "azure-kv" }

// Fetch retrieves a secret from Azure Key Vault.
//
// The SecretRef must have:
//   - Scheme == "azure-kv"
//   - Host    (the secret name)
//   - Path    must be empty (Azure KV names only allow alphanumerics and hyphens)
//   - Field   (optional) selects one key from a JSON-valued secret
//
// If Field is empty and the value is a JSON object with exactly one
// key, the single value is auto-resolved. If the value is not JSON
// or has multiple keys, it is returned as-is (plain string).
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("azure-kv: provider closed")
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	if ref.Scheme != "azure-kv" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: azure-kv URI missing secret name (host)", secrets.ErrInvalidURI)
	}
	if ref.Path != "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: azure-kv secret names do not support paths (got %q); use azure-kv://<name> only",
			secrets.ErrInvalidURI, ref.Host+"/"+ref.Path)
	}

	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("azure-kv: provider closed")
	}

	if hook := testFetchPostRLockHook; hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	resp, err := p.client.GetSecret(ctx, ref.Host, "", nil)
	if err != nil {
		return secrets.SecretValue{}, mapAzureError(err)
	}

	if resp.Value == nil {
		return secrets.SecretValue{}, fmt.Errorf("%w: secret has no value", secrets.ErrNotFound)
	}
	raw := []byte(*resp.Value)

	value, err := extractField(raw, ref.Field)
	if err != nil {
		return secrets.SecretValue{}, err
	}

	var version string
	if resp.ID != nil {
		parts := strings.Split(string(*resp.ID), "/")
		if len(parts) > 0 {
			version = parts[len(parts)-1]
		}
	}

	return secrets.SecretValue{
		Value:     value,
		Version:   version,
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider as closed. Safe to call concurrently and
// multiple times -- subsequent calls are no-ops.
func (p *Provider) Close() error {
	p.closed.Store(true)

	if hook := testClosePreLockHook; hook != nil {
		hook()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.client = nil
	return nil
}

// extractField handles field extraction from the raw secret bytes.
//
// If field is non-empty: parse as JSON, look up key, return value.
// If field is empty and value is a JSON object with exactly one key:
// auto-resolve to that key's value. Otherwise return raw bytes as-is.
func extractField(raw []byte, field string) ([]byte, error) {
	if field != "" {
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: cannot extract field %q: value is not JSON: %s",
				secrets.ErrInvalidURI, field, err)
		}
		v, ok := m[field]
		if !ok {
			return nil, fmt.Errorf("%w: field %q not found in secret", secrets.ErrNotFound, field)
		}
		return toBytes(v), nil
	}

	// No field specified -- try auto-resolve for single-key JSON objects.
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err == nil && len(m) == 1 {
		for _, v := range m {
			return toBytes(v), nil
		}
	}

	// Not JSON or multiple keys -- return raw.
	return raw, nil
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

// mapAzureError translates Azure SDK errors to the appropriate
// secrets sentinel errors.
func mapAzureError(err error) error {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 404:
			return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
		case 401, 403:
			return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, err.Error())
		}
	}
	return fmt.Errorf("azure-kv: %w", err)
}
