package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1Password/connect-sdk-go/connect"
	opSDK "github.com/1Password/connect-sdk-go/onepassword"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// opClient is the interface the provider uses for 1Password operations.
// Local types decouple from the SDK, making the interface mockable
// without SDK dependencies in tests.
type opClient interface {
	GetItemByTitle(title string, vaultUUID string) (mockItem, error)
	GetVaultsByTitle(title string) ([]mockVault, error)
}

// mockItem represents a 1Password item. Used as the opClient interface type.
type mockItem struct {
	Fields []mockItemField
}

// mockItemField represents a field within a 1Password item.
type mockItemField struct {
	Label string
	Value string
}

// mockVault represents a 1Password vault.
type mockVault struct {
	ID   string
	Name string
}

// Provider is a 1Password Connect-backed secrets.SecretProvider.
//
// Provider is safe for concurrent Fetch and Close. Close waits for
// any in-flight Fetch to finish before returning, so the contract
// "after Close returns, Fetch returns an error" holds even under
// concurrent access.
//
// Concurrency design mirrors keyring.Provider, vault.Provider, and
// awssm.Provider:
//   - closed is an atomic flag checked lock-free on the Fetch fast
//     path.
//   - mu is an RWMutex held for read by Fetch for its entire duration
//     (including the 1Password HTTP call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
	client opClient
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

// statusCodeError is an interface for errors that carry an HTTP status code.
type statusCodeError interface {
	GetStatusCode() int
}

// sdkClientAdapter wraps the real 1Password Connect SDK client and
// converts SDK types to the provider's local types.
type sdkClientAdapter struct {
	inner connect.Client
}

func (a *sdkClientAdapter) GetItemByTitle(title string, vaultUUID string) (mockItem, error) {
	item, err := a.inner.GetItemByTitle(title, vaultUUID)
	if err != nil {
		return mockItem{}, wrapOPError(err)
	}
	return convertItem(item), nil
}

func (a *sdkClientAdapter) GetVaultsByTitle(title string) ([]mockVault, error) {
	vaults, err := a.inner.GetVaultsByTitle(title)
	if err != nil {
		return nil, wrapOPError(err)
	}
	result := make([]mockVault, len(vaults))
	for i, v := range vaults {
		result[i] = mockVault{ID: v.ID, Name: v.Name}
	}
	return result, nil
}

func convertItem(item *opSDK.Item) mockItem {
	if item == nil {
		return mockItem{}
	}
	fields := make([]mockItemField, len(item.Fields))
	for i, f := range item.Fields {
		fields[i] = mockItemField{Label: f.Label, Value: f.Value}
	}
	return mockItem{Fields: fields}
}

// sdkHTTPError wraps an SDK error with an HTTP status code so that
// mapOPError can dispatch on status codes uniformly.
type sdkHTTPError struct {
	statusCode int
	inner      error
}

func (e *sdkHTTPError) Error() string      { return e.inner.Error() }
func (e *sdkHTTPError) Unwrap() error      { return e.inner }
func (e *sdkHTTPError) GetStatusCode() int { return e.statusCode }

func wrapOPError(err error) error {
	if err == nil {
		return nil
	}
	var sdkErr *opSDK.Error
	if extractSDKError(err, &sdkErr) {
		return &sdkHTTPError{statusCode: sdkErr.StatusCode, inner: err}
	}
	return err
}

func extractSDKError(err error, target **opSDK.Error) bool {
	// errors.As does not work here because opSDK.Error.Is uses
	// value equality, not type assertion. Walk the chain manually.
	for e := err; e != nil; {
		if sdkErr, ok := e.(*opSDK.Error); ok {
			*target = sdkErr
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// New constructs a 1Password Connect provider.
//
// Steps:
//  1. Validate the config (server_url required, api_key/api_key_ref mutual exclusion).
//  2. Resolve api_key_ref via resolver if set.
//  3. Create the Connect SDK client.
//  4. Probe connectivity via GetVaultsByTitle.
func New(ctx context.Context, cfg Config, resolver secrets.RefResolver) (*Provider, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("op: server_url is required")
	}
	if cfg.APIKey != "" && cfg.APIKeyRef != nil {
		return nil, fmt.Errorf("op: api_key and api_key_ref are mutually exclusive")
	}
	if cfg.APIKey == "" && cfg.APIKeyRef == nil {
		return nil, fmt.Errorf("op: one of api_key or api_key_ref is required")
	}

	apiKey := cfg.APIKey
	if cfg.APIKeyRef != nil {
		if resolver == nil {
			return nil, fmt.Errorf("op: api_key_ref is set but no resolver was provided")
		}
		sv, err := resolver(ctx, *cfg.APIKeyRef)
		if err != nil {
			return nil, fmt.Errorf("op: resolving api_key_ref: %w", err)
		}
		apiKey = string(sv.Value)
		sv.Zero()
	}

	sdkClient := connect.NewClientWithUserAgent(cfg.ServerURL, apiKey, "agentsh")
	adapter := &sdkClientAdapter{inner: sdkClient}

	// Probe connectivity: GetVaultsByTitle with a non-existent title.
	// Auth failures are fatal; not-found (empty result) is expected
	// and non-fatal.
	_, probeErr := adapter.GetVaultsByTitle("agentsh-probe-nonexistent")
	if probeErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		mapped := mapOPError(probeErr)
		if mapped != nil && isOPAuthError(mapped) {
			return nil, fmt.Errorf("%w: op connectivity probe: %s", secrets.ErrUnauthorized, probeErr.Error())
		}
		// Non-auth failure (e.g. network): swallow -- the Connect
		// server may still work for real requests.
	}

	return &Provider{client: adapter}, nil
}

// newFromClient constructs a Provider with an injected opClient.
// Used by tests to bypass SDK initialization.
func newFromClient(client opClient) *Provider {
	return &Provider{client: client}
}

// Name returns "op". Used in audit events.
func (p *Provider) Name() string { return "op" }

// Fetch retrieves a secret from 1Password Connect.
//
// The SecretRef must have:
//   - Scheme == "op"
//   - Host    (the vault name)
//   - Path    (the item title)
//   - Field   (optional) selects one field by label
//
// If Field is empty and the item has exactly one field, the single
// value is auto-resolved. If the item has multiple fields and no
// Field is specified, all fields are JSON-marshaled as a map.
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("op: provider closed")
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	if ref.Scheme != "op" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: op URI missing vault name (host)", secrets.ErrInvalidURI)
	}
	if ref.Path == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: op URI missing item title (path)", secrets.ErrInvalidURI)
	}

	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("op: provider closed")
	}

	if hook := testFetchPostRLockHook; hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Resolve vault by title to get UUID.
	vaults, err := p.client.GetVaultsByTitle(ref.Host)
	if err != nil {
		return secrets.SecretValue{}, mapOPError(err)
	}
	if len(vaults) == 0 {
		return secrets.SecretValue{}, fmt.Errorf("%w: vault %q not found", secrets.ErrNotFound, ref.Host)
	}
	vaultUUID := vaults[0].ID

	// Resolve item by title in vault.
	item, err := p.client.GetItemByTitle(ref.Path, vaultUUID)
	if err != nil {
		return secrets.SecretValue{}, mapOPError(err)
	}

	// Extract value from item fields.
	value, err := extractFieldFromItem(item, ref.Field)
	if err != nil {
		return secrets.SecretValue{}, err
	}

	return secrets.SecretValue{
		Value:     value,
		Version:   "", // 1Password has no version IDs
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

// extractFieldFromItem handles field extraction from a 1Password item.
//
// If field is non-empty: look up by label, return value.
// If field is empty and the item has exactly one field: auto-resolve.
// If field is empty and the item has multiple fields: marshal all as JSON.
// If the item has no fields: return ErrNotFound.
func extractFieldFromItem(item mockItem, field string) ([]byte, error) {
	if len(item.Fields) == 0 {
		return nil, fmt.Errorf("%w: item has no fields", secrets.ErrNotFound)
	}

	if field != "" {
		for _, f := range item.Fields {
			if f.Label == field {
				return []byte(f.Value), nil
			}
		}
		return nil, fmt.Errorf("%w: field %q not found in item", secrets.ErrNotFound, field)
	}

	if len(item.Fields) == 1 {
		return []byte(item.Fields[0].Value), nil
	}

	m := make(map[string]string, len(item.Fields))
	for _, f := range item.Fields {
		m[f.Label] = f.Value
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("op: marshaling item fields: %w", err)
	}
	return b, nil
}

// isOPAuthError reports whether err wraps secrets.ErrUnauthorized.
func isOPAuthError(err error) bool {
	return err != nil && errors.Is(err, secrets.ErrUnauthorized)
}

// mapOPError translates 1Password errors to the appropriate secrets
// sentinel errors.
func mapOPError(err error) error {
	if err == nil {
		return nil
	}
	var sce statusCodeError
	if asStatusCode(err, &sce) {
		switch sce.GetStatusCode() {
		case 404:
			return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
		case 401, 403:
			return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, err.Error())
		}
	}
	return fmt.Errorf("op: %w", err)
}

// asStatusCode walks the error chain looking for a statusCodeError.
func asStatusCode(err error, target *statusCodeError) bool {
	for err != nil {
		if sce, ok := err.(statusCodeError); ok {
			*target = sce
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
