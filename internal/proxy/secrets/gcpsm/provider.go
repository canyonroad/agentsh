package gcpsm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// smClient is the subset of the GCP Secret Manager API that the
// provider uses. The real *secretmanager.Client satisfies it;
// tests inject a mock.
type smClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest,
		opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// Provider is a GCP Secret Manager-backed secrets.SecretProvider.
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
//     (including the GCP gRPC call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu        sync.RWMutex
	closed    atomic.Bool
	client    smClient
	projectID string
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

// New constructs a GCP Secret Manager provider.
//
// Steps:
//  1. Validate the config (project_id required).
//  2. Create the Secret Manager client using ADC.
//  3. Probe connectivity via a dummy AccessSecretVersion call.
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error) {
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("gcp-sm: project_id is required")
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-sm: creating client: %w", err)
	}

	probeName := fmt.Sprintf("projects/%s/secrets/agentsh-probe-nonexistent/versions/latest", cfg.ProjectID)
	_, probeErr := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: probeName,
	})
	if probeErr != nil {
		if ctx.Err() != nil {
			_ = client.Close()
			return nil, ctx.Err()
		}
		code := status.Code(probeErr)
		if code == codes.Unauthenticated {
			_ = client.Close()
			return nil, fmt.Errorf("%w: gcp-sm connectivity probe: %s", secrets.ErrUnauthorized, probeErr.Error())
		}
		// PermissionDenied is non-fatal: in a least-privilege setup the
		// caller may lack access to the probe secret but still reach their
		// real secrets. NotFound and other codes are also non-fatal.
	}

	return &Provider{client: client, projectID: cfg.ProjectID}, nil
}

// newFromClient constructs a Provider with an injected smClient.
// Used by tests to bypass GCP SDK initialization.
func newFromClient(client smClient, projectID string) *Provider {
	return &Provider{client: client, projectID: projectID}
}

// Name returns "gcp-sm". Used in audit events.
func (p *Provider) Name() string { return "gcp-sm" }

// Fetch retrieves a secret from GCP Secret Manager.
//
// The SecretRef must have:
//   - Scheme == "gcp-sm"
//   - Host    (the secret name or first path segment)
//   - Path    (optional additional path segments, joined with "/")
//   - Field   (optional) selects one key from a JSON-valued secret
//
// If Field is empty and the value is a JSON object with exactly one
// key, the single value is auto-resolved. If the value is not JSON
// or has multiple keys, it is returned as-is (plain string).
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("gcp-sm: provider closed")
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	if ref.Scheme != "gcp-sm" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: gcp-sm URI missing secret name (host)", secrets.ErrInvalidURI)
	}

	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("gcp-sm: provider closed")
	}

	if hook := testFetchPostRLockHook; hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Build secret name from host + path.
	secretName := ref.Host
	if ref.Path != "" {
		secretName = ref.Host + "/" + ref.Path
	}

	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", p.projectID, secretName)

	resp, err := p.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	})
	if err != nil {
		return secrets.SecretValue{}, mapGCPError(err)
	}

	if resp.Payload == nil || len(resp.Payload.Data) == 0 {
		return secrets.SecretValue{}, fmt.Errorf("%w: secret has no payload data", secrets.ErrNotFound)
	}
	raw := resp.Payload.Data

	// Field extraction.
	value, err := extractField(raw, ref.Field)
	if err != nil {
		return secrets.SecretValue{}, err
	}

	var version string
	if parts := strings.Split(resp.Name, "/"); len(parts) > 0 {
		version = parts[len(parts)-1]
	}

	return secrets.SecretValue{
		Value:     value,
		Version:   version,
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider as closed and releases the GCP client.
// Safe to call concurrently and multiple times -- subsequent calls
// are no-ops.
func (p *Provider) Close() error {
	p.closed.Store(true)

	if hook := testClosePreLockHook; hook != nil {
		hook()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		_ = p.client.Close()
		p.client = nil
	}
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

// isGCPAuthError reports whether the gRPC status code is an auth error.
func isGCPAuthError(code codes.Code) bool {
	return code == codes.PermissionDenied || code == codes.Unauthenticated
}

// mapGCPError translates gRPC status errors to the appropriate
// secrets sentinel errors.
func mapGCPError(err error) error {
	code := status.Code(err)
	switch {
	case code == codes.NotFound:
		return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
	case isGCPAuthError(code):
		return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, err.Error())
	default:
		return fmt.Errorf("gcp-sm: %w", err)
	}
}
