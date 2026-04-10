package awssm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// smClient is the subset of the AWS Secrets Manager API that the
// provider uses. The real *secretsmanager.Client satisfies it;
// tests inject a mock.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput,
		opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Provider is an AWS Secrets Manager-backed secrets.SecretProvider.
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
//     (including the AWS HTTP call) and for write by Close. The
//     write lock ensures Close waits for any in-flight Fetch to
//     finish before returning.
type Provider struct {
	mu     sync.RWMutex
	closed atomic.Bool
	client smClient
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

// New constructs an AWS Secrets Manager provider.
//
// Steps:
//  1. Validate the config (region required).
//  2. Load default AWS config with the specified region.
//  3. Create the Secrets Manager client.
//  4. Probe connectivity via STS GetCallerIdentity.
func New(ctx context.Context, cfg Config, _ secrets.RefResolver) (*Provider, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("aws-sm: region is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("aws-sm: loading AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	// Probe connectivity: STS GetCallerIdentity is permission-neutral —
	// it verifies credentials are valid without requiring access to any
	// specific Secrets Manager resource. Auth failures are fatal (bad
	// credentials will never self-heal). Non-auth failures (e.g. STS
	// endpoint unreachable in a VPC-endpoint-only deployment) are
	// non-fatal — the SM endpoint may still work.
	stsClient := sts.NewFromConfig(awsCfg)
	_, probeErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if probeErr != nil && isAuthError(probeErr) {
		return nil, fmt.Errorf("%w: aws-sm connectivity probe: %s", secrets.ErrUnauthorized, probeErr.Error())
	}

	return &Provider{client: client}, nil
}

// newFromClient constructs a Provider with an injected smClient.
// Used by tests to bypass AWS SDK initialization.
func newFromClient(client smClient) *Provider {
	return &Provider{client: client}
}

// Name returns "aws-sm". Used in audit events.
func (p *Provider) Name() string { return "aws-sm" }

// Fetch retrieves a secret from AWS Secrets Manager.
//
// The SecretRef must have:
//   - Scheme == "aws-sm"
//   - Host    (the secret name or first path segment)
//   - Path    (optional additional path segments, joined with "/")
//   - Field   (optional) selects one key from a JSON-valued secret
//
// If Field is empty and the value is a JSON object with exactly one
// key, the single value is auto-resolved. If the value is not JSON
// or has multiple keys, it is returned as-is (plain string).
func (p *Provider) Fetch(ctx context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("aws-sm: provider closed")
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	if ref.Scheme != "aws-sm" {
		return secrets.SecretValue{}, fmt.Errorf("%w: wrong scheme %q", secrets.ErrInvalidURI, ref.Scheme)
	}
	if ref.Host == "" {
		return secrets.SecretValue{}, fmt.Errorf("%w: aws-sm URI missing secret name (host)", secrets.ErrInvalidURI)
	}

	if hook := testFetchPreLockHook; hook != nil {
		hook()
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed.Load() {
		return secrets.SecretValue{}, fmt.Errorf("aws-sm: provider closed")
	}

	if hook := testFetchPostRLockHook; hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return secrets.SecretValue{}, err
	}

	// Build SecretId from host + path.
	secretID := ref.Host
	if ref.Path != "" {
		secretID = ref.Host + "/" + ref.Path
	}

	output, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return secrets.SecretValue{}, mapAWSError(err)
	}

	// Extract raw value: prefer SecretString, fall back to SecretBinary.
	var raw []byte
	if output.SecretString != nil {
		raw = []byte(*output.SecretString)
	} else if output.SecretBinary != nil {
		raw = output.SecretBinary
	} else {
		return secrets.SecretValue{}, fmt.Errorf("%w: secret has no value", secrets.ErrNotFound)
	}

	// Field extraction.
	value, err := extractField(raw, ref.Field)
	if err != nil {
		return secrets.SecretValue{}, err
	}

	var version string
	if output.VersionId != nil {
		version = *output.VersionId
	}

	return secrets.SecretValue{
		Value:     value,
		Version:   version,
		FetchedAt: time.Now(),
	}, nil
}

// Close marks the provider as closed. Safe to call concurrently and
// multiple times — subsequent calls are no-ops.
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

	// No field specified — try auto-resolve for single-key JSON objects.
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err == nil && len(m) == 1 {
		for _, v := range m {
			return toBytes(v), nil
		}
	}

	// Not JSON or multiple keys — return raw.
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

// isAuthError reports whether err is an AWS auth/credential error.
// Used by both the constructor's STS probe and Fetch's error mapper.
func isAuthError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException",
			"UnrecognizedClientException",
			"InvalidSignatureException",
			"InvalidClientTokenId",
			"SignatureDoesNotMatch",
			"ExpiredTokenException",
			"IncompleteSignature":
			return true
		}
	}
	return false
}

// mapAWSError translates AWS SDK errors to the appropriate secrets
// sentinel errors.
func mapAWSError(err error) error {
	var rnf *types.ResourceNotFoundException
	if errors.As(err, &rnf) {
		return fmt.Errorf("%w: %s", secrets.ErrNotFound, err.Error())
	}

	if isAuthError(err) {
		return fmt.Errorf("%w: %s", secrets.ErrUnauthorized, err.Error())
	}

	return fmt.Errorf("aws-sm: %w", err)
}
