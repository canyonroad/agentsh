// Package audit provides tamper-proof audit logging with HMAC-based integrity chains.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/audit/kms"
	"github.com/agentsh/agentsh/internal/config"
)

// IntegrityMetadata contains the tamper-proof chain fields for an audit entry.
type IntegrityMetadata struct {
	Sequence  int64  `json:"sequence"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

// IntegrityChain maintains HMAC chain state for tamper-proof audit logging.
// Each entry's hash depends on the previous entry, forming a verifiable chain.
type IntegrityChain struct {
	mu        sync.Mutex
	key       []byte
	algorithm string
	sequence  int64
	prevHash  string
}

// MinKeyLength is the minimum recommended key length for HMAC-SHA256.
const MinKeyLength = 32

// ChainState represents the current state of the integrity chain for persistence.
type ChainState struct {
	Sequence int64  `json:"sequence"`
	PrevHash string `json:"prev_hash"`
}

// NewIntegrityChain creates a new integrity chain with the given HMAC key.
// The algorithm defaults to "hmac-sha256" if not specified.
// Returns an error if the key is shorter than MinKeyLength bytes.
func NewIntegrityChain(key []byte) (*IntegrityChain, error) {
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("key too short: got %d bytes, need at least %d", len(key), MinKeyLength)
	}
	return NewIntegrityChainWithAlgorithm(key, "hmac-sha256")
}

// NewIntegrityChainWithAlgorithm creates an integrity chain with a specific algorithm.
// Supported algorithms: "hmac-sha256", "hmac-sha512".
// Returns an error if the key is shorter than MinKeyLength bytes or algorithm is unsupported.
func NewIntegrityChainWithAlgorithm(key []byte, algorithm string) (*IntegrityChain, error) {
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("key too short: got %d bytes, need at least %d", len(key), MinKeyLength)
	}
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}
	switch algorithm {
	case "hmac-sha256", "hmac-sha512":
		// valid
	default:
		return nil, fmt.Errorf("unsupported algorithm %q: use hmac-sha256 or hmac-sha512", algorithm)
	}
	return &IntegrityChain{
		key:       key,
		algorithm: algorithm,
		sequence:  0,
		prevHash:  "",
	}, nil
}

// LoadKey loads an HMAC key from either a file path or an environment variable.
// If keyFile is non-empty, it reads the key from that file.
// Otherwise if keyEnv is non-empty, it reads the key from that environment variable.
// Returns an error if neither source provides a key or if reading fails.
func LoadKey(keyFile, keyEnv string) ([]byte, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file %q: %w", keyFile, err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return nil, fmt.Errorf("key file %q is empty", keyFile)
		}
		return []byte(key), nil
	}

	if keyEnv != "" {
		key := os.Getenv(keyEnv)
		if key == "" {
			return nil, fmt.Errorf("environment variable %q is empty or not set", keyEnv)
		}
		return []byte(key), nil
	}

	return nil, errors.New("no key source specified: provide key_file or key_env")
}

// NewKMSProvider creates a KMS provider from configuration.
func NewKMSProvider(cfg config.AuditIntegrityConfig) (kms.Provider, error) {
	// Determine key source
	source := cfg.KeySource
	if source == "" {
		// Legacy: infer from which fields are set
		if cfg.KeyFile != "" {
			source = "file"
		} else if cfg.KeyEnv != "" {
			source = "env"
		} else if cfg.AWSKMS.KeyID != "" {
			source = "aws_kms"
		} else if cfg.AzureKeyVault.VaultURL != "" {
			source = "azure_keyvault"
		} else if cfg.HashiCorpVault.Address != "" {
			source = "hashicorp_vault"
		} else if cfg.GCPKMS.KeyName != "" {
			source = "gcp_kms"
		}
	}

	kmsCfg := kms.Config{
		Source:  source,
		KeyFile: cfg.KeyFile,
		KeyEnv:  cfg.KeyEnv,

		AWSKeyID:            cfg.AWSKMS.KeyID,
		AWSRegion:           cfg.AWSKMS.Region,
		AWSEncryptedDEKFile: cfg.AWSKMS.EncryptedDEKFile,

		AzureVaultURL:   cfg.AzureKeyVault.VaultURL,
		AzureKeyName:    cfg.AzureKeyVault.KeyName,
		AzureKeyVersion: cfg.AzureKeyVault.KeyVersion,

		VaultAddress:    cfg.HashiCorpVault.Address,
		VaultAuthMethod: cfg.HashiCorpVault.AuthMethod,
		VaultTokenFile:  cfg.HashiCorpVault.TokenFile,
		VaultK8sRole:    cfg.HashiCorpVault.K8sRole,
		VaultAppRoleID:  cfg.HashiCorpVault.AppRoleID,
		VaultSecretID:   cfg.HashiCorpVault.SecretID,
		VaultSecretPath: cfg.HashiCorpVault.SecretPath,
		VaultKeyField:   cfg.HashiCorpVault.KeyField,

		GCPKeyName:          cfg.GCPKMS.KeyName,
		GCPEncryptedDEKFile: cfg.GCPKMS.EncryptedDEKFile,
	}

	return kms.NewProvider(kmsCfg)
}

// NewIntegrityChainFromConfig creates an integrity chain from configuration.
// It uses the configured KMS provider to retrieve the HMAC key.
func NewIntegrityChainFromConfig(ctx context.Context, cfg config.AuditIntegrityConfig) (*IntegrityChain, kms.Provider, error) {
	provider, err := NewKMSProvider(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create KMS provider: %w", err)
	}

	key, err := provider.GetKey(ctx)
	if err != nil {
		provider.Close()
		return nil, nil, fmt.Errorf("get key from %s: %w", provider.Name(), err)
	}

	algorithm := cfg.Algorithm
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}

	chain, err := NewIntegrityChainWithAlgorithm(key, algorithm)
	if err != nil {
		provider.Close()
		return nil, nil, err
	}

	return chain, provider, nil
}

// Wrap adds integrity metadata to an event payload.
// The payload must be valid JSON. Returns a new JSON payload with an "integrity" field.
func (c *IntegrityChain) Wrap(payload []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Parse existing payload
	var data map[string]any
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}

	// Use canonical JSON (re-marshaled) for HMAC to ensure verifiability.
	// Go's json.Marshal produces deterministic output with sorted keys.
	canonicalPayload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("canonical marshal: %w", err)
	}

	// Increment sequence
	c.sequence++

	// Compute HMAC of: sequence || prev_hash || canonical_payload
	entryHash := c.computeHash(c.sequence, c.prevHash, canonicalPayload)

	// Create integrity metadata
	meta := IntegrityMetadata{
		Sequence:  c.sequence,
		PrevHash:  c.prevHash,
		EntryHash: entryHash,
	}

	// Add integrity field to payload
	data["integrity"] = meta

	// Marshal the result
	result, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapped payload: %w", err)
	}

	// Update prevHash for next entry
	c.prevHash = entryHash

	return result, nil
}

// State returns the current chain state for persistence.
func (c *IntegrityChain) State() ChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ChainState{
		Sequence: c.sequence,
		PrevHash: c.prevHash,
	}
}

// Restore restores the chain state after a restart.
// This should be called before processing new events to continue the chain.
func (c *IntegrityChain) Restore(sequence int64, prevHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = sequence
	c.prevHash = prevHash
}

// computeHash computes the HMAC of: sequence || prev_hash || payload
func (c *IntegrityChain) computeHash(sequence int64, prevHash string, payload []byte) string {
	var h hash.Hash
	switch c.algorithm {
	case "hmac-sha512":
		h = hmac.New(sha512.New, c.key)
	default: // hmac-sha256
		h = hmac.New(sha256.New, c.key)
	}

	// Write sequence as string
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	// Write separator
	h.Write([]byte("|"))
	// Write prevHash
	h.Write([]byte(prevHash))
	// Write separator
	h.Write([]byte("|"))
	// Write payload
	h.Write(payload)

	return hex.EncodeToString(h.Sum(nil))
}
