// Package audit provides tamper-proof audit logging with HMAC-based integrity chains.
package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/audit/kms"
	"github.com/agentsh/agentsh/internal/config"
)

// IntegrityMetadata contains the tamper-proof chain fields for an audit entry.
type IntegrityMetadata struct {
	FormatVersion int    `json:"format_version"`
	Sequence      int64  `json:"sequence"`
	PrevHash      string `json:"prev_hash"`
	EntryHash     string `json:"entry_hash"`
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

// IntegrityFormatVersion is the JSON metadata format version emitted by Wrap.
const IntegrityFormatVersion = 2

// ErrSequenceOverflow indicates that the chain cannot advance past MaxInt64.
var ErrSequenceOverflow = errors.New("integrity sequence overflow")

// ChainState represents the last written entry in the integrity chain for persistence.
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
		sequence:  -1,
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
	data, err := parseIntegrityPayload(payload)
	if err != nil {
		return nil, err
	}

	// Use canonical JSON (re-marshaled) for HMAC to ensure verifiability.
	// Go's json.Marshal produces deterministic output with sorted keys.
	canonicalPayload, err := marshalCanonicalPayload(data)
	if err != nil {
		return nil, err
	}

	if c.sequence == math.MaxInt64 {
		return nil, ErrSequenceOverflow
	}
	nextSequence := c.sequence + 1

	// Compute HMAC of: format_version || sequence || prev_hash || canonical_payload
	entryHash, err := c.computeHash(IntegrityFormatVersion, nextSequence, c.prevHash, canonicalPayload)
	if err != nil {
		return nil, err
	}

	// Create integrity metadata
	meta := IntegrityMetadata{
		FormatVersion: IntegrityFormatVersion,
		Sequence:      nextSequence,
		PrevHash:      c.prevHash,
		EntryHash:     entryHash,
	}

	// Add integrity field to payload
	data["integrity"] = meta

	// Marshal the result
	result, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapped payload: %w", err)
	}

	// Record the most recent wrapped entry. State() reflects the last durable
	// entry once callers persist or explicitly Restore after a failed write.
	c.sequence = nextSequence
	c.prevHash = entryHash

	return result, nil
}

// State returns the last written chain state for persistence.
func (c *IntegrityChain) State() ChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ChainState{
		Sequence: c.sequence,
		PrevHash: c.prevHash,
	}
}

// Restore restores the chain state after a restart.
// The sequence must be the last written entry so the next Wrap continues at sequence+1.
func (c *IntegrityChain) Restore(sequence int64, prevHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = sequence
	c.prevHash = prevHash
}

// KeyFingerprint returns a stable SHA-256 fingerprint prefix for an HMAC key.
func KeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:16])
}

// KeyFingerprint returns a stable SHA-256 fingerprint prefix for the chain key.
func (c *IntegrityChain) KeyFingerprint() string {
	return KeyFingerprint(c.key)
}

// VerifyHash recomputes the canonical payload hash using the chain key and format version.
func (c *IntegrityChain) VerifyHash(formatVersion int, sequence int64, prevHash string, payload []byte, expectedHash string) (bool, error) {
	return VerifyHash(c.key, c.algorithm, formatVersion, sequence, prevHash, payload, expectedHash)
}

// VerifyWrapped verifies a wrapped payload, including integrity metadata.
func (c *IntegrityChain) VerifyWrapped(wrapped []byte) (bool, error) {
	return VerifyWrapped(c.key, c.algorithm, wrapped)
}

// VerifyHash recomputes an entry hash using canonical JSON payload encoding.
func VerifyHash(key []byte, algorithm string, formatVersion int, sequence int64, prevHash string, payload []byte, expectedHash string) (bool, error) {
	data, err := parseIntegrityPayload(payload)
	if err != nil {
		return false, err
	}
	delete(data, "integrity")
	canonicalPayload, err := marshalCanonicalPayload(data)
	if err != nil {
		return false, err
	}
	actualHash, err := computeIntegrityHash(key, algorithm, formatVersion, sequence, prevHash, canonicalPayload)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(actualHash), []byte(expectedHash)), nil
}

// VerifyWrapped verifies the integrity metadata and payload in a wrapped audit entry.
func VerifyWrapped(key []byte, algorithm string, wrapped []byte) (bool, error) {
	data, err := parseIntegrityPayloadUseNumber(wrapped)
	if err != nil {
		return false, err
	}

	meta, ok := integrityMetadataFromMap(data["integrity"])
	if !ok {
		return false, nil
	}

	delete(data, "integrity")
	canonicalPayload, err := marshalCanonicalPayload(data)
	if err != nil {
		return false, err
	}
	actualHash, err := computeIntegrityHash(key, algorithm, meta.FormatVersion, meta.Sequence, meta.PrevHash, canonicalPayload)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(actualHash), []byte(meta.EntryHash)), nil
}

// computeHash computes the HMAC of: format_version || sequence || prev_hash || payload
func (c *IntegrityChain) computeHash(formatVersion int, sequence int64, prevHash string, payload []byte) (string, error) {
	return computeIntegrityHash(c.key, c.algorithm, formatVersion, sequence, prevHash, payload)
}

func parseIntegrityPayload(payload []byte) (map[string]any, error) {
	var data map[string]any
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return data, nil
}

func parseIntegrityPayloadUseNumber(payload []byte) (map[string]any, error) {
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse payload: trailing data after JSON object")
		}
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return data, nil
}

func marshalCanonicalPayload(data map[string]any) ([]byte, error) {
	canonicalPayload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("canonical marshal: %w", err)
	}
	return canonicalPayload, nil
}

func computeIntegrityHash(key []byte, algorithm string, formatVersion int, sequence int64, prevHash string, payload []byte) (string, error) {
	var h hash.Hash
	switch algorithm {
	case "":
		h = hmac.New(sha256.New, key)
	case "hmac-sha512":
		h = hmac.New(sha512.New, key)
	default: // hmac-sha256
		if algorithm != "hmac-sha256" {
			return "", fmt.Errorf("unsupported algorithm %q: use hmac-sha256 or hmac-sha512", algorithm)
		}
		h = hmac.New(sha256.New, key)
	}

	// Write format version as string
	h.Write([]byte(strconv.Itoa(formatVersion)))
	// Write separator
	h.Write([]byte("|"))
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

	return hex.EncodeToString(h.Sum(nil)), nil
}

func integrityMetadataFromMap(v any) (IntegrityMetadata, bool) {
	integrity, ok := v.(map[string]any)
	if !ok {
		return IntegrityMetadata{}, false
	}

	formatVersion, ok := jsonInt(integrity["format_version"])
	if !ok {
		return IntegrityMetadata{}, false
	}
	sequence, ok := jsonInt64(integrity["sequence"])
	if !ok {
		return IntegrityMetadata{}, false
	}
	prevHash, ok := integrity["prev_hash"].(string)
	if !ok {
		return IntegrityMetadata{}, false
	}
	entryHash, ok := integrity["entry_hash"].(string)
	if !ok {
		return IntegrityMetadata{}, false
	}

	return IntegrityMetadata{
		FormatVersion: formatVersion,
		Sequence:      sequence,
		PrevHash:      prevHash,
		EntryHash:     entryHash,
	}, true
}

func jsonInt(v any) (int, bool) {
	n, ok := jsonInt64(v)
	if !ok {
		return 0, false
	}
	return int(n), true
}

func jsonInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		value, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return value, true
	case float64:
		if n != math.Trunc(n) {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}
