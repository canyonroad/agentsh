package server

import (
	"context"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/audit/kms"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/eventfilter"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

// buildWatchtowerStore constructs a watchtower.Store from the daemon
// AuditWatchtowerConfig. Returns (nil, nil) when disabled.
//
// Key-material handling: the HMAC key is retrieved from the configured
// Chain key source (file, env, or cloud KMS). HMACKeyID is derived
// from the key fingerprint so the WAL identity and SessionInit agree.
//
// AgentID: derived from os.Hostname() when not overridable from config
// (AuditWatchtowerConfig carries no explicit agent_id field in Phase 1).
// This gives a stable, human-readable per-host identity.
func buildWatchtowerStore(
	ctx context.Context,
	cfg config.AuditWatchtowerConfig,
	mapper compact.Mapper,
) (store.EventStore, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Resolve the HMAC key via the chain KMS source.
	kmsCfg := chainConfigToKMS(cfg.Chain)
	provider, err := kms.NewProvider(kmsCfg)
	if err != nil {
		return nil, fmt.Errorf("watchtower: chain KMS provider: %w", err)
	}
	defer provider.Close()

	hmacKey, err := provider.GetKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("watchtower: get chain key from %s: %w", provider.Name(), err)
	}

	// Derive a stable key ID from the key material.
	hmacKeyID := audit.KeyFingerprint(hmacKey)

	// Resolve auth bearer token.
	authBearer, err := resolveAuthBearer(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("watchtower: resolve auth token: %w", err)
	}

	// AgentID is not in AuditWatchtowerConfig (Phase 1 gap); derive from hostname.
	agentID, err := os.Hostname()
	if err != nil {
		agentID = "unknown"
	}

	// Infer TLS-enabled from presence of TLS configuration fields.
	tlsEnabled := cfg.TLS.CACertFile != "" || cfg.TLS.ClientCertFile != "" || cfg.TLS.InsecureSkipVerify

	// Build the eventfilter.Filter from config.
	var filter *eventfilter.Filter
	if cfg.Filter.IncludeTypes != nil || cfg.Filter.ExcludeTypes != nil ||
		cfg.Filter.IncludeCategories != nil || cfg.Filter.ExcludeCategories != nil ||
		cfg.Filter.MinRiskLevel != "" {
		filter = &eventfilter.Filter{
			IncludeTypes:      cfg.Filter.IncludeTypes,
			ExcludeTypes:      cfg.Filter.ExcludeTypes,
			IncludeCategories: cfg.Filter.IncludeCategories,
			ExcludeCategories: cfg.Filter.ExcludeCategories,
			MinRiskLevel:      cfg.Filter.MinRiskLevel,
		}
	}

	opts := watchtower.Options{
		WALDir:          cfg.StateDir,
		WALSegmentSize:  cfg.WAL.SegmentSize,
		WALMaxTotalSize: cfg.WAL.MaxTotalBytes,
		Mapper:          mapper,
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         agentID,
		SessionID:       cfg.SessionID,
		HMACKeyID:       hmacKeyID,
		HMACSecret:      hmacKey,
		HMACAlgorithm:   cfg.Chain.Algorithm,
		BatchMaxRecords: cfg.Batch.MaxEvents,
		BatchMaxBytes:   cfg.Batch.MaxBytes,
		BatchMaxAge:     cfg.Batch.MaxTimespan,
		Endpoint:        cfg.Endpoint,
		TLSEnabled:      tlsEnabled,
		TLSCACertFile:   cfg.TLS.CACertFile,
		TLSCertFile:     cfg.TLS.ClientCertFile,
		TLSKeyFile:      cfg.TLS.ClientKeyFile,
		TLSInsecure:     cfg.TLS.InsecureSkipVerify,
		AuthBearer:      authBearer,
		Filter:          filter,
	}

	s, err := watchtower.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("watchtower: %w", err)
	}
	return s, nil
}

// chainConfigToKMS converts WatchtowerChainConfig into a kms.Config that
// mirrors the mapping used by audit.NewKMSProvider for AuditIntegrityConfig.
func chainConfigToKMS(c config.WatchtowerChainConfig) kms.Config {
	source := c.KeySource
	if source == "" {
		switch {
		case c.KeyFile != "":
			source = "file"
		case c.KeyEnv != "":
			source = "env"
		case c.AWSKMS.KeyID != "":
			source = "aws_kms"
		case c.AzureKeyVault.VaultURL != "":
			source = "azure_keyvault"
		case c.HashiCorpVault.Address != "":
			source = "hashicorp_vault"
		case c.GCPKMS.KeyName != "":
			source = "gcp_kms"
		}
	}
	return kms.Config{
		Source:  source,
		KeyFile: c.KeyFile,
		KeyEnv:  c.KeyEnv,

		AWSKeyID:            c.AWSKMS.KeyID,
		AWSRegion:           c.AWSKMS.Region,
		AWSEncryptedDEKFile: c.AWSKMS.EncryptedDEKFile,

		AzureVaultURL:   c.AzureKeyVault.VaultURL,
		AzureKeyName:    c.AzureKeyVault.KeyName,
		AzureKeyVersion: c.AzureKeyVault.KeyVersion,

		VaultAddress:    c.HashiCorpVault.Address,
		VaultAuthMethod: c.HashiCorpVault.AuthMethod,
		VaultTokenFile:  c.HashiCorpVault.TokenFile,
		VaultK8sRole:    c.HashiCorpVault.K8sRole,
		VaultAppRoleID:  c.HashiCorpVault.AppRoleID,
		VaultSecretID:   c.HashiCorpVault.SecretID,
		VaultSecretPath: c.HashiCorpVault.SecretPath,
		VaultKeyField:   c.HashiCorpVault.KeyField,

		GCPKeyName:          c.GCPKMS.KeyName,
		GCPEncryptedDEKFile: c.GCPKMS.EncryptedDEKFile,
	}
}

// resolveAuthBearer loads the bearer token from the configured source.
// Exactly one of TokenFile, TokenEnv, or ClientCertAuth must be configured
// (enforced by config.AuditWatchtowerConfig.validate). ClientCertAuth does
// not yield a bearer token — the mTLS cert is wired in the TLS config.
func resolveAuthBearer(auth config.WatchtowerAuthConfig) (string, error) {
	if auth.TokenFile != "" {
		data, err := os.ReadFile(auth.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %q: %w", auth.TokenFile, err)
		}
		return string(data), nil
	}
	if auth.TokenEnv != "" {
		tok := os.Getenv(auth.TokenEnv)
		if tok == "" {
			return "", fmt.Errorf("token env %q is empty or not set", auth.TokenEnv)
		}
		return tok, nil
	}
	// ClientCertAuth: no bearer token; the caller uses TLS client cert.
	return "", nil
}

// BuildWatchtowerStoreForTest is a thin export of buildWatchtowerStore
// for white-box tests. Production callers use buildWatchtowerStore.
func BuildWatchtowerStoreForTest(ctx context.Context, cfg config.AuditWatchtowerConfig, m compact.Mapper) (store.EventStore, error) {
	return buildWatchtowerStore(ctx, cfg, m)
}
