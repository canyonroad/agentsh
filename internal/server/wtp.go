package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

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

	// Auto-generate SessionID when config field is empty. Config docs say
	// session_id is optional; an empty value must not cause a startup failure.
	sessionID := cfg.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s-%d", agentID, time.Now().UnixNano())
	}

	// TLS is ON by default. The caller must explicitly set tls.insecure: true
	// to disable it (e.g. for a local test server). When insecure is true,
	// a WARN is logged at construction time so operators see the choice in
	// their startup logs.
	tlsEnabled := !cfg.TLS.Insecure
	if cfg.TLS.Insecure {
		slog.Warn("watchtower: TLS disabled via tls.insecure=true; traffic is plaintext — do not use in production")
	}

	// Resolve LogGoawayMessage three-state to the transport.Options bool.
	// Defaulting MUST happen here (NOT in config.go's Validate/applyDefaults)
	// so that non-daemon CLI subcommands like `agentsh config show` don't
	// emit operational startup logs.
	const logGoawayDefault = false // PRD-defined default at this major version (v1)
	var logGoaway bool
	switch {
	case cfg.LogGoawayMessage == nil:
		logGoaway = logGoawayDefault
		slog.Default().Info("watchtower: log_goaway_message omitted; using default",
			"value", logGoawayDefault)
	case *cfg.LogGoawayMessage:
		logGoaway = true
		slog.Default().Warn("watchtower: log_goaway_message=true; goaway_message text will be logged after client-side sanitization, depends on server-side no-secrets contract",
			"see", "proto/canyonroad/wtp/v1/wtp.proto Goaway.message")
	default:
		logGoaway = false
		// explicit false — no log
	}

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
		SessionID:       sessionID,
		HMACKeyID:       hmacKeyID,
		HMACSecret:      hmacKey,
		HMACAlgorithm:   cfg.Chain.Algorithm,
		BatchMaxRecords: cfg.Batch.MaxEvents,
		BatchMaxBytes:   cfg.Batch.MaxBytes,
		BatchMaxAge:     cfg.Batch.MaxTimespan,
		HeartbeatEvery:  cfg.Heartbeat.Interval,
		BackoffInitial:  cfg.Backoff.Base,
		BackoffMax:      cfg.Backoff.Max,
		LogGoawayMessage: logGoaway,
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
// The returned token is always whitespace-trimmed; trailing newlines from
// file reads and leading/trailing spaces in env values are stripped.
func resolveAuthBearer(auth config.WatchtowerAuthConfig) (string, error) {
	if auth.TokenFile != "" {
		data, err := os.ReadFile(auth.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %q: %w", auth.TokenFile, err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("watchtower auth: token file %q is empty after whitespace trim", auth.TokenFile)
		}
		return token, nil
	}
	if auth.TokenEnv != "" {
		token := strings.TrimSpace(os.Getenv(auth.TokenEnv))
		if token == "" {
			return "", fmt.Errorf("watchtower auth: token env %q is empty or not set", auth.TokenEnv)
		}
		return token, nil
	}
	// ClientCertAuth: no bearer token; the caller uses TLS client cert.
	return "", nil
}

// BuildWatchtowerStoreForTest is a thin export of buildWatchtowerStore
// for white-box tests. Production callers use buildWatchtowerStore.
func BuildWatchtowerStoreForTest(ctx context.Context, cfg config.AuditWatchtowerConfig, m compact.Mapper) (store.EventStore, error) {
	return buildWatchtowerStore(ctx, cfg, m)
}

// ResolveLogGoawayMessageForTest exports the three-state resolution logic
// for unit tests. Returns the resolved bool and a string describing which
// case fired ("nil", "explicit_true", "explicit_false").
// Production code uses this same logic inline in buildWatchtowerStore.
func ResolveLogGoawayMessageForTest(cfg config.AuditWatchtowerConfig) (resolved bool, caseLabel string) {
	const logGoawayDefault = false
	switch {
	case cfg.LogGoawayMessage == nil:
		return logGoawayDefault, "nil"
	case *cfg.LogGoawayMessage:
		return true, "explicit_true"
	default:
		return false, "explicit_false"
	}
}

// ResolveAuthBearerForTest is a thin export of resolveAuthBearer for
// unit tests. Production callers use the unexported resolveAuthBearer.
func ResolveAuthBearerForTest(auth config.WatchtowerAuthConfig) (string, error) {
	return resolveAuthBearer(auth)
}
