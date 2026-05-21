package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/audit/kms"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy/signing"
	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/internal/store/eventfilter"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// resolveLogGoawayMessage applies the three-state (nil / false / true)
// semantics to the AuditWatchtowerConfig.LogGoawayMessage field and
// emits the appropriate startup log. It is the single source of truth
// for the resolution logic used by both the production
// buildWatchtowerStore path and the test helper
// ResolveLogGoawayMessageForTest — keeping them in sync so a drift in
// production cannot leave tests green while operators see different
// behavior.
//
// PRD-defined default at this major version (v1) is false.
func resolveLogGoawayMessage(cfgVal *bool, logger *slog.Logger) bool {
	const defaultV = false
	switch {
	case cfgVal == nil:
		logger.Info("watchtower: log_goaway_message omitted; using default",
			"value", defaultV)
		return defaultV
	case *cfgVal:
		logger.Warn("watchtower: log_goaway_message=true; goaway_message text will be logged after client-side sanitization, depends on server-side no-secrets contract",
			"see", "proto/canyonroad/wtp/v1/wtp.proto Goaway.message")
		return true
	default:
		// explicit false — no log
		return false
	}
}

// resolveAgentID returns the agent identifier the WTP store should
// advertise on the wire. Precedence:
//
//  1. TrimSpace(cfg.AgentID) if non-empty.
//  2. os.Hostname() + "-" + os.Getpid() — disambiguates multiple
//     agentsh processes on the same host. A Hostname() error
//     substitutes "unknown" for the host portion.
//
// This is called from buildWatchtowerStore. Keeping it as a small
// pure function lets us unit-test the resolution rungs independently
// of the surrounding KMS/transport machinery.
func resolveAgentID(cfg config.AuditWatchtowerConfig) string {
	id := strings.TrimSpace(cfg.AgentID)
	if id != "" {
		return id
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "unknown"
	}
	return fmt.Sprintf("%s-%d", h, os.Getpid())
}

// buildWatchtowerStore constructs a watchtower.Store from the daemon
// AuditWatchtowerConfig. Returns (nil, nil) when disabled.
//
// Key-material handling: the HMAC key is retrieved from the configured
// Chain key source (file, env, or cloud KMS). HMACKeyID is derived
// from the key fingerprint so the WAL identity and SessionInit agree.
//
// AgentID: cfg.AgentID takes precedence; empty/whitespace-only falls
// back to "<hostname>-<pid>" so multiple agentsh processes on the same
// host receive distinct identities. A Hostname() error substitutes
// "unknown" for the host portion. See resolveAgentID.
func buildWatchtowerStore(
	ctx context.Context,
	cfg config.AuditWatchtowerConfig,
	policies config.PoliciesConfig,
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

	agentID := resolveAgentID(cfg)

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
	logGoaway := resolveLogGoawayMessage(cfg.LogGoawayMessage, slog.Default())

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
		WALDir:                  cfg.StateDir,
		WALSegmentSize:          cfg.WAL.SegmentSize,
		WALMaxTotalSize:         cfg.WAL.MaxTotalBytes,
		Mapper:                  mapper,
		Allocator:               audit.NewSequenceAllocator(),
		AgentID:                 agentID,
		SessionID:               sessionID,
		KeyFingerprint:          hmacKeyID,
		HMACKeyID:               hmacKeyID,
		HMACSecret:              hmacKey,
		HMACAlgorithm:           cfg.Chain.Algorithm,
		BatchMaxRecords:         cfg.Batch.MaxEvents,
		BatchMaxBytes:           cfg.Batch.MaxBytes,
		BatchMaxAge:             cfg.Batch.MaxTimespan,
		HeartbeatEvery:          cfg.Heartbeat.Interval,
		BackoffInitial:          cfg.Backoff.Base,
		BackoffMax:              cfg.Backoff.Max,
		LogGoawayMessage:        logGoaway,
		Endpoint:                cfg.Endpoint,
		TLSEnabled:              tlsEnabled,
		TLSCACertFile:           cfg.TLS.CACertFile,
		TLSCertFile:             cfg.TLS.ClientCertFile,
		TLSKeyFile:              cfg.TLS.ClientKeyFile,
		TLSInsecure:             cfg.TLS.InsecureSkipVerify,
		AuthBearer:              authBearer,
		Filter:                  filter,
		EmitExtendedLossReasons: cfg.EmitExtendedLossReasons,
		CompressionAlgo:         cfg.Batch.Compression,
		ZstdLevel:               cfg.Batch.ZstdLevel,
		GzipLevel:               cfg.Batch.GzipLevel,
	}
	transport.SetEncoderEmitExtendedReasons(opts.EmitExtendedLossReasons)

	// Wire the pushed-policy install path. Disabled when the operator
	// hasn't configured a trust store; logging-only.
	opts.OnPolicyPushed = makePolicyInstallHook(policies)

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
	return buildWatchtowerStore(ctx, cfg, config.PoliciesConfig{}, m)
}

// ResolveLogGoawayMessageForTest exports the three-state resolution logic
// for unit tests. Returns the resolved bool and a string describing which
// case fired ("nil", "explicit_true", "explicit_false").
// Production code uses resolveLogGoawayMessage (the shared helper) inline in
// buildWatchtowerStore — this export is a thin pass-through so tests exercise
// the same code path production uses. The caseLabel return is test-only
// bookkeeping; production does not need it.
func ResolveLogGoawayMessageForTest(cfg config.AuditWatchtowerConfig) (resolved bool, caseLabel string) {
	// Derive the label WITHOUT duplicating the resolution logic: call the
	// shared helper first (with a discard logger so tests stay silent),
	// then classify the pointer state to produce the stable test label.
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolved = resolveLogGoawayMessage(cfg.LogGoawayMessage, discardLogger)
	switch {
	case cfg.LogGoawayMessage == nil:
		caseLabel = "nil"
	case *cfg.LogGoawayMessage:
		caseLabel = "explicit_true"
	default:
		caseLabel = "explicit_false"
	}
	return resolved, caseLabel
}

// ResolveAuthBearerForTest is a thin export of resolveAuthBearer for
// unit tests. Production callers use the unexported resolveAuthBearer.
func ResolveAuthBearerForTest(auth config.WatchtowerAuthConfig) (string, error) {
	return resolveAuthBearer(auth)
}

// ResolveAgentIDForTest is a thin export of resolveAgentID for unit
// tests. Production callers use the unexported resolveAgentID inline
// in buildWatchtowerStore.
func ResolveAgentIDForTest(cfg config.AuditWatchtowerConfig) string {
	return resolveAgentID(cfg)
}

// makePolicyInstallHook returns the OnPolicyPushed callback that runs
// when watchtower ships a policy down via SessionAck. Three responsibilities:
//
//  1. Verify ed25519(content, signature) against the agent's locally
//     configured trust bundle, looked up by SignerKeyID. Empty trust
//     store or unknown key → log WARN and skip the install.
//  2. Confirm sha256(content) matches the wire's ContentHash. A mismatch
//     means the wire was tampered with mid-flight or the operator
//     mis-signed; either way refuse the install.
//  3. Atomically write the policy YAML + companion .sig (in the format
//     internal/policy/signing expects) into {policies.dir}/{policy_id}.yaml.
//     The agent's Manager.Reload() (next session) picks up the new file.
//
// Returns nil when trust-store-based verification is impossible to
// configure (no dir set). The transport then logs the receipt at INFO
// but does NOT install anything — appropriate for deployments where
// the agent enforces a hardcoded local policy and the watchtower
// channel is observation-only.
func makePolicyInstallHook(policies config.PoliciesConfig) func(transport.PolicyPushed) {
	dir := policies.Dir
	trustDir := policies.Signing.TrustStore
	if dir == "" || trustDir == "" {
		return nil
	}
	return func(p transport.PolicyPushed) {
		if p.PolicyID == "" || len(p.Content) == 0 {
			return
		}
		// Reload the trust store on every receipt. The set is small
		// and operators can rotate keys without bouncing agentsh.
		ts, err := signing.LoadTrustStore(trustDir, false)
		if err != nil {
			slog.Warn("policy install: load trust store",
				"trust_store", trustDir, "err", err.Error())
			return
		}
		// Wire-format key IDs use an "ed25519:" prefix; the
		// agent's trust-store key IDs are bare hex (hex(sha256(pub))).
		keyID := strings.TrimPrefix(p.SignerKeyID, "ed25519:")
		kf, err := ts.FindKey(keyID)
		if err != nil {
			slog.Warn("policy install: unknown signer key",
				"signer_key_id", p.SignerKeyID, "err", err.Error())
			return
		}
		pub, err := base64.StdEncoding.DecodeString(kf.PublicKey)
		if err != nil {
			slog.Warn("policy install: decode trust-store public key",
				"key_id", keyID, "err", err.Error())
			return
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), p.Content, p.Signature) {
			slog.Warn("policy install: ed25519 verify failed",
				"key_id", keyID, "policy_id", p.PolicyID)
			return
		}
		// Content-hash double-check. The wire format is "sha256:<hex>".
		want := strings.TrimPrefix(p.ContentHash, "sha256:")
		got := sha256.Sum256(p.Content)
		gotHex := hex.EncodeToString(got[:])
		if !strings.EqualFold(want, gotHex) {
			slog.Warn("policy install: content_hash mismatch",
				"wire_hash", p.ContentHash, "computed_hash", "sha256:"+gotHex)
			return
		}

		yamlPath := filepath.Join(dir, p.PolicyID+".yaml")
		sigPath := yamlPath + ".sig"
		sig := signing.SigFile{
			Version:   1,
			Algorithm: "ed25519",
			KeyID:     keyID,
			Signer:    "watchtower-push",
			SignedAt:  time.Now().UTC().Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(p.Signature),
		}
		sigBytes, _ := json.Marshal(sig)
		// Atomic-write both via tmp+rename so a crash mid-write can't
		// leave the agent's policy dir half-updated.
		if err := atomicWrite(yamlPath, p.Content, 0o644); err != nil {
			slog.Warn("policy install: write policy yaml",
				"path", yamlPath, "err", err.Error())
			return
		}
		if err := atomicWrite(sigPath, sigBytes, 0o644); err != nil {
			slog.Warn("policy install: write policy sig",
				"path", sigPath, "err", err.Error())
			return
		}
		slog.Info("policy install: signature verified, policy written",
			"policy_id", p.PolicyID,
			"policy_version", p.PolicyVersion,
			"yaml_path", yamlPath,
			"sig_path", sigPath,
			"key_id", keyID,
		)
	}
}

// atomicWrite writes content to a sibling .tmp file and renames it
// over the destination so concurrent readers see either the old bytes
// or the new bytes — never a half-written file.
func atomicWrite(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
