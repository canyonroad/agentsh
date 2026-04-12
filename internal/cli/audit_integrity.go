package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/config"
)

var allowedResetReasonCodes = []string{
	"sidecar_missing",
	"sidecar_corrupt",
	"key_rotated",
	"legacy_archived",
	"manual_reset",
	"post_tamper_recovery",
}

func loadAuditIntegrityKey(ctx context.Context, cfg config.AuditIntegrityConfig) ([]byte, func() error, error) {
	provider, err := audit.NewKMSProvider(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create KMS provider: %w", err)
	}

	key, err := provider.GetKey(ctx)
	if err != nil {
		_ = provider.Close()
		return nil, nil, fmt.Errorf("get key from %s: %w", provider.Name(), err)
	}

	return key, provider.Close, nil
}

func resolveResetReasonCode(reasonCode string, legacyArchive bool) (string, error) {
	code := strings.TrimSpace(reasonCode)
	if code == "" {
		if legacyArchive {
			code = "legacy_archived"
		} else {
			code = "manual_reset"
		}
	}

	for _, allowed := range allowedResetReasonCodes {
		if code == allowed {
			return code, nil
		}
	}

	return "", fmt.Errorf("invalid --reason-code %q (expected one of: %s)", code, strings.Join(allowedResetReasonCodes, ", "))
}
