package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newAuditChainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Audit integrity chain maintenance commands",
	}
	cmd.AddCommand(newAuditChainStatusCmd())
	cmd.AddCommand(newAuditChainResetCmd())
	cmd.AddCommand(newAuditChainVerifyCmd())
	return cmd
}

func newAuditChainStatusCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show persisted audit chain state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadLocalConfig(configPath)
			if err != nil {
				return err
			}
			state, err := audit.ReadSidecar(audit.SidecarPath(cfg.Audit.Output))
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(state)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to agentsh config YAML (default: auto-discover)")
	return cmd
}

func newAuditChainResetCmd() *cobra.Command {
	var (
		configPath    string
		reason        string
		reasonCode    string
		legacyArchive bool
		force         bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset the audit integrity chain and write a conspicuous rotation event",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("reason is required")
			}

			cfg, _, err := loadLocalConfig(configPath)
			if err != nil {
				return err
			}
			key, err := audit.LoadKey(cfg.Audit.Integrity.KeyFile, cfg.Audit.Integrity.KeyEnv)
			if err != nil {
				return err
			}

			logPath := cfg.Audit.Output
			lockFile, err := openAndLockAuditFile(logPath)
			if err != nil {
				return err
			}
			defer func() { _ = closeAndUnlockAuditFile(lockFile) }()

			if !force {
				confirmed, err := confirmReset(cmd.InOrStdin(), cmd.OutOrStdout(), reason, legacyArchive, logPath)
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}

			return resetIntegrityChain(cmd.Context(), cfg, key, logPath, resetOptions{
				Reason:        reason,
				ReasonCode:    reasonCode,
				LegacyArchive: legacyArchive,
				Now:           time.Now,
			})
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to agentsh config YAML (default: auto-discover)")
	cmd.Flags().StringVar(&reason, "reason", "", "Required free-form reason stored in the integrity_chain_rotated event")
	cmd.Flags().StringVar(&reasonCode, "reason-code", "manual_reset", "Structured reset reason code")
	cmd.Flags().BoolVar(&legacyArchive, "legacy-archive", false, "Rename the current log to audit.jsonl.legacy.<timestamp> before starting fresh")
	cmd.Flags().BoolVar(&force, "force", false, "Skip the confirmation prompt")
	return cmd
}

func newAuditChainVerifyCmd() *cobra.Command {
	cmd := newAuditVerifyCmd()
	cmd.Use = "verify <log-file>"
	cmd.Short = "Verify integrity chain of the audit log rotation set"
	return cmd
}

type resetOptions struct {
	Reason        string
	ReasonCode    string
	LegacyArchive bool
	Now           func() time.Time
}

func confirmReset(in io.Reader, out io.Writer, reason string, legacyArchive bool, logPath string) (bool, error) {
	mode := "preserve the current log and append a rotation event"
	if legacyArchive {
		mode = "rename the current log to a legacy archive and start fresh"
	}
	if _, err := fmt.Fprintf(out, "This will reset the audit integrity chain for %s\nMode: %s\nReason: %q\nContinue? [y/N] ", logPath, mode, reason); err != nil {
		return false, err
	}

	var answer string
	if _, err := fmt.Fscanln(in, &answer); err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func resetIntegrityChain(ctx context.Context, cfg *config.Config, key []byte, logPath string, opts resetOptions) error {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	if opts.LegacyArchive {
		archivePath := logPath + ".legacy." + now().UTC().Format("20060102T150405Z")
		if err := os.Rename(logPath, archivePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("archive legacy audit log: %w", err)
		}
	}

	inner, err := jsonl.New(logPath, cfg.Audit.Rotation.MaxSizeMB, cfg.Audit.Rotation.MaxBackups)
	if err != nil {
		return err
	}
	defer inner.Close()

	algorithm := cfg.Audit.Integrity.Algorithm
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}
	chain, err := audit.NewIntegrityChainWithAlgorithm(key, algorithm)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(types.Event{
		Type:      "integrity_chain_rotated",
		Timestamp: now().UTC(),
		Fields: map[string]any{
			"reason":      opts.Reason,
			"reason_code": opts.ReasonCode,
			"new_chain": map[string]any{
				"format_version":  audit.IntegrityFormatVersion,
				"sequence":        0,
				"key_fingerprint": chain.KeyFingerprint(),
			},
		},
	})
	if err != nil {
		return err
	}

	wrapped, err := chain.Wrap(payload)
	if err != nil {
		return err
	}
	if err := inner.WriteRaw(ctx, wrapped); err != nil {
		return err
	}

	state := chain.State()
	return audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: chain.KeyFingerprint(),
		UpdatedAt:      now().UTC(),
	})
}
