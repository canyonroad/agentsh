package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
			defer func() {
				if lockFile != nil {
					_ = closeAndUnlockAuditFile(lockFile)
				}
			}()

			if !force {
				confirmed, err := confirmReset(cmd.InOrStdin(), cmd.OutOrStdout(), reason, legacyArchive, logPath)
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}

			if err := resetIntegrityChain(cmd.Context(), cfg, key, logPath, lockFile, resetOptions{
				Reason:        reason,
				ReasonCode:    reasonCode,
				LegacyArchive: legacyArchive,
				Now:           time.Now,
			}); err != nil {
				return err
			}
			lockFile = nil
			return nil
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

func resetIntegrityChain(ctx context.Context, cfg *config.Config, key []byte, logPath string, lockFile *os.File, opts resetOptions) error {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	if !opts.LegacyArchive {
		if _, err := audit.DiscoverRotationSet(logPath); err != nil {
			return fmt.Errorf("cannot perform in-place reset on incomplete audit rotation set: %w; retry with --legacy-archive", err)
		}
	}

	priorSummary, hasPriorData, err := currentChainSummary(logPath)
	if err != nil {
		return err
	}
	if !opts.LegacyArchive && hasPriorData && priorSummary == nil {
		return fmt.Errorf("cannot capture prior chain summary for in-place reset; retry with --legacy-archive")
	}

	if opts.LegacyArchive {
		stamp := now().UTC().Format("20060102T150405Z")
		if err := archiveRotationSet(logPath, stamp); err != nil {
			return err
		}
	}

	inner, err := jsonl.NewWithLock(logPath, cfg.Audit.Rotation.MaxSizeMB, cfg.Audit.Rotation.MaxBackups, lockFile)
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

	fields := map[string]any{
		"reason":      opts.Reason,
		"reason_code": opts.ReasonCode,
		"new_chain": map[string]any{
			"format_version":  audit.IntegrityFormatVersion,
			"sequence":        0,
			"key_fingerprint": chain.KeyFingerprint(),
		},
	}
	if priorSummary != nil {
		fields["prior_chain_summary"] = priorSummary
	}

	payload, err := json.Marshal(types.Event{
		Type:      "integrity_chain_rotated",
		Timestamp: now().UTC(),
		Fields:    fields,
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

func currentChainSummary(logPath string) (map[string]any, bool, error) {
	files, err := existingRotationFiles(logPath)
	if err != nil {
		return nil, false, err
	}

	_, lastLine, err := readLastNonEmptyLineBestEffort(files)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, len(files) > 0, err
	}

	entry, err := audit.ParseIntegrityEntry(lastLine)
	if err != nil || entry.Integrity == nil {
		return nil, true, nil
	}

	return map[string]any{
		"last_sequence_seen_in_log":   entry.Integrity.Sequence,
		"last_entry_hash_seen_in_log": entry.Integrity.EntryHash,
	}, true, nil
}

func archiveRotationSet(logPath, stamp string) error {
	files, err := existingRotationFiles(logPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		target := logPath + ".legacy." + stamp
		if file.IsBackup {
			target = logPath + ".legacy." + stamp + "." + strconv.Itoa(file.Index)
		}
		if err := os.Rename(file.Path, target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("archive legacy audit log %s: %w", file.Path, err)
		}
	}

	sidecarPath := audit.SidecarPath(logPath)
	if err := os.Rename(sidecarPath, logPath+".legacy."+stamp+".chain"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("archive legacy audit sidecar: %w", err)
	}
	return nil
}

func existingRotationFiles(logPath string) ([]audit.LogFile, error) {
	dir := filepath.Dir(logPath)
	baseName := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read audit rotation dir: %w", err)
	}

	files := make([]audit.LogFile, 0, len(entries)+1)
	if _, err := os.Stat(logPath); err == nil {
		files = append(files, audit.LogFile{Path: logPath})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, baseName+".") {
			continue
		}
		suffix := strings.TrimPrefix(name, baseName+".")
		index, err := strconv.Atoi(suffix)
		if err != nil || index <= 0 {
			continue
		}
		files = append(files, audit.LogFile{
			Path:     filepath.Join(dir, name),
			Index:    index,
			IsBackup: true,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].IsBackup != files[j].IsBackup {
			return files[i].IsBackup
		}
		if files[i].IsBackup {
			return files[i].Index < files[j].Index
		}
		return files[i].Path < files[j].Path
	})
	return files, nil
}

func discoverRotationSetForVerify(logPath string) ([]audit.LogFile, error) {
	dir := filepath.Dir(logPath)
	baseName := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read audit rotation dir: %w", err)
	}

	indexes := make([]int, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, baseName+".") {
			continue
		}
		suffix := strings.TrimPrefix(name, baseName+".")
		index, err := strconv.Atoi(suffix)
		if err != nil {
			continue
		}
		indexes = append(indexes, index)
	}

	sort.Ints(indexes)
	for i, index := range indexes {
		want := i + 1
		if index != want {
			return nil, fmt.Errorf("missing audit log file %s.%d", logPath, want)
		}
	}

	files := make([]audit.LogFile, 0, len(indexes)+1)
	for i := len(indexes) - 1; i >= 0; i-- {
		files = append(files, audit.LogFile{
			Path:     logPath + "." + strconv.Itoa(indexes[i]),
			Index:    indexes[i],
			IsBackup: true,
		})
	}
	if _, err := os.Stat(logPath); err == nil {
		files = append(files, audit.LogFile{
			Path:     logPath,
			Index:    0,
			IsBackup: false,
		})
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", logPath, err)
	}

	return files, nil
}

func readLastNonEmptyLineBestEffort(files []audit.LogFile) (audit.LogFile, []byte, error) {
	if len(files) == 0 {
		return audit.LogFile{}, nil, os.ErrNotExist
	}

	newest := make([]audit.LogFile, 0, len(files))
	var baseFile *audit.LogFile
	for i := range files {
		file := files[i]
		if file.IsBackup {
			newest = append(newest, file)
			continue
		}
		copy := file
		baseFile = &copy
	}
	sort.Slice(newest, func(i, j int) bool {
		return newest[i].Index < newest[j].Index
	})
	if baseFile != nil {
		newest = append([]audit.LogFile{*baseFile}, newest...)
	}

	for _, file := range newest {
		f, err := os.Open(file.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return audit.LogFile{}, nil, fmt.Errorf("open %s: %w", file.Path, err)
		}

		reader := bufio.NewReader(f)
		var last []byte
		for {
			rawLine, readErr := reader.ReadBytes('\n')
			if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = f.Close()
				return audit.LogFile{}, nil, fmt.Errorf("scan %s: %w", file.Path, readErr)
			}

			line := bytes.TrimSpace(rawLine)
			if len(line) == 0 {
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			last = bytes.Clone(line)
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		_ = f.Close()
		if len(last) > 0 {
			return file, last, nil
		}
	}

	return audit.LogFile{}, nil, os.ErrNotExist
}
