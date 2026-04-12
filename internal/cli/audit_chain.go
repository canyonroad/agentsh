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
			if cfg.Audit.Output == "" {
				return fmt.Errorf("audit log output is not configured")
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
			if cfg.Audit.Output == "" {
				return fmt.Errorf("audit log output is not configured")
			}
			resolvedReasonCode, err := resolveResetReasonCode(reasonCode, legacyArchive)
			if err != nil {
				return err
			}
			key, closeKey, err := loadAuditIntegrityKey(cmd.Context(), cfg.Audit.Integrity)
			if err != nil {
				return fmt.Errorf("load audit integrity key: %w", err)
			}
			defer func() { _ = closeKey() }()

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
				ReasonCode:    resolvedReasonCode,
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
	cmd.Flags().StringVar(&reasonCode, "reason-code", "", "Structured reset reason code (sidecar_missing, sidecar_corrupt, key_rotated, legacy_archived, manual_reset, post_tamper_recovery)")
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

	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
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
	var archivedTo string
	algorithm := cfg.Audit.Integrity.Algorithm
	if algorithm == "" {
		algorithm = "hmac-sha256"
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
	if !opts.LegacyArchive && hasPriorData && opts.ReasonCode == "key_rotated" {
		return fmt.Errorf("cannot acknowledge key rotation with an in-place reset; retry with --legacy-archive")
	}
	if !opts.LegacyArchive && hasPriorData {
		ok, err := visibleRotationSetVerifiesWith(logPath, key, algorithm)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("cannot perform in-place reset with the current audit integrity key/algorithm; retry with --legacy-archive")
		}
	}

	if opts.LegacyArchive {
		stamp := now().UTC().Format("20060102T150405Z")
		archivedTo = logPath + ".legacy." + stamp
		if err := archiveRotationSet(logPath, stamp); err != nil {
			return err
		}
	}

	inner, err := jsonl.NewWithLock(logPath, cfg.Audit.Rotation.MaxSizeMB, cfg.Audit.Rotation.MaxBackups, lockFile)
	if err != nil {
		return err
	}
	defer inner.Close()

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
	if archivedTo != "" {
		fields["prior_log_archived_to"] = archivedTo
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
	supported, err := visibleRotationSetSupportsInPlaceReset(files)
	if err != nil {
		return nil, len(files) > 0, err
	}
	if !supported {
		return nil, true, nil
	}

	entry, err := audit.ParseIntegrityEntry(lastLine)
	if err != nil || entry.Integrity == nil {
		return nil, true, nil
	}
	if entry.Integrity.FormatVersion != audit.IntegrityFormatVersion {
		return nil, true, nil
	}

	return map[string]any{
		"last_sequence_seen_in_log":   entry.Integrity.Sequence,
		"last_entry_hash_seen_in_log": entry.Integrity.EntryHash,
	}, true, nil
}

func visibleRotationSetVerifiesWith(logPath string, key []byte, algorithm string) (bool, error) {
	files, err := audit.DiscoverRotationSet(logPath)
	if err != nil {
		return false, err
	}
	if len(files) == 0 {
		return true, nil
	}

	summary := &verifySummary{fileCount: len(files)}
	state := verifyState{}

	for _, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, fmt.Errorf("open %s: %w", file.Path, err)
		}

		reader := bufio.NewReader(f)
		lineNo := 0
		for {
			rawLine, readErr := reader.ReadBytes('\n')
			if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = f.Close()
				return false, fmt.Errorf("scan %s: %w", file.Path, readErr)
			}

			lineNo++
			line := bytes.TrimSpace(rawLine)
			if len(line) == 0 {
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}

			entry, err := audit.ParseIntegrityEntry(line)
			if err != nil || entry.Integrity == nil {
				_ = f.Close()
				return false, nil
			}
			if entry.Integrity.FormatVersion != audit.IntegrityFormatVersion {
				_ = f.Close()
				return false, nil
			}

			rotationBoundary := entry.Type == "integrity_chain_rotated" &&
				entry.Integrity.Sequence == 0 &&
				entry.Integrity.PrevHash == ""

			if !state.seeded && file.IsBackup && summary.verifiedEntries == 0 {
				state.expectedSequence = entry.Integrity.Sequence
				state.expectedPrevHash = entry.Integrity.PrevHash
				state.seeded = true
			}

			if rotationBoundary {
				if err := verifyRotationBoundary(entry.CanonicalPayload, summary, state, file.IsBackup); err != nil {
					_ = f.Close()
					return false, nil
				}
			} else {
				if !state.seeded {
					state.expectedSequence = 0
					state.expectedPrevHash = ""
					state.seeded = true
				}
				if entry.Integrity.Sequence != state.expectedSequence {
					_ = f.Close()
					return false, nil
				}
				if entry.Integrity.PrevHash != state.expectedPrevHash {
					_ = f.Close()
					return false, nil
				}
			}

			ok, err := audit.VerifyHash(
				key,
				algorithm,
				entry.Integrity.FormatVersion,
				entry.Integrity.Sequence,
				entry.Integrity.PrevHash,
				entry.CanonicalPayload,
				entry.Integrity.EntryHash,
			)
			if err != nil {
				_ = f.Close()
				return false, err
			}
			if !ok {
				_ = f.Close()
				return false, nil
			}

			summary.verifiedEntries++
			state.expectedSequence = entry.Integrity.Sequence + 1
			state.expectedPrevHash = entry.Integrity.EntryHash
			state.seeded = true

			if errors.Is(readErr, io.EOF) {
				break
			}
		}

		if err := f.Close(); err != nil {
			return false, err
		}
	}

	return true, nil
}

func visibleRotationSetSupportsInPlaceReset(files []audit.LogFile) (bool, error) {
	for _, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, fmt.Errorf("open %s: %w", file.Path, err)
		}

		reader := bufio.NewReader(f)
		for {
			rawLine, readErr := reader.ReadBytes('\n')
			if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
				break
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				_ = f.Close()
				return false, fmt.Errorf("scan %s: %w", file.Path, readErr)
			}

			line := bytes.TrimSpace(rawLine)
			if len(line) == 0 {
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}

			entry, err := audit.ParseIntegrityEntry(line)
			if err != nil || entry.Integrity == nil {
				_ = f.Close()
				return false, nil
			}
			if entry.Integrity.FormatVersion != audit.IntegrityFormatVersion {
				_ = f.Close()
				return false, nil
			}

			if errors.Is(readErr, io.EOF) {
				break
			}
		}

		if err := f.Close(); err != nil {
			return false, err
		}
	}

	return true, nil
}

func archiveRotationSet(logPath, stamp string) error {
	files, err := archiveableRotationFiles(logPath)
	if err != nil {
		return err
	}

	// Build the full move set (source → target) including the sidecar.
	type moveOp struct{ src, dst string }
	moves := make([]moveOp, 0, len(files)+1)
	for _, file := range files {
		target := logPath + ".legacy." + stamp
		if file.Suffix != "" {
			target = logPath + ".legacy." + stamp + "." + file.Suffix
		}
		moves = append(moves, moveOp{src: file.Path, dst: target})
	}
	sidecarPath := audit.SidecarPath(logPath)
	moves = append(moves, moveOp{src: sidecarPath, dst: logPath + ".legacy." + stamp + ".chain"})

	// Execute moves, rolling back on failure.
	var completed []moveOp
	for _, m := range moves {
		if err := os.Rename(m.src, m.dst); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			// Roll back already-moved files.
			for _, done := range completed {
				_ = os.Rename(done.dst, done.src)
			}
			return fmt.Errorf("archive legacy audit log %s: %w", m.src, err)
		}
		completed = append(completed, m)
	}
	return nil
}

type archiveableAuditFile struct {
	Path   string
	Suffix string
}

func archiveableRotationFiles(logPath string) ([]archiveableAuditFile, error) {
	dir := filepath.Dir(logPath)
	baseName := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read audit rotation dir: %w", err)
	}

	files := make([]archiveableAuditFile, 0, len(entries)+1)
	if _, err := os.Stat(logPath); err == nil {
		files = append(files, archiveableAuditFile{Path: logPath})
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
		if _, err := strconv.Atoi(suffix); err != nil {
			continue
		}
		files = append(files, archiveableAuditFile{
			Path:   filepath.Join(dir, name),
			Suffix: suffix,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].Suffix == "" || files[j].Suffix == "" {
			return files[i].Suffix == ""
		}
		left, _ := strconv.Atoi(files[i].Suffix)
		right, _ := strconv.Atoi(files[j].Suffix)
		return left > right
	})
	return files, nil
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
		if err != nil || index <= 0 {
			continue
		}
		indexes = append(indexes, index)
	}

	sort.Ints(indexes)
	files := make([]audit.LogFile, 0, len(indexes)+1)
	baseExists := false
	if _, err := os.Stat(logPath); err == nil {
		baseExists = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", logPath, err)
	}

	if baseExists {
		for i, index := range indexes {
			want := i + 1
			if index != want {
				return nil, fmt.Errorf("missing audit log file %s.%d", logPath, want)
			}
		}
	} else {
		for i := 1; i < len(indexes); i++ {
			want := indexes[i-1] + 1
			if indexes[i] != want {
				return nil, fmt.Errorf("missing audit log file %s.%d", logPath, want)
			}
		}
	}

	for i := len(indexes) - 1; i >= 0; i-- {
		files = append(files, audit.LogFile{
			Path:     logPath + "." + strconv.Itoa(indexes[i]),
			Index:    indexes[i],
			IsBackup: true,
		})
	}
	if baseExists {
		files = append(files, audit.LogFile{
			Path:     logPath,
			Index:    0,
			IsBackup: false,
		})
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
