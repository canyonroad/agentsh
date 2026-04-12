package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	tolerateUnsigned   bool
	tolerateTruncation bool
	fromSequence       int64
	configPath         string
}

type verifyState struct {
	expectedSequence int64
	expectedPrevHash string
	seeded           bool
}

type verifySummary struct {
	fileCount       int
	verifiedEntries int
	firstSequence   int64
	lastSequence    int64
	firstLocation   string
	lastLocation    string
	rotationCount   int
}

func newAuditVerifyCmd() *cobra.Command {
	var opts verifyOptions

	cmd := &cobra.Command{
		Use:   "verify <log-file>",
		Short: "Verify integrity chain of the audit log rotation set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadLocalConfig(opts.configPath)
			if err != nil {
				return err
			}
			if !cfg.Audit.Integrity.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "integrity not enabled in this log; nothing to verify")
				return nil
			}

			key, err := audit.LoadKey(cfg.Audit.Integrity.KeyFile, cfg.Audit.Integrity.KeyEnv)
			if err != nil {
				return fmt.Errorf("load audit integrity key: %w", err)
			}
			algorithm := cfg.Audit.Integrity.Algorithm
			if algorithm == "" {
				algorithm = "hmac-sha256"
			}

			files, err := audit.DiscoverRotationSet(args[0])
			if err != nil {
				return err
			}
			if len(files) == 0 {
				if _, err := os.Stat(args[0]); err != nil {
					return fmt.Errorf("open %s: %w", args[0], err)
				}
				files = append(files, audit.LogFile{Path: args[0], Index: 0, IsBackup: false})
			}

			summary, err := verifyIntegrityChain(files, key, algorithm, opts)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "verified %d entries across %d files\n", summary.verifiedEntries, summary.fileCount)
			if summary.verifiedEntries > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "first: seq=%d (%s)\n", summary.firstSequence, summary.firstLocation)
				fmt.Fprintf(cmd.OutOrStdout(), "last:  seq=%d (%s)\n", summary.lastSequence, summary.lastLocation)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.configPath, "config", "", "Path to agentsh config YAML (default: auto-discover)")
	cmd.Flags().BoolVar(&opts.tolerateUnsigned, "tolerate-unsigned", false, "Warn and skip unsigned lines instead of failing")
	cmd.Flags().BoolVar(&opts.tolerateTruncation, "tolerate-truncation", false, "Accept a truncated final line as end-of-chain")
	cmd.Flags().Int64Var(&opts.fromSequence, "from-sequence", 0, "Start verification from this sequence instead of the visible chain origin")

	return cmd
}

func verifyIntegrityChain(files []audit.LogFile, key []byte, algorithm string, opts verifyOptions) (*verifySummary, error) {
	summary := &verifySummary{fileCount: len(files)}
	state := verifyState{}

	record := func(filePath string, lineNo int, meta audit.IntegrityMetadata, eventType string) {
		if summary.verifiedEntries == 0 {
			summary.firstSequence = meta.Sequence
			summary.firstLocation = fmt.Sprintf("%s:%d", filePath, lineNo)
		}
		summary.verifiedEntries++
		summary.lastSequence = meta.Sequence
		summary.lastLocation = fmt.Sprintf("%s:%d", filePath, lineNo)
		if eventType == "integrity_chain_rotated" {
			summary.rotationCount++
		}
	}

	for fileIndex, file := range files {
		f, err := os.Open(file.Path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", file.Path, err)
		}

		scanner := audit.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}

			entry, err := audit.ParseIntegrityEntry(line)
			if err != nil {
				if opts.tolerateTruncation && fileIndex == len(files)-1 && isLikelyTruncation(err) {
					break
				}
				_ = f.Close()
				return nil, fmt.Errorf("malformed JSON at %s:%d: %w", file.Path, lineNo, err)
			}
			if entry.Integrity == nil {
				if opts.tolerateUnsigned {
					continue
				}
				_ = f.Close()
				return nil, fmt.Errorf("unsigned line at %s:%d", file.Path, lineNo)
			}
			if entry.Integrity.FormatVersion < audit.IntegrityFormatVersion {
				_ = f.Close()
				return nil, fmt.Errorf("legacy-format entry at %s:%d", file.Path, lineNo)
			}

			if opts.fromSequence > 0 && !state.seeded {
				if entry.Integrity.Sequence < opts.fromSequence {
					continue
				}
				if entry.Integrity.Sequence != opts.fromSequence {
					_ = f.Close()
					return nil, fmt.Errorf("sequence mismatch at %s:%d: expected starting sequence %d, got %d", file.Path, lineNo, opts.fromSequence, entry.Integrity.Sequence)
				}
				state.expectedSequence = entry.Integrity.Sequence
				state.expectedPrevHash = entry.Integrity.PrevHash
				state.seeded = true
			}
			if !state.seeded && file.IsBackup && summary.verifiedEntries == 0 {
				state.expectedSequence = entry.Integrity.Sequence
				state.expectedPrevHash = entry.Integrity.PrevHash
				state.seeded = true
			}

			rotationBoundary := summary.verifiedEntries > 0 &&
				entry.Type == "integrity_chain_rotated" &&
				entry.Integrity.Sequence == 0 &&
				entry.Integrity.PrevHash == ""

			if !rotationBoundary {
				if !state.seeded {
					state.expectedSequence = 0
					state.expectedPrevHash = ""
					state.seeded = true
				}
				if entry.Integrity.Sequence != state.expectedSequence {
					_ = f.Close()
					return nil, fmt.Errorf("sequence mismatch at %s:%d: expected %d, got %d", file.Path, lineNo, state.expectedSequence, entry.Integrity.Sequence)
				}
				if entry.Integrity.PrevHash != state.expectedPrevHash {
					_ = f.Close()
					return nil, fmt.Errorf("chain broken at %s:%d: expected prev_hash %q, got %q", file.Path, lineNo, state.expectedPrevHash, entry.Integrity.PrevHash)
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
				return nil, fmt.Errorf("verify hash at %s:%d: %w", file.Path, lineNo, err)
			}
			if !ok {
				_ = f.Close()
				return nil, fmt.Errorf("hash mismatch at %s:%d", file.Path, lineNo)
			}

			record(file.Path, lineNo, *entry.Integrity, entry.Type)
			state.expectedSequence = entry.Integrity.Sequence + 1
			state.expectedPrevHash = entry.Integrity.EntryHash
			state.seeded = true
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("scan %s: %w", file.Path, err)
		}
		_ = f.Close()
	}

	return summary, nil
}

func isLikelyTruncation(err error) bool {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return true
	}
	return false
}
