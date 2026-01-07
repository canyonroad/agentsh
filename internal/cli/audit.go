package cli

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log management commands",
	}

	cmd.AddCommand(newAuditVerifyCmd())
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var (
		keyFile   string
		keyEnv    string
		algorithm string
	)

	cmd := &cobra.Command{
		Use:   "verify <log-file>",
		Short: "Verify integrity chain of audit log",
		Long: `Verify the integrity chain of a JSONL audit log file.

This command reads each line of the audit log, checking that:
1. The prev_hash field matches the previous entry's entry_hash
2. The HMAC signature (entry_hash) is correct for the payload

Examples:
  # Verify using a key file
  agentsh audit verify /var/log/agentsh/audit.jsonl --key-file=/etc/agentsh/hmac.key

  # Verify using an environment variable
  export AUDIT_KEY="my-secret-key-32-bytes-long!!!"
  agentsh audit verify audit.jsonl --key-env=AUDIT_KEY

  # Verify using SHA-512 algorithm
  agentsh audit verify audit.jsonl --key-file=/etc/agentsh/hmac.key --algorithm=hmac-sha512`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logPath := args[0]

			// Validate that one of key-file or key-env is provided
			if keyFile == "" && keyEnv == "" {
				return fmt.Errorf("either --key-file or --key-env is required")
			}

			// Validate algorithm
			switch algorithm {
			case "hmac-sha256", "hmac-sha512":
				// valid
			default:
				return fmt.Errorf("unsupported algorithm %q: use hmac-sha256 or hmac-sha512", algorithm)
			}

			// Load the HMAC key
			key, err := audit.LoadKey(keyFile, keyEnv)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}

			// Open the log file
			f, err := os.Open(logPath)
			if err != nil {
				return fmt.Errorf("open log file: %w", err)
			}
			defer f.Close()

			// Verify the chain
			result, err := verifyIntegrityChain(f, key, algorithm)
			if err != nil {
				return err
			}

			// Output results
			fmt.Fprintf(cmd.OutOrStdout(), "Verified %d entries (%d skipped without integrity)\n",
				result.verified, result.skipped)

			if result.chainIntact {
				fmt.Fprintln(cmd.OutOrStdout(), "Chain intact: OK")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Chain BROKEN at entry %d: %s\n",
					result.brokenAt, result.brokenReason)
				return fmt.Errorf("integrity verification failed")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&keyFile, "key-file", "", "Path to HMAC key file")
	cmd.Flags().StringVar(&keyEnv, "key-env", "", "Environment variable containing HMAC key")
	cmd.Flags().StringVar(&algorithm, "algorithm", "hmac-sha256", "HMAC algorithm (hmac-sha256 or hmac-sha512)")

	return cmd
}

// verifyResult holds the outcome of integrity chain verification.
type verifyResult struct {
	verified     int
	skipped      int
	chainIntact  bool
	brokenAt     int
	brokenReason string
}

// integrityEntry represents an entry with integrity metadata.
type integrityEntry struct {
	Integrity struct {
		Sequence  int64  `json:"sequence"`
		PrevHash  string `json:"prev_hash"`
		EntryHash string `json:"entry_hash"`
	} `json:"integrity"`
}

// verifyIntegrityChain reads a JSONL file and verifies the integrity chain.
func verifyIntegrityChain(r io.Reader, key []byte, algorithm string) (*verifyResult, error) {
	result := &verifyResult{
		chainIntact: true,
	}

	scanner := bufio.NewScanner(r)
	// Increase buffer size for potentially long JSON lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB max line size

	var prevEntryHash string
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse the entry to check for integrity field
		var entry integrityEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Not valid JSON, skip
			result.skipped++
			continue
		}

		// Check if entry has integrity field (entry_hash is the indicator)
		if entry.Integrity.EntryHash == "" {
			result.skipped++
			continue
		}

		// Verify prev_hash chain
		if entry.Integrity.PrevHash != prevEntryHash {
			result.chainIntact = false
			result.brokenAt = lineNum
			result.brokenReason = fmt.Sprintf("prev_hash mismatch: expected %q, got %q",
				prevEntryHash, entry.Integrity.PrevHash)
			return result, nil
		}

		// Recompute the HMAC to verify entry_hash
		// Extract the original payload (without integrity field) for HMAC computation
		originalPayload, err := extractOriginalPayload([]byte(line))
		if err != nil {
			result.chainIntact = false
			result.brokenAt = lineNum
			result.brokenReason = fmt.Sprintf("failed to extract payload: %v", err)
			return result, nil
		}

		computedHash := computeEntryHash(key, algorithm, entry.Integrity.Sequence, entry.Integrity.PrevHash, originalPayload)
		if computedHash != entry.Integrity.EntryHash {
			result.chainIntact = false
			result.brokenAt = lineNum
			result.brokenReason = fmt.Sprintf("entry_hash mismatch: computed %q, got %q",
				computedHash, entry.Integrity.EntryHash)
			return result, nil
		}

		// Entry verified successfully
		result.verified++
		prevEntryHash = entry.Integrity.EntryHash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read log file: %w", err)
	}

	return result, nil
}

// extractOriginalPayload removes the integrity field from a JSON entry
// to reconstruct the original payload that was used for HMAC computation.
func extractOriginalPayload(line []byte) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(line, &data); err != nil {
		return nil, err
	}

	// Remove the integrity field
	delete(data, "integrity")

	// Marshal back to JSON
	return json.Marshal(data)
}

// computeEntryHash computes the HMAC of: sequence|prev_hash|payload
// Supports hmac-sha256 and hmac-sha512 algorithms.
func computeEntryHash(key []byte, algorithm string, sequence int64, prevHash string, payload []byte) string {
	var h hash.Hash
	switch algorithm {
	case "hmac-sha512":
		h = hmac.New(sha512.New, key)
	default: // hmac-sha256
		h = hmac.New(sha256.New, key)
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
