package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LLMLogEntry represents either a request or response log entry.
// The type is determined by which fields are present.
type LLMLogEntry struct {
	// Request-specific fields
	ID        string       `json:"id,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
	Dialect   string       `json:"dialect,omitempty"`
	Request   *LLMRequest  `json:"request,omitempty"`
	DLP       *LLMDLPInfo  `json:"dlp,omitempty"`

	// Response-specific fields
	RequestID  string       `json:"request_id,omitempty"`
	DurationMs int64        `json:"duration_ms,omitempty"`
	Response   *LLMResponse `json:"response,omitempty"`
	Usage      *LLMUsage    `json:"usage,omitempty"`
}

// LLMRequest contains request details.
type LLMRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// LLMResponse contains response details.
type LLMResponse struct {
	Status int `json:"status"`
}

// LLMUsage contains token usage.
type LLMUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// LLMDLPInfo contains DLP redaction info.
type LLMDLPInfo struct {
	Redactions []LLMRedaction `json:"redactions"`
}

// LLMRedaction represents a single redaction.
type LLMRedaction struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// isRequest returns true if this entry is a request (has ID field).
func (e *LLMLogEntry) isRequest() bool {
	return e.ID != "" && e.RequestID == ""
}

// isResponse returns true if this entry is a response (has RequestID field).
func (e *LLMLogEntry) isResponse() bool {
	return e.RequestID != ""
}

// LLMLogRow represents a combined request+response for display.
type LLMLogRow struct {
	ID           string
	Timestamp    time.Time
	Dialect      string
	Path         string
	Status       int
	DurationMs   int64
	InputTokens  int
	OutputTokens int
	Redactions   int
}

// FormatLLMLogRow formats a log row for display.
// Format: req_001  10:30:01  anthropic  /v1/messages  200  1.2s  150→892 tokens  [2 redactions]
func FormatLLMLogRow(row LLMLogRow) string {
	// Format duration
	duration := fmt.Sprintf("%.1fs", float64(row.DurationMs)/1000)

	// Format tokens
	tokens := fmt.Sprintf("%d→%d tokens", row.InputTokens, row.OutputTokens)

	// Base format
	result := fmt.Sprintf("%-12s  %s  %-10s  %-25s  %d  %6s  %s",
		row.ID,
		row.Timestamp.Format("15:04:05"),
		row.Dialect,
		truncatePath(row.Path, 25),
		row.Status,
		duration,
		tokens,
	)

	// Add redactions if present
	if row.Redactions > 0 {
		result += fmt.Sprintf("  [%d redactions]", row.Redactions)
	}

	return result
}

// truncatePath truncates a path to maxLen, adding ellipsis if needed.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}

// ReadLLMLogsFromFile reads and parses LLM logs from a JSONL file.
// Returns combined request+response rows for display.
func ReadLLMLogsFromFile(path string) ([]LLMLogRow, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open llm log file: %w", err)
	}
	defer file.Close()

	return ReadLLMLogs(file)
}

// ReadLLMLogs reads and parses LLM logs from a reader.
func ReadLLMLogs(r io.Reader) ([]LLMLogRow, error) {
	// Track requests by ID to correlate with responses
	requests := make(map[string]*LLMLogEntry)
	var rows []LLMLogRow

	scanner := bufio.NewScanner(r)
	// Set a larger buffer for potentially large log lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		var entry LLMLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			// Skip malformed lines
			continue
		}

		if entry.isRequest() {
			// Store request for later correlation
			requests[entry.ID] = &entry
		} else if entry.isResponse() {
			// Find matching request
			req, ok := requests[entry.RequestID]
			if !ok {
				// Orphan response - create minimal row
				row := LLMLogRow{
					ID:         entry.RequestID,
					Timestamp:  entry.Timestamp,
					Dialect:    "unknown",
					Path:       "?",
					Status:     0,
					DurationMs: entry.DurationMs,
				}
				if entry.Response != nil {
					row.Status = entry.Response.Status
				}
				if entry.Usage != nil {
					row.InputTokens = entry.Usage.InputTokens
					row.OutputTokens = entry.Usage.OutputTokens
				}
				rows = append(rows, row)
				continue
			}

			// Create combined row
			row := LLMLogRow{
				ID:         req.ID,
				Timestamp:  req.Timestamp,
				Dialect:    req.Dialect,
				DurationMs: entry.DurationMs,
			}

			if req.Request != nil {
				row.Path = req.Request.Path
			}

			if entry.Response != nil {
				row.Status = entry.Response.Status
			}

			if entry.Usage != nil {
				row.InputTokens = entry.Usage.InputTokens
				row.OutputTokens = entry.Usage.OutputTokens
			}

			// Count total redactions
			if req.DLP != nil {
				for _, r := range req.DLP.Redactions {
					row.Redactions += r.Count
				}
			}

			rows = append(rows, row)

			// Clean up
			delete(requests, entry.RequestID)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan llm log file: %w", err)
	}

	return rows, nil
}

// GetSessionLLMLogPath returns the path to the LLM log file for a session.
// It tries multiple locations in order of preference.
func GetSessionLLMLogPath(sessionID string) (string, error) {
	// Try AGENTSH_SESSIONS_DIR first
	if sessionsDir := os.Getenv("AGENTSH_SESSIONS_DIR"); sessionsDir != "" {
		path := filepath.Join(sessionsDir, sessionID, "llm-requests.jsonl")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Try ~/.local/share/agentsh/sessions (XDG data dir)
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".local", "share", "agentsh", "sessions", sessionID, "llm-requests.jsonl")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Try ~/.agentsh/sessions (legacy location)
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".agentsh", "sessions", sessionID, "llm-requests.jsonl")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("llm log file not found for session %s", sessionID)
}

// DisplayLLMLogs reads and displays LLM logs for a session.
func DisplayLLMLogs(w io.Writer, sessionID string, jsonOutput bool) error {
	path, err := GetSessionLLMLogPath(sessionID)
	if err != nil {
		return err
	}

	rows, err := ReadLLMLogsFromFile(path)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		fmt.Fprintln(w, "No LLM requests logged for this session")
		return nil
	}

	if jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	// Human-readable output
	for _, row := range rows {
		fmt.Fprintln(w, FormatLLMLogRow(row))
	}

	return nil
}
