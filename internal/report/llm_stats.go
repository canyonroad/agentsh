package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// LLMLogEntry is a union type for request and response log entries.
// The type is determined by which fields are present.
type LLMLogEntry struct {
	// Common fields
	SessionID string `json:"session_id"`

	// Request-specific fields
	ID      string         `json:"id,omitempty"`
	Dialect string         `json:"dialect,omitempty"`
	Request *LLMRequestInfo `json:"request,omitempty"`
	DLP     *LLMDLPInfo    `json:"dlp,omitempty"`

	// Response-specific fields
	RequestID  string          `json:"request_id,omitempty"`
	DurationMs int64           `json:"duration_ms,omitempty"`
	Response   *LLMResponseInfo `json:"response,omitempty"`
	Usage      *LLMUsage       `json:"usage,omitempty"`
}

// LLMRequestInfo contains request details from the log.
type LLMRequestInfo struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	BodySize int    `json:"body_size"`
}

// LLMResponseInfo contains response details from the log.
type LLMResponseInfo struct {
	Status   int `json:"status"`
	BodySize int `json:"body_size"`
}

// LLMUsage contains token usage from the log.
type LLMUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// LLMDLPInfo contains DLP redaction info from the log.
type LLMDLPInfo struct {
	Redactions []LLMRedaction `json:"redactions"`
}

// LLMRedaction represents a single redaction from the log.
type LLMRedaction struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// isRequest returns true if this entry is a request (has ID field).
func (e *LLMLogEntry) isRequest() bool {
	return e.ID != ""
}

// isResponse returns true if this entry is a response (has RequestID field).
func (e *LLMLogEntry) isResponse() bool {
	return e.RequestID != ""
}

// isError returns true if the response indicates an error (status >= 400).
func (e *LLMLogEntry) isError() bool {
	return e.Response != nil && e.Response.Status >= 400
}

// ParseLLMRequestsFile parses an llm-requests.jsonl file and returns aggregated stats.
// Returns nil stats (not an error) if the file doesn't exist.
func ParseLLMRequestsFile(path string) (*LLMUsageStats, *DLPEventStats, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("open llm requests file: %w", err)
	}
	defer file.Close()

	// Track stats by provider (dialect)
	providerStats := make(map[string]*ProviderUsage)

	// Track DLP redactions by type
	redactionCounts := make(map[string]int)

	// Track request dialects for correlating responses
	requestDialects := make(map[string]string)

	scanner := bufio.NewScanner(file)
	// Set a larger buffer for potentially large log lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		var entry LLMLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			// Skip malformed lines
			continue
		}

		if entry.isRequest() {
			// Store dialect for this request
			requestDialects[entry.ID] = entry.Dialect

			// Count DLP redactions
			if entry.DLP != nil {
				for _, r := range entry.DLP.Redactions {
					redactionCounts[r.Type] += r.Count
				}
			}
		} else if entry.isResponse() {
			// Look up the dialect from the original request
			dialect := requestDialects[entry.RequestID]
			if dialect == "" {
				dialect = "unknown"
			}

			// Ensure provider entry exists
			if providerStats[dialect] == nil {
				providerStats[dialect] = &ProviderUsage{
					Provider: formatProviderName(dialect),
				}
			}

			ps := providerStats[dialect]
			ps.Requests++
			ps.DurationMs += entry.DurationMs

			if entry.Usage != nil {
				ps.TokensIn += entry.Usage.InputTokens
				ps.TokensOut += entry.Usage.OutputTokens
			}

			if entry.isError() {
				ps.Errors++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan llm requests file: %w", err)
	}

	// Build LLM usage stats
	var llmStats *LLMUsageStats
	if len(providerStats) > 0 {
		llmStats = &LLMUsageStats{
			Providers: make([]ProviderUsage, 0, len(providerStats)),
		}

		// Sort providers alphabetically for consistent output
		providers := make([]string, 0, len(providerStats))
		for p := range providerStats {
			providers = append(providers, p)
		}
		sort.Strings(providers)

		for _, p := range providers {
			ps := providerStats[p]
			llmStats.Providers = append(llmStats.Providers, *ps)
			llmStats.Total.Requests += ps.Requests
			llmStats.Total.TokensIn += ps.TokensIn
			llmStats.Total.TokensOut += ps.TokensOut
			llmStats.Total.Errors += ps.Errors
			llmStats.Total.DurationMs += ps.DurationMs
		}
	}

	// Build DLP stats
	var dlpStats *DLPEventStats
	if len(redactionCounts) > 0 {
		dlpStats = &DLPEventStats{
			Redactions: make([]RedactionCount, 0, len(redactionCounts)),
		}

		// Sort redaction types alphabetically for consistent output
		types := make([]string, 0, len(redactionCounts))
		for t := range redactionCounts {
			types = append(types, t)
		}
		sort.Strings(types)

		for _, t := range types {
			count := redactionCounts[t]
			dlpStats.Redactions = append(dlpStats.Redactions, RedactionCount{
				Type:  t,
				Count: count,
			})
			dlpStats.Total += count
		}
	}

	return llmStats, dlpStats, nil
}

// formatProviderName converts a dialect to a display name.
func formatProviderName(dialect string) string {
	switch dialect {
	case "anthropic":
		return "Anthropic"
	case "openai":
		return "OpenAI"
	case "chatgpt":
		return "ChatGPT"
	default:
		if dialect == "" || dialect == "unknown" {
			return "Unknown"
		}
		return dialect
	}
}
