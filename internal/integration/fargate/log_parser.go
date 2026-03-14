//go:build fargate

package fargate

import (
	"strings"
)

// TestResult represents the outcome of a single test check.
type TestResult struct {
	Pass   bool
	Detail string
}

// WorkloadResult holds parsed results from the workload container logs.
type WorkloadResult struct {
	Results          map[string]TestResult
	SeccompAvailable string
	Complete         bool
}

// ParseWorkloadLogs scans workload log lines for structured test markers.
//
// Expected format: "NAME:PASS:detail" or "NAME:FAIL:detail" or "NAME:WARN:detail"
// WARN is treated as a non-pass (needs investigation).
func ParseWorkloadLogs(lines []string) WorkloadResult {
	result := WorkloadResult{
		Results: make(map[string]TestResult),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "=== DONE ===" {
			result.Complete = true
			continue
		}

		if strings.HasPrefix(line, "SECCOMP:") {
			result.SeccompAvailable = strings.TrimPrefix(line, "SECCOMP:")
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		name, verdict, detail := parts[0], parts[1], parts[2]

		switch name {
		case "SETUP", "CONTROL", "FILECONTROL", "EXEC", "FILE", "NET":
			result.Results[name] = TestResult{
				Pass:   verdict == "PASS",
				Detail: detail,
			}
		}
	}

	return result
}

// AuditEvent represents a parsed audit event from agentsh logs.
type AuditEvent struct {
	Action  string
	Syscall string
	Fields  map[string]string
}

// ParseAuditEvents scans agentsh log lines for audit events.
// Uses quote-aware field parsing to avoid false positives from
// key=value pairs appearing inside quoted logfmt values.
func ParseAuditEvents(lines []string) []AuditEvent {
	var events []AuditEvent

	for _, line := range lines {
		if !strings.Contains(line, "action=") {
			continue
		}

		fields := parseLogFields(line)

		action, ok := fields["action"]
		if !ok {
			continue
		}

		events = append(events, AuditEvent{
			Action:  action,
			Syscall: fields["syscall"],
			Fields:  fields,
		})
	}

	return events
}

// parseLogFields extracts key=value pairs from a structured log line,
// correctly handling quoted values (e.g., msg="some text action=deny").
//
// Supported format: space-delimited key=value or key="quoted value" pairs
// (standard logfmt). Tabs are treated as whitespace. Unclosed quotes consume
// the remainder of the line. Escaped quotes inside values are not supported
// (slog/logfmt does not produce them).
func parseLogFields(line string) map[string]string {
	fields := make(map[string]string)
	i := 0
	for i < len(line) {
		// Skip whitespace (space or tab)
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}

		// Find key (up to '=' or whitespace)
		start := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			// No '=' found — skip this token
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			continue
		}
		key := line[start:i]
		i++ // skip '='

		// Read value (quoted or unquoted)
		if i < len(line) && line[i] == '"' {
			i++ // skip opening quote
			valStart := i
			for i < len(line) && line[i] != '"' {
				i++
			}
			fields[key] = line[valStart:i]
			if i < len(line) {
				i++ // skip closing quote
			}
		} else {
			valStart := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			fields[key] = line[valStart:i]
		}
	}
	return fields
}
