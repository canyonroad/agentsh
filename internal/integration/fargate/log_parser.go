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
// Parses key=value tokens from structured log lines, skipping quoted values
// to avoid false positives from logfmt msg fields containing "action=".
func ParseAuditEvents(lines []string) []AuditEvent {
	var events []AuditEvent

	for _, line := range lines {
		if !strings.Contains(line, "action=") {
			continue
		}

		fields := make(map[string]string)
		for _, token := range strings.Fields(line) {
			// Skip tokens that are part of quoted strings (logfmt values with spaces)
			if strings.ContainsRune(token, '"') {
				continue
			}
			if k, v, ok := strings.Cut(token, "="); ok {
				fields[k] = v
			}
		}

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
