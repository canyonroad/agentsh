//go:build fargate

package fargate

import (
	"testing"
)

func TestParseWorkloadLogs_AllPass(t *testing.T) {
	logs := []string{
		"SETUP:PASS:tracer attached",
		"=== POSITIVE CONTROL ===",
		"CONTROL:PASS:allowed command ran",
		"=== FILE WRITE CONTROL ===",
		"FILECONTROL:PASS:write works",
		"=== EXEC TEST ===",
		"EXEC:PASS:wget denied",
		"=== FILE TEST ===",
		"FILE:PASS:write denied",
		"=== NETWORK TEST ===",
		"NET:PASS:connect denied (ConnectionRefusedError)",
		"=== SECCOMP PROBE ===",
		"SECCOMP:AVAILABLE",
		"=== DONE ===",
	}

	result := ParseWorkloadLogs(logs)

	if !result.Complete {
		t.Error("expected complete")
	}
	for _, name := range []string{"SETUP", "CONTROL", "FILECONTROL", "EXEC", "FILE", "NET"} {
		r, ok := result.Results[name]
		if !ok {
			t.Errorf("missing result for %s", name)
			continue
		}
		if !r.Pass {
			t.Errorf("%s: expected pass, got fail: %s", name, r.Detail)
		}
	}
	if result.SeccompAvailable != "AVAILABLE" {
		t.Errorf("seccomp = %q, want AVAILABLE", result.SeccompAvailable)
	}
}

func TestParseWorkloadLogs_ExecFail(t *testing.T) {
	logs := []string{
		"SETUP:PASS:tracer attached",
		"CONTROL:PASS:allowed command ran",
		"FILECONTROL:PASS:write works",
		"EXEC:FAIL:wget ran",
		"FILE:PASS:write denied",
		"NET:PASS:connect denied (OSError)",
		"SECCOMP:UNAVAILABLE",
		"=== DONE ===",
	}

	result := ParseWorkloadLogs(logs)

	if !result.Complete {
		t.Error("expected complete")
	}
	if result.Results["EXEC"].Pass {
		t.Error("EXEC should have failed")
	}
	if result.Results["EXEC"].Detail != "wget ran" {
		t.Errorf("EXEC detail = %q, want 'wget ran'", result.Results["EXEC"].Detail)
	}
	if result.SeccompAvailable != "UNAVAILABLE" {
		t.Errorf("seccomp = %q, want UNAVAILABLE", result.SeccompAvailable)
	}
}

func TestParseWorkloadLogs_Incomplete(t *testing.T) {
	logs := []string{
		"SETUP:PASS:tracer attached",
		"CONTROL:PASS:allowed command ran",
	}

	result := ParseWorkloadLogs(logs)

	if result.Complete {
		t.Error("expected incomplete (no DONE marker)")
	}
	if len(result.Results) != 2 {
		t.Errorf("result count = %d, want 2", len(result.Results))
	}
}

func TestParseWorkloadLogs_SetupFail(t *testing.T) {
	logs := []string{
		"SETUP:FAIL:tracer did not attach within 30s",
	}

	result := ParseWorkloadLogs(logs)

	if result.Results["SETUP"].Pass {
		t.Error("SETUP should have failed")
	}
}

func TestParseWorkloadLogs_MissingControl(t *testing.T) {
	logs := []string{
		"SETUP:PASS:tracer attached",
		"EXEC:PASS:wget denied",
		"=== DONE ===",
	}

	result := ParseWorkloadLogs(logs)

	if _, ok := result.Results["CONTROL"]; ok {
		t.Error("CONTROL should not be present")
	}
}

func TestParseWorkloadLogs_NetWarn(t *testing.T) {
	logs := []string{
		"SETUP:PASS:tracer attached",
		"CONTROL:PASS:allowed command ran",
		"FILECONTROL:PASS:write works",
		"NET:WARN:unexpected error (TimeoutError: timed out)",
		"=== DONE ===",
	}

	result := ParseWorkloadLogs(logs)

	r, ok := result.Results["NET"]
	if !ok {
		t.Fatal("missing NET result")
	}
	if r.Pass {
		t.Error("NET:WARN should not count as pass")
	}
}

func TestParseAuditEvents(t *testing.T) {
	logs := []string{
		`level=INFO msg="audit" action=deny syscall=execve command=wget pid=1234`,
		`level=INFO msg="audit" action=deny syscall=openat path=/etc/shadow.test pid=1234`,
		`level=INFO msg="audit" action=deny syscall=connect addr=169.254.169.254 pid=1234`,
		`level=INFO msg="startup complete"`,
	}

	events := ParseAuditEvents(logs)

	if len(events) != 3 {
		t.Fatalf("event count = %d, want 3", len(events))
	}

	denyCount := 0
	for _, e := range events {
		if e.Action == "deny" {
			denyCount++
		}
	}
	if denyCount != 3 {
		t.Errorf("deny event count = %d, want 3", denyCount)
	}
}

func TestParseAuditEvents_Empty(t *testing.T) {
	logs := []string{
		`level=INFO msg="startup complete"`,
		`level=INFO msg="tracer ready"`,
	}

	events := ParseAuditEvents(logs)

	if len(events) != 0 {
		t.Errorf("event count = %d, want 0", len(events))
	}
}

func TestParseAuditEvents_QuotedValueNotFalsePositive(t *testing.T) {
	// "action=deny" appearing inside a quoted msg value should NOT be
	// parsed as a real audit event field.
	logs := []string{
		`level=INFO msg="user said action=deny is configured" pid=1234`,
	}

	events := ParseAuditEvents(logs)

	if len(events) != 0 {
		t.Errorf("event count = %d, want 0 (action=deny was inside quotes)", len(events))
	}
}

func TestParseAuditEvents_TabDelimited(t *testing.T) {
	logs := []string{
		"level=INFO\tmsg=\"audit\"\taction=deny\tsyscall=execve\tpid=1234",
	}

	events := ParseAuditEvents(logs)

	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].Syscall != "execve" {
		t.Errorf("syscall = %q, want execve", events[0].Syscall)
	}
}

func TestParseAuditEvents_UnclosedQuote(t *testing.T) {
	// Unclosed quote should consume remainder of line as the value,
	// not cause a false positive for fields after the quote.
	logs := []string{
		`level=INFO msg="unclosed quote with action=deny`,
	}

	events := ParseAuditEvents(logs)

	if len(events) != 0 {
		t.Errorf("event count = %d, want 0 (action=deny inside unclosed quote)", len(events))
	}
}
