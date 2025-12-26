package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{
		Output:    buf,
		SessionID: "sess-123",
		AgentID:   "agent-456",
		TenantID:  "tenant-789",
	})

	if logger == nil {
		t.Fatal("NewAuditLogger returned nil")
	}

	if logger.sessionID != "sess-123" {
		t.Errorf("sessionID = %q, want sess-123", logger.sessionID)
	}
	if logger.agentID != "agent-456" {
		t.Errorf("agentID = %q, want agent-456", logger.agentID)
	}
	if logger.tenantID != "tenant-789" {
		t.Errorf("tenantID = %q, want tenant-789", logger.tenantID)
	}
}

func TestAuditLogger_DefaultOutput(t *testing.T) {
	logger := NewAuditLogger(AuditLoggerConfig{})
	if logger.output == nil {
		t.Error("output should default to stdout")
	}
}

func TestAuditLogger_WithSession(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	newLogger := logger.WithSession("new-session")
	if newLogger.sessionID != "new-session" {
		t.Errorf("sessionID = %q, want new-session", newLogger.sessionID)
	}
	if newLogger.output != buf {
		t.Error("output should be preserved")
	}
}

func TestAuditLogger_WithAgent(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf, SessionID: "sess-123"})

	newLogger := logger.WithAgent("new-agent")
	if newLogger.agentID != "new-agent" {
		t.Errorf("agentID = %q, want new-agent", newLogger.agentID)
	}
	if newLogger.sessionID != "sess-123" {
		t.Error("sessionID should be preserved")
	}
}

func TestAuditLogger_WithTenant(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	newLogger := logger.WithTenant("new-tenant")
	if newLogger.tenantID != "new-tenant" {
		t.Errorf("tenantID = %q, want new-tenant", newLogger.tenantID)
	}
}

func TestAuditLogger_LogLevels(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{
		Output:   buf,
		MinLevel: LogInfo,
	})

	ctx := context.Background()

	// Debug should be filtered out
	logger.Debug(ctx, "debug message", nil)
	if buf.Len() > 0 {
		t.Error("debug message should be filtered when minLevel is info")
	}

	// Info should pass
	buf.Reset()
	logger.Info(ctx, "info message", nil)
	if buf.Len() == 0 {
		t.Error("info message should be logged")
	}

	// Warn should pass
	buf.Reset()
	logger.Warn(ctx, "warn message", nil)
	if buf.Len() == 0 {
		t.Error("warn message should be logged")
	}

	// Error should pass
	buf.Reset()
	logger.Error(ctx, "error message", nil)
	if buf.Len() == 0 {
		t.Error("error message should be logged")
	}
}

func TestAuditLogger_LogFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{
		Output:    buf,
		SessionID: "sess-123",
		AgentID:   "agent-456",
		TenantID:  "tenant-789",
	})

	ctx := context.Background()
	logger.Info(ctx, "test message", map[string]any{
		"custom_field": "custom_value",
		"count":        42,
	})

	// Parse the JSON output
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	// Check required fields
	if entry["level"] != "info" {
		t.Errorf("level = %v, want info", entry["level"])
	}
	if entry["msg"] != "test message" {
		t.Errorf("msg = %v, want 'test message'", entry["msg"])
	}
	if entry["session_id"] != "sess-123" {
		t.Errorf("session_id = %v, want sess-123", entry["session_id"])
	}
	if entry["agent_id"] != "agent-456" {
		t.Errorf("agent_id = %v, want agent-456", entry["agent_id"])
	}
	if entry["tenant_id"] != "tenant-789" {
		t.Errorf("tenant_id = %v, want tenant-789", entry["tenant_id"])
	}

	// Check custom fields
	if entry["custom_field"] != "custom_value" {
		t.Errorf("custom_field = %v, want custom_value", entry["custom_field"])
	}
	if entry["count"] != float64(42) { // JSON numbers are float64
		t.Errorf("count = %v, want 42", entry["count"])
	}

	// Check timestamp format (RFC3339Nano)
	ts, ok := entry["ts"].(string)
	if !ok {
		t.Error("ts should be a string")
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("ts should be RFC3339Nano format: %v", err)
	}
}

func TestAuditLogger_LogOperation(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{
		Output:    buf,
		SessionID: "sess-123",
	})

	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileRead,
		SessionID: "sess-123",
		AgentID:   "agent-456",
		Path:      "/etc/passwd",
	}

	logger.LogOperation(ctx, op, "deny", 150*time.Microsecond)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["msg"] != "operation" {
		t.Errorf("msg = %v, want operation", entry["msg"])
	}
	if entry["type"] != "file_read" {
		t.Errorf("type = %v, want file_read", entry["type"])
	}
	if entry["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", entry["decision"])
	}
	if entry["path"] != "/etc/passwd" {
		t.Errorf("path = %v, want /etc/passwd", entry["path"])
	}
	if entry["latency_us"] != float64(150) {
		t.Errorf("latency_us = %v, want 150", entry["latency_us"])
	}
}

func TestAuditLogger_LogApproval(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	logger.LogApproval(ctx, OpFileDelete, "/workspace/file.txt", "user@example.com", true, 5*time.Second)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["msg"] != "approval" {
		t.Errorf("msg = %v, want approval", entry["msg"])
	}
	if entry["approver"] != "user@example.com" {
		t.Errorf("approver = %v, want user@example.com", entry["approver"])
	}
	if entry["approved"] != true {
		t.Errorf("approved = %v, want true", entry["approved"])
	}
}

func TestAuditLogger_LogSessionStart(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	logger.LogSessionStart(ctx, "/workspace", "default")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["msg"] != "session_start" {
		t.Errorf("msg = %v, want session_start", entry["msg"])
	}
	if entry["workspace"] != "/workspace" {
		t.Errorf("workspace = %v, want /workspace", entry["workspace"])
	}
	if entry["policy_set"] != "default" {
		t.Errorf("policy_set = %v, want default", entry["policy_set"])
	}
}

func TestAuditLogger_LogSessionEnd(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	logger.LogSessionEnd(ctx, 0, 5*time.Minute, "completed")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["msg"] != "session_end" {
		t.Errorf("msg = %v, want session_end", entry["msg"])
	}
	if entry["exit_code"] != float64(0) {
		t.Errorf("exit_code = %v, want 0", entry["exit_code"])
	}
	if entry["final_state"] != "completed" {
		t.Errorf("final_state = %v, want completed", entry["final_state"])
	}
}

func TestAuditLogger_LogPolicyDeny(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	op := &InterceptedOperation{
		Type: OpFileRead,
		Path: "/etc/shadow",
	}
	logger.LogPolicyDeny(ctx, op, "deny-shadow", "Access to shadow file denied")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["level"] != "warn" {
		t.Errorf("level = %v, want warn", entry["level"])
	}
	if entry["msg"] != "policy_deny" {
		t.Errorf("msg = %v, want policy_deny", entry["msg"])
	}
	if entry["rule_name"] != "deny-shadow" {
		t.Errorf("rule_name = %v, want deny-shadow", entry["rule_name"])
	}
}

func TestAuditLogger_LogWebhook(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{
		Output:   buf,
		MinLevel: LogDebug,
	})

	ctx := context.Background()

	// Success case
	logger.LogWebhook(ctx, "https://hooks.example.com", 200, 100*time.Millisecond, nil)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["level"] != "debug" {
		t.Errorf("level = %v, want debug", entry["level"])
	}
	if entry["msg"] != "webhook_dispatch" {
		t.Errorf("msg = %v, want webhook_dispatch", entry["msg"])
	}

	// Error case
	buf.Reset()
	logger.LogWebhook(ctx, "https://hooks.example.com", 0, 100*time.Millisecond, context.DeadlineExceeded)

	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["level"] != "error" {
		t.Errorf("level = %v, want error", entry["level"])
	}
	if entry["msg"] != "webhook_error" {
		t.Errorf("msg = %v, want webhook_error", entry["msg"])
	}
}

func TestAuditLogger_LogSecurityEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	logger.LogSecurityEvent(ctx, "registry_modification", "critical", map[string]any{
		"path":      `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"technique": "T1547.001",
	})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["event_type"] != "registry_modification" {
		t.Errorf("event_type = %v, want registry_modification", entry["event_type"])
	}
	if entry["severity"] != "critical" {
		t.Errorf("severity = %v, want critical", entry["severity"])
	}
	if entry["technique"] != "T1547.001" {
		t.Errorf("technique = %v, want T1547.001", entry["technique"])
	}
}

func TestAuditLogger_JSONNewlineDelimited(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewAuditLogger(AuditLoggerConfig{Output: buf})

	ctx := context.Background()
	logger.Info(ctx, "message 1", nil)
	logger.Info(ctx, "message 2", nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}

	// Each line should be valid JSON
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestLogEntry_MarshalJSON(t *testing.T) {
	entry := LogEntry{
		Level:     "info",
		Timestamp: "2025-01-15T14:30:00Z",
		Message:   "test",
		SessionID: "sess-123",
		Fields: map[string]any{
			"custom": "value",
		},
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse marshaled JSON: %v", err)
	}

	// Standard fields should be present
	if parsed["level"] != "info" {
		t.Errorf("level = %v, want info", parsed["level"])
	}
	if parsed["session_id"] != "sess-123" {
		t.Errorf("session_id = %v, want sess-123", parsed["session_id"])
	}

	// Custom fields should be flattened
	if parsed["custom"] != "value" {
		t.Errorf("custom = %v, want value", parsed["custom"])
	}
}
