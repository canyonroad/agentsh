package observability

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log entry.
type LogLevel string

const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// AuditLogger provides structured logging with session/agent context.
type AuditLogger struct {
	output    io.Writer
	mu        sync.Mutex
	sessionID string
	agentID   string
	tenantID  string
	minLevel  LogLevel
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	Output    io.Writer
	SessionID string
	AgentID   string
	TenantID  string
	MinLevel  LogLevel
}

// NewAuditLogger creates a new structured audit logger.
func NewAuditLogger(cfg AuditLoggerConfig) *AuditLogger {
	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}
	minLevel := cfg.MinLevel
	if minLevel == "" {
		minLevel = LogInfo
	}
	return &AuditLogger{
		output:    output,
		sessionID: cfg.SessionID,
		agentID:   cfg.AgentID,
		tenantID:  cfg.TenantID,
		minLevel:  minLevel,
	}
}

// LogEntry represents a structured log entry.
type LogEntry struct {
	Level     string            `json:"level"`
	Timestamp string            `json:"ts"`
	Message   string            `json:"msg"`
	SessionID string            `json:"session_id,omitempty"`
	AgentID   string            `json:"agent_id,omitempty"`
	TenantID  string            `json:"tenant_id,omitempty"`
	TraceID   string            `json:"trace_id,omitempty"`
	SpanID    string            `json:"span_id,omitempty"`
	Fields    map[string]any    `json:"-"`
}

// MarshalJSON implements custom JSON marshaling to flatten Fields.
func (e LogEntry) MarshalJSON() ([]byte, error) {
	// Create a map with all standard fields
	m := make(map[string]any)
	m["level"] = e.Level
	m["ts"] = e.Timestamp
	m["msg"] = e.Message

	if e.SessionID != "" {
		m["session_id"] = e.SessionID
	}
	if e.AgentID != "" {
		m["agent_id"] = e.AgentID
	}
	if e.TenantID != "" {
		m["tenant_id"] = e.TenantID
	}
	if e.TraceID != "" {
		m["trace_id"] = e.TraceID
	}
	if e.SpanID != "" {
		m["span_id"] = e.SpanID
	}

	// Merge in custom fields
	for k, v := range e.Fields {
		m[k] = v
	}

	return json.Marshal(m)
}

// WithSession returns a new logger with session context.
func (l *AuditLogger) WithSession(sessionID string) *AuditLogger {
	return &AuditLogger{
		output:    l.output,
		sessionID: sessionID,
		agentID:   l.agentID,
		tenantID:  l.tenantID,
		minLevel:  l.minLevel,
	}
}

// WithAgent returns a new logger with agent context.
func (l *AuditLogger) WithAgent(agentID string) *AuditLogger {
	return &AuditLogger{
		output:    l.output,
		sessionID: l.sessionID,
		agentID:   agentID,
		tenantID:  l.tenantID,
		minLevel:  l.minLevel,
	}
}

// WithTenant returns a new logger with tenant context.
func (l *AuditLogger) WithTenant(tenantID string) *AuditLogger {
	return &AuditLogger{
		output:    l.output,
		sessionID: l.sessionID,
		agentID:   l.agentID,
		tenantID:  tenantID,
		minLevel:  l.minLevel,
	}
}

func (l *AuditLogger) shouldLog(level LogLevel) bool {
	levels := map[LogLevel]int{
		LogDebug: 0,
		LogInfo:  1,
		LogWarn:  2,
		LogError: 3,
	}
	return levels[level] >= levels[l.minLevel]
}

func (l *AuditLogger) log(ctx context.Context, level LogLevel, msg string, fields map[string]any) {
	if !l.shouldLog(level) {
		return
	}

	entry := LogEntry{
		Level:     string(level),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Message:   msg,
		SessionID: l.sessionID,
		AgentID:   l.agentID,
		TenantID:  l.tenantID,
		TraceID:   ExtractTraceID(ctx),
		SpanID:    ExtractSpanID(ctx),
		Fields:    fields,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.output.Write(data)
	l.output.Write([]byte("\n"))
}

// Debug logs a debug-level message.
func (l *AuditLogger) Debug(ctx context.Context, msg string, fields map[string]any) {
	l.log(ctx, LogDebug, msg, fields)
}

// Info logs an info-level message.
func (l *AuditLogger) Info(ctx context.Context, msg string, fields map[string]any) {
	l.log(ctx, LogInfo, msg, fields)
}

// Warn logs a warning-level message.
func (l *AuditLogger) Warn(ctx context.Context, msg string, fields map[string]any) {
	l.log(ctx, LogWarn, msg, fields)
}

// Error logs an error-level message.
func (l *AuditLogger) Error(ctx context.Context, msg string, fields map[string]any) {
	l.log(ctx, LogError, msg, fields)
}

// LogOperation logs an intercepted operation with decision.
func (l *AuditLogger) LogOperation(ctx context.Context, op *InterceptedOperation, decision string, latency time.Duration) {
	fields := map[string]any{
		"type":       string(op.Type),
		"decision":   decision,
		"latency_us": latency.Microseconds(),
	}

	if op.Path != "" {
		fields["path"] = op.Path
	}
	if op.Target != "" {
		fields["target"] = op.Target
	}
	for k, v := range op.Extra {
		fields[k] = v
	}

	l.Info(ctx, "operation", fields)
}

// LogApproval logs an approval event.
func (l *AuditLogger) LogApproval(ctx context.Context, opType OperationType, path string, approver string, approved bool, latency time.Duration) {
	fields := map[string]any{
		"type":       string(opType),
		"path":       path,
		"approver":   approver,
		"approved":   approved,
		"latency_ms": latency.Milliseconds(),
	}

	l.Info(ctx, "approval", fields)
}

// LogSessionStart logs session start.
func (l *AuditLogger) LogSessionStart(ctx context.Context, workspacePath string, policySet string) {
	fields := map[string]any{
		"workspace":  workspacePath,
		"policy_set": policySet,
	}

	l.Info(ctx, "session_start", fields)
}

// LogSessionEnd logs session end.
func (l *AuditLogger) LogSessionEnd(ctx context.Context, exitCode int, duration time.Duration, state string) {
	fields := map[string]any{
		"exit_code":   exitCode,
		"duration_s":  duration.Seconds(),
		"final_state": state,
	}

	l.Info(ctx, "session_end", fields)
}

// LogPolicyDeny logs a policy denial.
func (l *AuditLogger) LogPolicyDeny(ctx context.Context, op *InterceptedOperation, ruleName string, reason string) {
	fields := map[string]any{
		"type":      string(op.Type),
		"rule_name": ruleName,
		"reason":    reason,
	}

	if op.Path != "" {
		fields["path"] = op.Path
	}
	if op.Target != "" {
		fields["target"] = op.Target
	}

	l.Warn(ctx, "policy_deny", fields)
}

// LogWebhook logs a webhook dispatch.
func (l *AuditLogger) LogWebhook(ctx context.Context, url string, statusCode int, latency time.Duration, err error) {
	fields := map[string]any{
		"url":        url,
		"latency_ms": latency.Milliseconds(),
	}

	if statusCode > 0 {
		fields["status_code"] = statusCode
	}

	if err != nil {
		fields["error"] = err.Error()
		l.Error(ctx, "webhook_error", fields)
	} else {
		l.Debug(ctx, "webhook_dispatch", fields)
	}
}

// LogSecurityEvent logs a security-relevant event (for SIEM ingestion).
func (l *AuditLogger) LogSecurityEvent(ctx context.Context, eventType string, severity string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["event_type"] = eventType
	fields["severity"] = severity

	l.Info(ctx, "security_event", fields)
}
