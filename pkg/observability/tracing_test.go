package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func init() {
	// Use noop tracer for tests
	otel.SetTracerProvider(noop.NewTracerProvider())
}

func TestOperationType_String(t *testing.T) {
	tests := []struct {
		op   OperationType
		want string
	}{
		{OpFileRead, "file_read"},
		{OpFileWrite, "file_write"},
		{OpNetConnect, "net_connect"},
		{OpDNSQuery, "dns_query"},
		{OpExec, "exec"},
	}

	for _, tt := range tests {
		if got := tt.op.String(); got != tt.want {
			t.Errorf("%v.String() = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestTraceOperation(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileRead,
		SessionID: "sess-123",
		AgentID:   "agent-456",
		TenantID:  "tenant-789",
		Path:      "/etc/passwd",
		Extra: map[string]string{
			"mode": "r",
		},
	}

	ctx, span := TraceOperation(ctx, op)
	defer span.End()

	if span == nil {
		t.Error("TraceOperation returned nil span")
	}

	// Verify context is updated
	if ctx == nil {
		t.Error("TraceOperation returned nil context")
	}
}

func TestTraceOperation_MinimalOp(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpNetConnect,
		SessionID: "sess-123",
		AgentID:   "agent-456",
		Target:    "api.example.com:443",
	}

	ctx, span := TraceOperation(ctx, op)
	defer span.End()

	if span == nil {
		t.Error("TraceOperation returned nil span")
	}
}

func TestRecordDecision(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileRead,
		SessionID: "sess-123",
		AgentID:   "agent-456",
	}

	_, span := TraceOperation(ctx, op)
	defer span.End()

	// Should not panic
	RecordDecision(span, "allow", "rule-1")
	RecordDecision(span, "deny", "rule-2")
}

func TestRecordApproval(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileDelete,
		SessionID: "sess-123",
		AgentID:   "agent-456",
	}

	_, span := TraceOperation(ctx, op)
	defer span.End()

	// Should not panic
	RecordApproval(span, "user@example.com", true, 5*time.Second)
	RecordApproval(span, "user@example.com", false, 10*time.Second)
}

func TestRecordRedirect(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileWrite,
		SessionID: "sess-123",
		AgentID:   "agent-456",
	}

	_, span := TraceOperation(ctx, op)
	defer span.End()

	// Should not panic
	RecordRedirect(span, "/secret/file", "/workspace/.scratch/file")
}

func TestRecordError(t *testing.T) {
	ctx := context.Background()
	op := &InterceptedOperation{
		Type:      OpFileRead,
		SessionID: "sess-123",
		AgentID:   "agent-456",
	}

	_, span := TraceOperation(ctx, op)
	defer span.End()

	// Should not panic with nil error
	RecordError(span, nil)

	// Should not panic with real error
	RecordError(span, context.DeadlineExceeded)
}

func TestPolicyEvalSpan(t *testing.T) {
	ctx := context.Background()

	ctx, span := PolicyEvalSpan(ctx)
	defer span.End()

	if span == nil {
		t.Error("PolicyEvalSpan returned nil span")
	}
}

func TestApprovalSpan(t *testing.T) {
	ctx := context.Background()

	ctx, span := ApprovalSpan(ctx, OpFileDelete, "/workspace/important.txt")
	defer span.End()

	if span == nil {
		t.Error("ApprovalSpan returned nil span")
	}
}

func TestWebhookSpan(t *testing.T) {
	ctx := context.Background()

	ctx, span := WebhookSpan(ctx, "https://hooks.example.com/notify")
	defer span.End()

	if span == nil {
		t.Error("WebhookSpan returned nil span")
	}
}

func TestRecordWebhookResult(t *testing.T) {
	ctx := context.Background()
	_, span := WebhookSpan(ctx, "https://hooks.example.com/notify")
	defer span.End()

	// Should not panic
	RecordWebhookResult(span, 200, nil)
	RecordWebhookResult(span, 500, nil)
	RecordWebhookResult(span, 0, context.DeadlineExceeded)
}

func TestExtractTraceID(t *testing.T) {
	// With noop tracer, should return empty string
	ctx := context.Background()
	traceID := ExtractTraceID(ctx)

	// Noop tracer returns invalid span context, so trace ID should be empty
	if traceID != "" {
		t.Logf("TraceID with noop tracer: %q", traceID)
	}
}

func TestExtractSpanID(t *testing.T) {
	// With noop tracer, should return empty string
	ctx := context.Background()
	spanID := ExtractSpanID(ctx)

	// Noop tracer returns invalid span context, so span ID should be empty
	if spanID != "" {
		t.Logf("SpanID with noop tracer: %q", spanID)
	}
}
