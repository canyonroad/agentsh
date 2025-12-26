package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the OpenTelemetry tracer name.
	TracerName = "agentsh"
)

// OperationType represents the type of intercepted operation.
type OperationType string

const (
	OpFileRead    OperationType = "file_read"
	OpFileWrite   OperationType = "file_write"
	OpFileCreate  OperationType = "file_create"
	OpFileDelete  OperationType = "file_delete"
	OpNetConnect  OperationType = "net_connect"
	OpDNSQuery    OperationType = "dns_query"
	OpEnvRead     OperationType = "env_read"
	OpEnvWrite    OperationType = "env_write"
	OpExec        OperationType = "exec"
	OpRegistryRead  OperationType = "registry_read"
	OpRegistryWrite OperationType = "registry_write"
)

// String returns the string representation of the operation type.
func (o OperationType) String() string {
	return string(o)
}

// InterceptedOperation represents an operation being traced.
type InterceptedOperation struct {
	Type      OperationType
	SessionID string
	AgentID   string
	TenantID  string
	Path      string
	Target    string // For network: host:port, for DNS: domain
	Extra     map[string]string
}

// TraceOperation starts a new span for an intercepted operation.
func TraceOperation(ctx context.Context, op *InterceptedOperation) (context.Context, trace.Span) {
	tracer := otel.Tracer(TracerName)

	attrs := []attribute.KeyValue{
		attribute.String("session.id", op.SessionID),
		attribute.String("agent.id", op.AgentID),
		attribute.String("operation.type", string(op.Type)),
	}

	if op.TenantID != "" {
		attrs = append(attrs, attribute.String("tenant.id", op.TenantID))
	}
	if op.Path != "" {
		attrs = append(attrs, attribute.String("operation.path", op.Path))
	}
	if op.Target != "" {
		attrs = append(attrs, attribute.String("operation.target", op.Target))
	}
	for k, v := range op.Extra {
		attrs = append(attrs, attribute.String("operation."+k, v))
	}

	ctx, span := tracer.Start(ctx, op.Type.String(),
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	return ctx, span
}

// RecordDecision records the policy decision on a span.
func RecordDecision(span trace.Span, decision string, ruleName string) {
	span.SetAttributes(
		attribute.String("decision", decision),
		attribute.String("decision.rule", ruleName),
	)

	if decision == "deny" {
		span.SetStatus(codes.Error, "operation denied by policy")
	}
}

// RecordApproval records approval-related events on a span.
func RecordApproval(span trace.Span, approver string, approved bool, duration time.Duration) {
	span.AddEvent("approval_received", trace.WithAttributes(
		attribute.String("approver", approver),
		attribute.Bool("approved", approved),
		attribute.Int64("duration_ms", duration.Milliseconds()),
	))

	if !approved {
		span.SetStatus(codes.Error, "approval denied")
	}
}

// RecordRedirect records a redirect action on a span.
func RecordRedirect(span trace.Span, originalPath, redirectPath string) {
	span.AddEvent("redirect", trace.WithAttributes(
		attribute.String("original_path", originalPath),
		attribute.String("redirect_path", redirectPath),
	))
}

// RecordError records an error on a span.
func RecordError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// PolicyEvalSpan creates a child span for policy evaluation.
func PolicyEvalSpan(ctx context.Context) (context.Context, trace.Span) {
	tracer := otel.Tracer(TracerName)
	return tracer.Start(ctx, "policy_eval",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// ApprovalSpan creates a child span for approval workflow.
func ApprovalSpan(ctx context.Context, opType OperationType, path string) (context.Context, trace.Span) {
	tracer := otel.Tracer(TracerName)
	return tracer.Start(ctx, "awaiting_approval",
		trace.WithAttributes(
			attribute.String("operation.type", string(opType)),
			attribute.String("operation.path", path),
		),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// WebhookSpan creates a child span for webhook dispatch.
func WebhookSpan(ctx context.Context, url string) (context.Context, trace.Span) {
	tracer := otel.Tracer(TracerName)
	return tracer.Start(ctx, "webhook_dispatch",
		trace.WithAttributes(
			attribute.String("webhook.url", url),
		),
		trace.WithSpanKind(trace.SpanKindClient),
	)
}

// RecordWebhookResult records webhook dispatch result.
func RecordWebhookResult(span trace.Span, statusCode int, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	span.SetAttributes(attribute.Int("http.status_code", statusCode))
	if statusCode >= 400 {
		span.SetStatus(codes.Error, "webhook returned error status")
	}
}

// ExtractTraceID extracts the trace ID from a context.
func ExtractTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// ExtractSpanID extracts the span ID from a context.
func ExtractSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return ""
	}
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.SpanID().String()
}
