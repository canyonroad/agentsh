package otel

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// convertToLogRecord converts an agentsh Event to an OTEL log Record.
// The returned record is intended for use with Logger.Emit().
func convertToLogRecord(ev types.Event) otellog.Record {
	var rec otellog.Record

	rec.SetTimestamp(ev.Timestamp)
	rec.SetBody(otellog.StringValue(eventBody(ev)))
	rec.SetSeverity(eventSeverity(ev))
	rec.SetSeverityText(eventSeverity(ev).String())

	// Build attributes.
	attrs := eventAttributes(ev)
	rec.AddAttributes(attrs...)

	return rec
}

// eventContext creates a context with trace correlation from the event's
// fields, if trace_id and span_id are present. The OTEL SDK log processor
// extracts trace context from the context passed to Logger.Emit().
func eventContext(ctx context.Context, ev types.Event) context.Context {
	traceID, hasTrace := extractTraceID(ev)
	spanID, hasSpan := extractSpanID(ev)
	if !hasTrace && !hasSpan {
		return ctx
	}

	cfg := trace.SpanContextConfig{}
	if hasTrace {
		cfg.TraceID = traceID
	}
	if hasSpan {
		cfg.SpanID = spanID
	}
	sc := trace.NewSpanContext(cfg)
	return trace.ContextWithSpanContext(ctx, sc)
}

// eventBody returns a human-readable summary of the event.
func eventBody(ev types.Event) string {
	decision := ""
	if ev.Policy != nil && ev.Policy.Decision != "" {
		decision = " [" + string(ev.Policy.Decision) + "]"
	}
	target := ev.Path
	if target == "" {
		target = ev.Domain
	}
	if target == "" {
		target = ev.Remote
	}
	if target != "" {
		return fmt.Sprintf("%s: %s%s", ev.Type, target, decision)
	}
	return fmt.Sprintf("%s%s", ev.Type, decision)
}

// eventSeverity maps policy decisions to OTEL severity levels.
func eventSeverity(ev types.Event) otellog.Severity {
	if ev.Policy == nil {
		return otellog.SeverityInfo
	}
	switch string(ev.Policy.Decision) {
	case "deny":
		return otellog.SeverityError
	case "redirect", "approve", "soft_delete":
		return otellog.SeverityWarn
	default:
		return otellog.SeverityInfo
	}
}

// eventAttributes builds OTEL log attributes from an event using semantic
// conventions where applicable and the agentsh.* namespace for custom fields.
func eventAttributes(ev types.Event) []otellog.KeyValue {
	var attrs []otellog.KeyValue

	// Semantic conventions: process.
	if ev.PID != 0 {
		attrs = append(attrs, otellog.Int("process.pid", ev.PID))
	}
	if ev.ParentPID != 0 {
		attrs = append(attrs, otellog.Int("process.parent_pid", ev.ParentPID))
	}
	if ev.Filename != "" {
		attrs = append(attrs, otellog.String("process.executable.path", ev.Filename))
	}

	// agentsh namespace.
	if ev.ID != "" {
		attrs = append(attrs, otellog.String("agentsh.event.id", ev.ID))
	}
	attrs = append(attrs, otellog.String("agentsh.event.type", ev.Type))
	if ev.SessionID != "" {
		attrs = append(attrs, otellog.String("agentsh.session.id", ev.SessionID))
	}
	if ev.CommandID != "" {
		attrs = append(attrs, otellog.String("agentsh.command.id", ev.CommandID))
	}
	if ev.Source != "" {
		attrs = append(attrs, otellog.String("agentsh.source", ev.Source))
	}
	if ev.Path != "" {
		attrs = append(attrs, otellog.String("agentsh.path", ev.Path))
	}
	if ev.Domain != "" {
		attrs = append(attrs, otellog.String("agentsh.domain", ev.Domain))
	}
	if ev.Remote != "" {
		attrs = append(attrs, otellog.String("agentsh.remote", ev.Remote))
	}
	if ev.Operation != "" {
		attrs = append(attrs, otellog.String("agentsh.operation", ev.Operation))
	}
	if ev.EffectiveAction != "" {
		attrs = append(attrs, otellog.String("agentsh.effective_action", ev.EffectiveAction))
	}

	// Policy info.
	if ev.Policy != nil {
		if ev.Policy.Decision != "" {
			attrs = append(attrs, otellog.String("agentsh.decision", string(ev.Policy.Decision)))
		}
		if ev.Policy.Rule != "" {
			attrs = append(attrs, otellog.String("agentsh.policy.rule", ev.Policy.Rule))
		}
	}

	// Fields: add selected well-known fields.
	if ev.Fields != nil {
		for _, key := range []string{
			"risk_level", "agent_id", "agent_type", "agent_framework",
			"tenant_id", "workspace_id", "policy_name",
			"latency_us", "queue_time_us", "policy_eval_us",
			"intercept_us", "backend_us", "error", "error_code",
		} {
			v, ok := ev.Fields[key]
			if !ok {
				continue
			}
			switch val := v.(type) {
			case string:
				if val != "" {
					attrs = append(attrs, otellog.String("agentsh."+key, val))
				}
			case int:
				attrs = append(attrs, otellog.Int("agentsh."+key, val))
			case int64:
				attrs = append(attrs, otellog.Int64("agentsh."+key, val))
			case float64:
				attrs = append(attrs, otellog.Float64("agentsh."+key, val))
			}
		}
	}

	return attrs
}

// extractTraceID parses a 32-hex-character trace ID from event fields.
func extractTraceID(ev types.Event) (trace.TraceID, bool) {
	if ev.Fields == nil {
		return trace.TraceID{}, false
	}
	s, ok := ev.Fields["trace_id"].(string)
	if !ok || s == "" {
		return trace.TraceID{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return trace.TraceID{}, false
	}
	var tid trace.TraceID
	copy(tid[:], b)
	return tid, true
}

// extractSpanID parses a 16-hex-character span ID from event fields.
func extractSpanID(ev types.Event) (trace.SpanID, bool) {
	if ev.Fields == nil {
		return trace.SpanID{}, false
	}
	s, ok := ev.Fields["span_id"].(string)
	if !ok || s == "" {
		return trace.SpanID{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 8 {
		return trace.SpanID{}, false
	}
	var sid trace.SpanID
	copy(sid[:], b)
	return sid, true
}

// BuildResource creates an OTEL Resource with the agentsh service name and
// optional extra attributes.
func BuildResource(serviceName string, extraAttrs map[string]string) *resource.Resource {
	kvs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	for k, v := range extraAttrs {
		kvs = append(kvs, attribute.String(k, v))
	}
	res, _ := resource.New(
		context.Background(),
		resource.WithAttributes(kvs...),
	)
	return res
}
