package otel

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

func TestConvertToLogRecord_BasicFields(t *testing.T) {
	ev := types.Event{
		ID:        "evt-123",
		Timestamp: time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Type:      "file_write",
		SessionID: "sess-abc",
		CommandID: "cmd-1",
		PID:       4567,
		Path:      "/workspace/foo.txt",
		Operation: "write",
	}

	rec := convertToLogRecord(ev)

	// Check timestamp.
	if !rec.Timestamp().Equal(ev.Timestamp) {
		t.Errorf("timestamp = %v, want %v", rec.Timestamp(), ev.Timestamp)
	}

	// Check body contains event type and path.
	body := rec.Body()
	if body.Kind() != otellog.KindString {
		t.Fatalf("body kind = %v, want String", body.Kind())
	}
	want := "file_write: /workspace/foo.txt"
	if body.AsString() != want {
		t.Errorf("body = %q, want %q", body.AsString(), want)
	}

	// Check severity: file_write with no policy decision defaults to INFO.
	if rec.Severity() != otellog.SeverityInfo {
		t.Errorf("severity = %v, want INFO", rec.Severity())
	}
}

func TestConvertToLogRecord_BodyWithDecision(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_delete",
		SessionID: "s",
		Path:      "/etc/passwd",
		Policy:    &types.PolicyInfo{Decision: "deny"},
	}

	rec := convertToLogRecord(ev)
	want := "file_delete: /etc/passwd [deny]"
	if rec.Body().AsString() != want {
		t.Errorf("body = %q, want %q", rec.Body().AsString(), want)
	}
}

func TestConvertToLogRecord_BodyFallbackTargets(t *testing.T) {
	tests := []struct {
		name   string
		ev     types.Event
		want   string
	}{
		{
			name: "domain target",
			ev: types.Event{
				Timestamp: time.Now(), Type: "dns_query",
				SessionID: "s", Domain: "example.com",
			},
			want: "dns_query: example.com",
		},
		{
			name: "remote target",
			ev: types.Event{
				Timestamp: time.Now(), Type: "net_connect",
				SessionID: "s", Remote: "1.2.3.4:443",
			},
			want: "net_connect: 1.2.3.4:443",
		},
		{
			name: "no target",
			ev: types.Event{
				Timestamp: time.Now(), Type: "process_start",
				SessionID: "s",
			},
			want: "process_start",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := convertToLogRecord(tt.ev)
			if rec.Body().AsString() != tt.want {
				t.Errorf("body = %q, want %q", rec.Body().AsString(), tt.want)
			}
		})
	}
}

func TestConvertToLogRecord_Severity(t *testing.T) {
	tests := []struct {
		decision string
		want     otellog.Severity
	}{
		{"allow", otellog.SeverityInfo},
		{"audit", otellog.SeverityInfo},
		{"redirect", otellog.SeverityWarn},
		{"approve", otellog.SeverityWarn},
		{"soft_delete", otellog.SeverityWarn},
		{"deny", otellog.SeverityError},
		{"", otellog.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.decision, func(t *testing.T) {
			ev := types.Event{
				Timestamp: time.Now(),
				Type:      "file_write",
				SessionID: "s",
			}
			if tt.decision != "" {
				ev.Policy = &types.PolicyInfo{Decision: types.Decision(tt.decision)}
			}

			rec := convertToLogRecord(ev)
			if rec.Severity() != tt.want {
				t.Errorf("severity = %v, want %v", rec.Severity(), tt.want)
			}
		})
	}
}

func TestConvertToLogRecord_Attributes(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "sess-1",
		CommandID: "cmd-1",
		PID:       100,
		ParentPID: 50,
		Path:      "/workspace/test.go",
		Policy:    &types.PolicyInfo{Decision: "allow", Rule: "allow-workspace"},
	}

	rec := convertToLogRecord(ev)

	attrs := logRecordAttrs(rec)
	assertAttr(t, attrs, "process.pid", int64(100))
	assertAttr(t, attrs, "process.parent_pid", int64(50))
	assertAttr(t, attrs, "canyonroad.product", "agentsh")
	assertAttr(t, attrs, "canyonroad.event.type", "file_write")
	assertAttr(t, attrs, "canyonroad.session.id", "sess-1")
	assertAttr(t, attrs, "canyonroad.command.id", "cmd-1")
	assertAttr(t, attrs, "canyonroad.path", "/workspace/test.go")
	assertAttr(t, attrs, "canyonroad.decision", "allow")
	assertAttr(t, attrs, "canyonroad.policy.rule", "allow-workspace")
}

func TestConvertToLogRecord_FieldsAttributes(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "s",
		Fields: map[string]any{
			"risk_level":    "high",
			"agent_id":      "agent-1",
			"latency_us":    int64(1500),
			"policy_eval_us": 250,
			"error":         "permission denied",
			// Fields not in the well-known list should be ignored.
			"custom_field": "ignored",
		},
	}

	rec := convertToLogRecord(ev)
	attrs := logRecordAttrs(rec)

	assertAttr(t, attrs, "canyonroad.risk_level", "high")
	assertAttr(t, attrs, "canyonroad.agent_id", "agent-1")
	assertAttr(t, attrs, "canyonroad.latency_us", int64(1500))
	assertAttr(t, attrs, "canyonroad.error", "permission denied")

	// Custom fields not in the well-known list should not appear.
	if _, ok := attrs["canyonroad.custom_field"]; ok {
		t.Error("unexpected attribute canyonroad.custom_field")
	}
}

func TestConvertToLogRecord_OptionalFieldsOmitted(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "s",
	}

	rec := convertToLogRecord(ev)
	attrs := logRecordAttrs(rec)

	// PID=0 should not produce an attribute.
	if _, ok := attrs["process.pid"]; ok {
		t.Error("unexpected attribute process.pid when PID=0")
	}
	// No policy -> no decision attribute.
	if _, ok := attrs["canyonroad.decision"]; ok {
		t.Error("unexpected attribute canyonroad.decision when no policy")
	}
}

func TestEventContext_WithTraceCorrelation(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "s",
		Fields: map[string]any{
			"trace_id": "0af7651916cd43dd8448eb211c80319c",
			"span_id":  "b7ad6b7169203331",
		},
	}

	ctx := eventContext(context.Background(), ev)
	sc := trace.SpanContextFromContext(ctx)

	if sc.TraceID().String() != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace_id = %q", sc.TraceID().String())
	}
	if sc.SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("span_id = %q", sc.SpanID().String())
	}
	// Without explicit trace_flags, should default to sampled
	if !sc.IsSampled() {
		t.Error("expected sampled flag when trace_flags absent")
	}
}

func TestEventContext_TraceFlags_Sampled(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "s",
		Fields: map[string]any{
			"trace_id":    "0af7651916cd43dd8448eb211c80319c",
			"span_id":     "b7ad6b7169203331",
			"trace_flags": "01",
		},
	}

	ctx := eventContext(context.Background(), ev)
	sc := trace.SpanContextFromContext(ctx)

	if !sc.IsSampled() {
		t.Error("expected sampled flag for trace_flags=01")
	}
}

func TestEventContext_TraceFlags_Unsampled(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "s",
		Fields: map[string]any{
			"trace_id":    "0af7651916cd43dd8448eb211c80319c",
			"span_id":     "b7ad6b7169203331",
			"trace_flags": "00",
		},
	}

	ctx := eventContext(context.Background(), ev)
	sc := trace.SpanContextFromContext(ctx)

	if sc.IsSampled() {
		t.Error("expected unsampled for trace_flags=00")
	}
}

func TestEventContext_TraceFlags_Invalid(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "s",
		Fields: map[string]any{
			"trace_id":    "0af7651916cd43dd8448eb211c80319c",
			"span_id":     "b7ad6b7169203331",
			"trace_flags": "zz",
		},
	}

	ctx := eventContext(context.Background(), ev)
	sc := trace.SpanContextFromContext(ctx)

	// Invalid trace_flags should fall back to default (sampled)
	if !sc.IsSampled() {
		t.Error("expected sampled flag as default when trace_flags is invalid")
	}
}

func TestEventContext_NoTraceFields(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "s",
	}

	ctx := eventContext(context.Background(), ev)
	sc := trace.SpanContextFromContext(ctx)

	if sc.HasTraceID() {
		t.Error("expected no trace ID when fields are absent")
	}
	if sc.HasSpanID() {
		t.Error("expected no span ID when fields are absent")
	}
}

func TestEventContext_InvalidTraceID(t *testing.T) {
	tests := []struct {
		name    string
		traceID string
	}{
		{"too short", "0af765"},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := types.Event{
				Timestamp: time.Now(),
				Type:      "file_write",
				SessionID: "s",
				Fields:    map[string]any{"trace_id": tt.traceID},
			}

			ctx := eventContext(context.Background(), ev)
			sc := trace.SpanContextFromContext(ctx)
			if sc.HasTraceID() {
				t.Error("expected no trace ID for invalid input")
			}
		})
	}
}

func TestBuildResource(t *testing.T) {
	res := BuildResource("my-agentsh", map[string]string{"env": "prod"})

	attrs := res.Attributes()
	found := map[string]string{}
	for _, a := range attrs {
		if a.Value.Type() == attribute.STRING {
			found[string(a.Key)] = a.Value.AsString()
		}
	}

	if found["service.name"] != "my-agentsh" {
		t.Errorf("service.name = %q, want %q", found["service.name"], "my-agentsh")
	}
	if found["env"] != "prod" {
		t.Errorf("env = %q, want %q", found["env"], "prod")
	}
}

func TestBuildResource_NoExtras(t *testing.T) {
	res := BuildResource("agentsh", nil)

	attrs := res.Attributes()
	found := false
	for _, a := range attrs {
		if string(a.Key) == "service.name" && a.Value.AsString() == "agentsh" {
			found = true
		}
	}
	if !found {
		t.Error("missing service.name attribute")
	}
}

// logRecordAttrs extracts attributes from a log record into a map keyed by
// attribute name.
func logRecordAttrs(rec otellog.Record) map[string]otellog.Value {
	m := make(map[string]otellog.Value)
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		m[kv.Key] = kv.Value
		return true
	})
	return m
}

// assertAttr asserts that an attribute exists with the expected value.
func assertAttr(t *testing.T, attrs map[string]otellog.Value, key string, want any) {
	t.Helper()
	v, ok := attrs[key]
	if !ok {
		t.Errorf("missing attribute %q", key)
		return
	}
	switch w := want.(type) {
	case string:
		if v.AsString() != w {
			t.Errorf("attr %q = %v, want %q", key, v, w)
		}
	case int64:
		if v.AsInt64() != w {
			t.Errorf("attr %q = %v, want %d", key, v, w)
		}
	case float64:
		if v.AsFloat64() != w {
			t.Errorf("attr %q = %v, want %f", key, v, w)
		}
	default:
		t.Errorf("unsupported assertion type for attr %q: %T", key, want)
	}
}
