# OpenTelemetry Event Export Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Export agentsh audit events to any OpenTelemetry collector via OTLP (gRPC or HTTP), with configurable filtering.

**Architecture:** New `internal/store/otel/` package implementing the `store.EventStore` interface, plugged into the existing composite store chain alongside SQLite/JSONL/webhook. OTEL SDK handles batching and export.

**Tech Stack:** Go OpenTelemetry SDK (`go.opentelemetry.io/otel` v1.39.0+), OTLP log/trace exporters, `path.Match` for glob filtering.

**Design doc:** `docs/plans/2026-02-17-otel-event-export-design.md`

**Worktree:** `/home/eran/work/agentsh/.worktrees/feat-otel-export/`

---

## Task 1: Add OTEL Config Structs

**Dependencies:** None (can run in parallel with Tasks 2, 3)

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Step 1: Add config structs to `internal/config/config.go`**

After `AuditEncryptionConfig` (around line 148), add the OTEL field to `AuditConfig`:

```go
// In AuditConfig struct, add after Encryption field:
	// OTEL configures OpenTelemetry event export.
	OTEL AuditOTELConfig `yaml:"otel"`
```

Then add these new struct definitions after `AuditEncryptionConfig` struct (after line ~175):

```go
type AuditOTELConfig struct {
	Enabled  bool                    `yaml:"enabled"`
	Endpoint string                  `yaml:"endpoint"`
	Protocol string                  `yaml:"protocol"` // "grpc" or "http"
	TLS      OTELTLSConfig           `yaml:"tls"`
	Headers  map[string]string       `yaml:"headers"`
	Timeout  string                  `yaml:"timeout"`
	Signals  OTELSignalsConfig       `yaml:"signals"`
	Batch    OTELBatchConfig         `yaml:"batch"`
	Filter   OTELFilterConfig        `yaml:"filter"`
	Resource OTELResourceConfig      `yaml:"resource"`
}

type OTELTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	Insecure bool   `yaml:"insecure"`
}

type OTELSignalsConfig struct {
	Logs  bool `yaml:"logs"`
	Spans bool `yaml:"spans"`
}

type OTELBatchConfig struct {
	MaxSize int    `yaml:"max_size"`
	Timeout string `yaml:"timeout"`
}

type OTELFilterConfig struct {
	IncludeTypes      []string `yaml:"include_types"`
	ExcludeTypes      []string `yaml:"exclude_types"`
	IncludeCategories []string `yaml:"include_categories"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	MinRiskLevel      string   `yaml:"min_risk_level"`
}

type OTELResourceConfig struct {
	ServiceName     string            `yaml:"service_name"`
	ExtraAttributes map[string]string `yaml:"extra_attributes"`
}
```

**Step 2: Add defaults in `applyDefaultsWithSource`**

In `internal/config/config.go`, in function `applyDefaultsWithSource` (line 689), after the webhook defaults block (after line ~935), add:

```go
	// OTEL defaults
	if cfg.Audit.OTEL.Endpoint == "" {
		cfg.Audit.OTEL.Endpoint = "localhost:4317"
	}
	if cfg.Audit.OTEL.Protocol == "" {
		cfg.Audit.OTEL.Protocol = "grpc"
	}
	if cfg.Audit.OTEL.Timeout == "" {
		cfg.Audit.OTEL.Timeout = "10s"
	}
	if !cfg.Audit.OTEL.Signals.Logs && !cfg.Audit.OTEL.Signals.Spans {
		cfg.Audit.OTEL.Signals.Logs = true
		cfg.Audit.OTEL.Signals.Spans = true
	}
	if cfg.Audit.OTEL.Batch.MaxSize == 0 {
		cfg.Audit.OTEL.Batch.MaxSize = 512
	}
	if cfg.Audit.OTEL.Batch.Timeout == "" {
		cfg.Audit.OTEL.Batch.Timeout = "5s"
	}
	if cfg.Audit.OTEL.Resource.ServiceName == "" {
		cfg.Audit.OTEL.Resource.ServiceName = "agentsh"
	}
```

**Step 3: Add env overrides in `applyEnvOverrides`**

In `internal/config/config.go`, in function `applyEnvOverrides` (line 1001), add before the closing brace:

```go
	// OTEL overrides
	if v := os.Getenv("AGENTSH_OTEL_ENDPOINT"); v != "" {
		cfg.Audit.OTEL.Endpoint = v
	} else if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		cfg.Audit.OTEL.Endpoint = v
	}
	if v := os.Getenv("AGENTSH_OTEL_PROTOCOL"); v != "" {
		cfg.Audit.OTEL.Protocol = v
	}
```

**Step 4: Add validation in `validateConfig`**

In `internal/config/config.go`, in function `validateConfig` (line 1032), add before `return nil`:

```go
	// Validate OTEL config
	if cfg.Audit.OTEL.Enabled {
		switch cfg.Audit.OTEL.Protocol {
		case "grpc", "http":
		default:
			return fmt.Errorf("invalid audit.otel.protocol %q (must be \"grpc\" or \"http\")", cfg.Audit.OTEL.Protocol)
		}
		if cfg.Audit.OTEL.Endpoint == "" {
			return fmt.Errorf("audit.otel.endpoint is required when otel is enabled")
		}
		switch cfg.Audit.OTEL.Filter.MinRiskLevel {
		case "", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid audit.otel.filter.min_risk_level %q", cfg.Audit.OTEL.Filter.MinRiskLevel)
		}
	}
```

**Step 5: Write config parsing test**

Add to the existing test file `internal/config/config_test.go`:

```go
func TestOTELConfigParsing(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
    endpoint: "collector.example.com:4317"
    protocol: grpc
    tls:
      enabled: true
      cert_file: "/etc/certs/client.crt"
      key_file: "/etc/certs/client.key"
    headers:
      Authorization: "Bearer test-token"
    timeout: "15s"
    signals:
      logs: true
      spans: false
    batch:
      max_size: 256
      timeout: "3s"
    filter:
      include_types: ["file_*", "net_*"]
      exclude_types: ["file_stat"]
      include_categories: ["file", "network"]
      min_risk_level: "medium"
    resource:
      service_name: "my-agentsh"
      extra_attributes:
        environment: "production"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	otel := cfg.Audit.OTEL
	if !otel.Enabled {
		t.Error("expected otel.enabled=true")
	}
	if otel.Endpoint != "collector.example.com:4317" {
		t.Errorf("endpoint = %q", otel.Endpoint)
	}
	if otel.Protocol != "grpc" {
		t.Errorf("protocol = %q", otel.Protocol)
	}
	if !otel.TLS.Enabled {
		t.Error("expected tls.enabled=true")
	}
	if otel.Headers["Authorization"] != "Bearer test-token" {
		t.Errorf("headers = %v", otel.Headers)
	}
	if otel.Timeout != "15s" {
		t.Errorf("timeout = %q", otel.Timeout)
	}
	if !otel.Signals.Logs || otel.Signals.Spans {
		t.Errorf("signals = %+v", otel.Signals)
	}
	if otel.Batch.MaxSize != 256 {
		t.Errorf("batch.max_size = %d", otel.Batch.MaxSize)
	}
	if len(otel.Filter.IncludeTypes) != 2 || otel.Filter.IncludeTypes[0] != "file_*" {
		t.Errorf("filter.include_types = %v", otel.Filter.IncludeTypes)
	}
	if otel.Filter.MinRiskLevel != "medium" {
		t.Errorf("filter.min_risk_level = %q", otel.Filter.MinRiskLevel)
	}
	if otel.Resource.ServiceName != "my-agentsh" {
		t.Errorf("resource.service_name = %q", otel.Resource.ServiceName)
	}
}

func TestOTELConfigDefaults(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	otel := cfg.Audit.OTEL
	if otel.Endpoint != "localhost:4317" {
		t.Errorf("default endpoint = %q, want localhost:4317", otel.Endpoint)
	}
	if otel.Protocol != "grpc" {
		t.Errorf("default protocol = %q, want grpc", otel.Protocol)
	}
	if otel.Timeout != "10s" {
		t.Errorf("default timeout = %q, want 10s", otel.Timeout)
	}
	if !otel.Signals.Logs || !otel.Signals.Spans {
		t.Errorf("default signals = %+v, want both true", otel.Signals)
	}
	if otel.Batch.MaxSize != 512 {
		t.Errorf("default batch.max_size = %d, want 512", otel.Batch.MaxSize)
	}
	if otel.Resource.ServiceName != "agentsh" {
		t.Errorf("default resource.service_name = %q, want agentsh", otel.Resource.ServiceName)
	}
}

func TestOTELConfigEnvOverrides(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	t.Setenv("AGENTSH_OTEL_ENDPOINT", "otel.prod:4317")
	t.Setenv("AGENTSH_OTEL_PROTOCOL", "http")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Audit.OTEL.Endpoint != "otel.prod:4317" {
		t.Errorf("endpoint = %q, want otel.prod:4317", cfg.Audit.OTEL.Endpoint)
	}
	if cfg.Audit.OTEL.Protocol != "http" {
		t.Errorf("protocol = %q, want http", cfg.Audit.OTEL.Protocol)
	}
}

func TestOTELConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid protocol",
			yaml: `
audit:
  otel:
    enabled: true
    protocol: websocket
`,
			wantErr: "invalid audit.otel.protocol",
		},
		{
			name: "invalid risk level",
			yaml: `
audit:
  otel:
    enabled: true
    filter:
      min_risk_level: "extreme"
`,
			wantErr: "invalid audit.otel.filter.min_risk_level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
```

**Step 6: Run tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/config/ -run TestOTEL -v
```

Expected: All 4 OTEL config tests pass.

**Step 7: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(otel): add OTEL export config structs, defaults, env overrides, and validation"
```

---

## Task 2: Implement Event Filter

**Dependencies:** None (can run in parallel with Tasks 1, 3)

**Files:**
- Create: `internal/store/otel/filter.go`
- Create: `internal/store/otel/filter_test.go`

**Step 1: Create the filter package and write tests first**

Create `internal/store/otel/filter_test.go`:

```go
package otel

import (
	"testing"
)

func TestFilter_NilPassesAll(t *testing.T) {
	var f *Filter
	if !f.Match("file_write", "file", "high") {
		t.Error("nil filter should pass all events")
	}
}

func TestFilter_EmptyPassesAll(t *testing.T) {
	f := &Filter{}
	if !f.Match("file_write", "file", "") {
		t.Error("empty filter should pass all events")
	}
}

func TestFilter_IncludeTypes(t *testing.T) {
	f := &Filter{IncludeTypes: []string{"file_*", "net_*"}}

	tests := []struct {
		eventType string
		want      bool
	}{
		{"file_write", true},
		{"file_read", true},
		{"net_connect", true},
		{"process_start", false},
		{"dns_query", false},
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, "", ""); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.eventType, got, tt.want)
		}
	}
}

func TestFilter_ExcludeTypes(t *testing.T) {
	f := &Filter{ExcludeTypes: []string{"file_stat", "dir_list"}}

	tests := []struct {
		eventType string
		want      bool
	}{
		{"file_write", true},
		{"file_stat", false},
		{"dir_list", false},
		{"net_connect", true},
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, "", ""); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.eventType, got, tt.want)
		}
	}
}

func TestFilter_IncludeCategories(t *testing.T) {
	f := &Filter{IncludeCategories: []string{"file", "network"}}

	tests := []struct {
		category string
		want     bool
	}{
		{"file", true},
		{"network", true},
		{"process", false},
		{"signal", false},
	}
	for _, tt := range tests {
		if got := f.Match("any", tt.category, ""); got != tt.want {
			t.Errorf("Match(category=%q) = %v, want %v", tt.category, got, tt.want)
		}
	}
}

func TestFilter_ExcludeCategories(t *testing.T) {
	f := &Filter{ExcludeCategories: []string{"environment"}}

	tests := []struct {
		category string
		want     bool
	}{
		{"file", true},
		{"environment", false},
	}
	for _, tt := range tests {
		if got := f.Match("any", tt.category, ""); got != tt.want {
			t.Errorf("Match(category=%q) = %v, want %v", tt.category, got, tt.want)
		}
	}
}

func TestFilter_MinRiskLevel(t *testing.T) {
	f := &Filter{MinRiskLevel: "medium"}

	tests := []struct {
		risk string
		want bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", false},
		{"", false}, // no risk = below threshold
	}
	for _, tt := range tests {
		if got := f.Match("any", "any", tt.risk); got != tt.want {
			t.Errorf("Match(risk=%q) = %v, want %v", tt.risk, got, tt.want)
		}
	}
}

func TestFilter_Combined(t *testing.T) {
	f := &Filter{
		IncludeCategories: []string{"file", "network"},
		ExcludeTypes:      []string{"file_stat"},
	}

	tests := []struct {
		eventType string
		category  string
		want      bool
	}{
		{"file_write", "file", true},
		{"file_stat", "file", false},   // excluded by type
		{"net_connect", "network", true},
		{"process_start", "process", false}, // not in included categories
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, tt.category, ""); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.eventType, tt.category, got, tt.want)
		}
	}
}
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/store/otel/ -run TestFilter -v
```

Expected: Compilation error — package and types don't exist yet.

**Step 3: Implement the filter**

Create `internal/store/otel/filter.go`:

```go
package otel

import (
	"path"
)

// Filter controls which events are exported via OTEL.
type Filter struct {
	IncludeTypes      []string
	ExcludeTypes      []string
	IncludeCategories []string
	ExcludeCategories []string
	MinRiskLevel      string
}

// riskLevels maps risk level strings to numeric values for comparison.
var riskLevels = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Match returns true if the event should be exported.
func (f *Filter) Match(eventType, category, riskLevel string) bool {
	if f == nil {
		return true
	}

	// Include type filter: if set, event type must match at least one pattern.
	if len(f.IncludeTypes) > 0 {
		matched := false
		for _, pattern := range f.IncludeTypes {
			if ok, _ := path.Match(pattern, eventType); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Include category filter: if set, category must be in the list.
	if len(f.IncludeCategories) > 0 {
		found := false
		for _, c := range f.IncludeCategories {
			if c == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Exclude type filter.
	for _, pattern := range f.ExcludeTypes {
		if ok, _ := path.Match(pattern, eventType); ok {
			return false
		}
	}

	// Exclude category filter.
	for _, c := range f.ExcludeCategories {
		if c == category {
			return false
		}
	}

	// Min risk level filter.
	if f.MinRiskLevel != "" {
		threshold := riskLevels[f.MinRiskLevel]
		actual := riskLevels[riskLevel]
		if actual < threshold {
			return false
		}
	}

	return true
}
```

**Step 4: Run tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/store/otel/ -run TestFilter -v
```

Expected: All filter tests pass.

**Step 5: Commit**

```bash
git add internal/store/otel/filter.go internal/store/otel/filter_test.go
git commit -m "feat(otel): add event filter with glob patterns, categories, and risk levels"
```

---

## Task 3: Implement Event-to-OTLP Converter

**Dependencies:** None (can run in parallel with Tasks 1, 2)

**Files:**
- Create: `internal/store/otel/convert.go`
- Create: `internal/store/otel/convert_test.go`

**Step 1: Add OTEL SDK dependencies**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go get go.opentelemetry.io/otel/sdk/log go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
```

**Step 2: Write converter tests**

Create `internal/store/otel/convert_test.go`:

```go
package otel

import (
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

	// Check timestamp
	if !rec.Timestamp().Equal(ev.Timestamp) {
		t.Errorf("timestamp = %v, want %v", rec.Timestamp(), ev.Timestamp)
	}

	// Check body contains event type and path
	body := rec.Body()
	if body.Kind() != otellog.KindString {
		t.Fatalf("body kind = %v, want String", body.Kind())
	}
	if body.AsString() == "" {
		t.Error("body should not be empty")
	}

	// Check severity - file_write with no decision defaults to INFO
	if rec.Severity() != otellog.SeverityInfo {
		t.Errorf("severity = %v, want INFO", rec.Severity())
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

func TestConvertToLogRecord_TraceCorrelation(t *testing.T) {
	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "s",
		Fields: map[string]any{
			"trace_id": "0af7651916cd43dd8448eb211c80319c",
			"span_id":  "b7ad6b7169203331",
		},
	}

	rec := convertToLogRecord(ev)

	if rec.TraceID().String() != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace_id = %q", rec.TraceID().String())
	}
	if rec.SpanID().String() != "b7ad6b7169203331" {
		t.Errorf("span_id = %q", rec.SpanID().String())
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
	assertAttr(t, attrs, "agentsh.event.type", "file_write")
	assertAttr(t, attrs, "agentsh.session.id", "sess-1")
	assertAttr(t, attrs, "agentsh.command.id", "cmd-1")
	assertAttr(t, attrs, "agentsh.decision", "allow")
	assertAttr(t, attrs, "agentsh.policy.rule", "allow-workspace")
}

func TestBuildResource(t *testing.T) {
	res := buildResource("my-agentsh", map[string]string{"env": "prod"})

	attrs := res.Attributes()
	found := map[string]string{}
	for _, a := range attrs {
		if a.Value.Type() == attribute.STRING {
			found[string(a.Key)] = a.Value.AsString()
		}
	}

	if found["service.name"] != "my-agentsh" {
		t.Errorf("service.name = %q", found["service.name"])
	}
	if found["env"] != "prod" {
		t.Errorf("env = %q", found["env"])
	}
}

// Helper: extract attributes from a log record into a map.
func logRecordAttrs(rec otellog.Record) map[string]otellog.Value {
	m := make(map[string]otellog.Value)
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		m[kv.Key] = kv.Value
		return true
	})
	return m
}

// Helper: assert an attribute exists with expected value.
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
	}
}
```

**Step 3: Run tests to verify they fail**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/store/otel/ -run TestConvert -v
```

Expected: Compilation error — converter functions don't exist.

**Step 4: Implement the converter**

Create `internal/store/otel/convert.go`:

```go
package otel

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// convertToLogRecord converts an agentsh Event to an OTEL LogRecord.
func convertToLogRecord(ev types.Event) otellog.Record {
	var rec otellog.Record

	rec.SetTimestamp(ev.Timestamp)
	rec.SetBody(otellog.StringValue(eventBody(ev)))
	rec.SetSeverity(eventSeverity(ev))

	// Trace correlation
	if traceID, ok := extractTraceID(ev); ok {
		rec.SetTraceID(traceID)
	}
	if spanID, ok := extractSpanID(ev); ok {
		rec.SetSpanID(spanID)
	}

	// Build attributes
	attrs := eventAttributes(ev)
	rec.AddAttributes(attrs...)

	return rec
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

// eventAttributes builds OTEL attributes from an event using semantic conventions.
func eventAttributes(ev types.Event) []otellog.KeyValue {
	var attrs []otellog.KeyValue

	// Semantic conventions: process
	if ev.PID != 0 {
		attrs = append(attrs, otellog.Int("process.pid", ev.PID))
	}
	if ev.ParentPID != 0 {
		attrs = append(attrs, otellog.Int("process.parent_pid", ev.ParentPID))
	}
	if ev.Filename != "" {
		attrs = append(attrs, otellog.String("process.executable.path", ev.Filename))
	}

	// agentsh namespace
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

	// Policy info
	if ev.Policy != nil {
		if ev.Policy.Decision != "" {
			attrs = append(attrs, otellog.String("agentsh.decision", string(ev.Policy.Decision)))
		}
		if ev.Policy.Rule != "" {
			attrs = append(attrs, otellog.String("agentsh.policy.rule", ev.Policy.Rule))
		}
	}

	// Fields - add selected well-known fields
	if ev.Fields != nil {
		for _, key := range []string{
			"risk_level", "agent_id", "agent_type", "agent_framework",
			"tenant_id", "workspace_id", "policy_name",
			"latency_us", "queue_time_us", "policy_eval_us",
			"intercept_us", "backend_us", "error", "error_code",
		} {
			if v, ok := ev.Fields[key]; ok {
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
	}

	return attrs
}

// extractTraceID parses a trace ID from event fields.
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

// extractSpanID parses a span ID from event fields.
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

// buildResource creates an OTEL Resource with agentsh service attributes.
func buildResource(serviceName string, extraAttrs map[string]string) *resource.Resource {
	attrs := []resource.Option{
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	}
	for k, v := range extraAttrs {
		attrs = append(attrs, resource.WithAttributes(
			semconv.ServiceName(serviceName), // needed for dedup
		))
		_ = k
		_ = v
	}

	// Build with extra attributes using a slice
	kvs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	for k, v := range extraAttrs {
		kvs = append(kvs, attribute.String(k, v))
	}

	res, _ := resource.New(
		resource.WithAttributes(kvs...),
	)
	return res
}
```

Note: The converter uses `otellog.Record` directly. The `buildResource` function uses `resource.New()` with proper attribute setup. You'll need to add `"go.opentelemetry.io/otel/attribute"` to the imports. Adjust the `buildResource` function to properly handle the duplicate logic — the clean version is:

```go
func buildResource(serviceName string, extraAttrs map[string]string) *resource.Resource {
	kvs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	for k, v := range extraAttrs {
		kvs = append(kvs, attribute.String(k, v))
	}
	res, _ := resource.New(
		resource.WithAttributes(kvs...),
	)
	return res
}
```

**Step 5: Run tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/store/otel/ -run "TestConvert|TestBuild" -v
```

Expected: All converter tests pass.

**Step 6: Commit**

```bash
git add internal/store/otel/convert.go internal/store/otel/convert_test.go
git commit -m "feat(otel): add event-to-OTLP converter with semantic convention attributes"
```

---

## Task 4: Implement OTEL Store

**Dependencies:** Tasks 1, 2, 3 must be complete.

**Files:**
- Create: `internal/store/otel/otel.go`
- Create: `internal/store/otel/otel_test.go`

**Step 1: Write store tests**

Create `internal/store/otel/otel_test.go`:

```go
package otel

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestStore_AppendEvent_Filtered(t *testing.T) {
	// Create store with a filter that only allows file events
	st, err := newTestStore(t, &Filter{
		IncludeCategories: []string{"file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()

	// File event — should be exported
	fileEv := types.Event{
		ID:        "1",
		Timestamp: time.Now().UTC(),
		Type:      "file_write",
		SessionID: "s",
		Fields:    map[string]any{"category": "file"},
	}
	if err := st.AppendEvent(ctx, fileEv); err != nil {
		t.Fatal(err)
	}

	// Net event — should be filtered out
	netEv := types.Event{
		ID:        "2",
		Timestamp: time.Now().UTC(),
		Type:      "net_connect",
		SessionID: "s",
		Fields:    map[string]any{"category": "network"},
	}
	if err := st.AppendEvent(ctx, netEv); err != nil {
		t.Fatal(err)
	}

	// Verify only 1 event was exported (via the test log exporter)
	if got := st.logExportCount(); got != 1 {
		t.Errorf("exported %d log records, want 1", got)
	}
}

func TestStore_QueryEvents_NotSupported(t *testing.T) {
	st, err := newTestStore(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.QueryEvents(context.Background(), types.EventQuery{})
	if err == nil {
		t.Error("expected error from QueryEvents")
	}
}

func TestStore_Close_Flushes(t *testing.T) {
	st, err := newTestStore(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	ev := types.Event{
		ID:        "1",
		Timestamp: time.Now().UTC(),
		Type:      "file_write",
		SessionID: "s",
	}
	if err := st.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if got := st.logExportCount(); got != 1 {
		t.Errorf("after close: exported %d, want 1", got)
	}
}
```

The `newTestStore` helper and `logExportCount` method will be implemented in the store using OTEL SDK's in-memory/test exporters.

**Step 2: Implement the store**

Create `internal/store/otel/otel.go`:

```go
package otel

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

// Store exports agentsh events via OpenTelemetry.
type Store struct {
	filter *Filter
	res    *resource.Resource

	logProvider   *sdklog.LoggerProvider
	logger        otellog.Logger
	traceProvider *sdktrace.TracerProvider

	enableLogs  bool
	enableSpans bool

	dropped atomic.Int64
}

// Config holds configuration for the OTEL store.
type Config struct {
	Endpoint string
	Protocol string // "grpc" or "http"
	TLS      config.OTELTLSConfig
	Headers  map[string]string
	Timeout  string
	Signals  config.OTELSignalsConfig
	Batch    config.OTELBatchConfig
	Filter   config.OTELFilterConfig
	Resource config.OTELResourceConfig
}

// New creates a new OTEL event store.
func New(ctx context.Context, cfg Config) (*Store, error) {
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse otel timeout: %w", err)
	}

	batchTimeout, err := time.ParseDuration(cfg.Batch.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse otel batch timeout: %w", err)
	}

	res := buildResource(cfg.Resource.ServiceName, cfg.Resource.ExtraAttributes)

	filter := &Filter{
		IncludeTypes:      cfg.Filter.IncludeTypes,
		ExcludeTypes:      cfg.Filter.ExcludeTypes,
		IncludeCategories: cfg.Filter.IncludeCategories,
		ExcludeCategories: cfg.Filter.ExcludeCategories,
		MinRiskLevel:      cfg.Filter.MinRiskLevel,
	}

	s := &Store{
		filter:      filter,
		res:         res,
		enableLogs:  cfg.Signals.Logs,
		enableSpans: cfg.Signals.Spans,
	}

	// Initialize log exporter and provider
	if cfg.Signals.Logs {
		var logExporter sdklog.Exporter
		switch cfg.Protocol {
		case "http":
			logExporter, err = otlploghttp.New(ctx,
				otlploghttp.WithEndpoint(cfg.Endpoint),
				otlploghttp.WithTimeout(timeout),
				otlploghttp.WithHeaders(cfg.Headers),
			)
		default: // grpc
			logExporter, err = otlploggrpc.New(ctx,
				otlploggrpc.WithEndpoint(cfg.Endpoint),
				otlploggrpc.WithTimeout(timeout),
				otlploggrpc.WithHeaders(cfg.Headers),
			)
		}
		if err != nil {
			return nil, fmt.Errorf("create otel log exporter: %w", err)
		}

		s.logProvider = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter,
				sdklog.WithMaxQueueSize(cfg.Batch.MaxSize),
				sdklog.WithExportTimeout(batchTimeout),
			)),
		)
		s.logger = s.logProvider.Logger("agentsh")
	}

	// Initialize trace exporter and provider
	if cfg.Signals.Spans {
		var traceExporter sdktrace.SpanExporter
		switch cfg.Protocol {
		case "http":
			traceExporter, err = otlptracehttp.New(ctx,
				otlptracehttp.WithEndpoint(cfg.Endpoint),
				otlptracehttp.WithTimeout(timeout),
				otlptracehttp.WithHeaders(cfg.Headers),
			)
		default: // grpc
			traceExporter, err = otlptracegrpc.New(ctx,
				otlptracegrpc.WithEndpoint(cfg.Endpoint),
				otlptracegrpc.WithTimeout(timeout),
				otlptracegrpc.WithHeaders(cfg.Headers),
			)
		}
		if err != nil {
			return nil, fmt.Errorf("create otel trace exporter: %w", err)
		}

		s.traceProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithBatcher(traceExporter,
				sdktrace.WithMaxQueueSize(cfg.Batch.MaxSize),
				sdktrace.WithExportTimeout(batchTimeout),
			),
		)
	}

	return s, nil
}

// AppendEvent converts an event and sends it to the OTEL exporters.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	// Resolve category from event type
	category := events.EventCategory[events.EventType(ev.Type)]
	riskLevel, _ := ev.Fields["risk_level"].(string)

	if !s.filter.Match(ev.Type, category, riskLevel) {
		return nil
	}

	if s.enableLogs && s.logger != nil {
		rec := convertToLogRecord(ev)
		s.logger.Emit(ctx, rec)
	}

	// Span export can be added in a follow-up if needed.
	// The trace provider is initialized and ready.

	return nil
}

// QueryEvents is not supported for the OTEL store.
func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, fmt.Errorf("otel store does not support queries")
}

// Dropped returns the number of dropped events.
func (s *Store) Dropped() int64 {
	return s.dropped.Load()
}

// Close shuts down the OTEL exporters, flushing any pending data.
func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var firstErr error
	if s.logProvider != nil {
		if err := s.logProvider.Shutdown(ctx); err != nil {
			slog.Warn("otel log provider shutdown", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if s.traceProvider != nil {
		if err := s.traceProvider.Shutdown(ctx); err != nil {
			slog.Warn("otel trace provider shutdown", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
```

Add a test helper at the bottom of the test file or in a `helpers_test.go`:

```go
// newTestStore creates a Store with in-memory exporters for testing.
func newTestStore(t *testing.T, filter *Filter) (*testableStore, error) {
	t.Helper()

	// Use a simple log exporter that counts records
	exporter := &countingLogExporter{}

	res := buildResource("agentsh-test", nil)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)),
	)

	s := &Store{
		filter:     filter,
		res:        res,
		logProvider: provider,
		logger:     provider.Logger("agentsh-test"),
		enableLogs: true,
	}

	return &testableStore{Store: s, logExp: exporter}, nil
}

type testableStore struct {
	*Store
	logExp *countingLogExporter
}

func (ts *testableStore) logExportCount() int {
	return int(ts.logExp.count.Load())
}

type countingLogExporter struct {
	count atomic.Int64
}

func (e *countingLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	e.count.Add(int64(len(records)))
	return nil
}

func (e *countingLogExporter) Shutdown(ctx context.Context) error { return nil }
func (e *countingLogExporter) ForceFlush(ctx context.Context) error { return nil }
```

Note: You'll need `"sync/atomic"` in the test imports for the `atomic.Int64`. Adjust imports as the OTEL SDK API requires — the exact types may need adapting to the v1.39.0 API surface. Check `go doc go.opentelemetry.io/otel/sdk/log` for the exact `Exporter` interface.

**Step 3: Run tests**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./internal/store/otel/ -v
```

Expected: All tests pass (filter + converter + store tests).

**Step 4: Verify cross-compilation**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && GOOS=windows go build ./...
```

**Step 5: Commit**

```bash
git add internal/store/otel/otel.go internal/store/otel/otel_test.go go.mod go.sum
git commit -m "feat(otel): implement OTEL event store with log export and batching"
```

---

## Task 5: Wire OTEL Store into Server

**Dependencies:** Tasks 1 and 4 must be complete.

**Files:**
- Modify: `internal/server/server.go`

**Step 1: Add OTEL store initialization**

In `internal/server/server.go`, add the import:

```go
otelstore "github.com/agentsh/agentsh/internal/store/otel"
```

In the `New` function, after the webhook store creation block (after line ~147, before the `var eventStores` line), add:

```go
	var otelStore *otelstore.Store
	if cfg.Audit.OTEL.Enabled {
		otelStore, err = otelstore.New(context.Background(), otelstore.Config{
			Endpoint: cfg.Audit.OTEL.Endpoint,
			Protocol: cfg.Audit.OTEL.Protocol,
			TLS:      cfg.Audit.OTEL.TLS,
			Headers:  cfg.Audit.OTEL.Headers,
			Timeout:  cfg.Audit.OTEL.Timeout,
			Signals:  cfg.Audit.OTEL.Signals,
			Batch:    cfg.Audit.OTEL.Batch,
			Filter:   cfg.Audit.OTEL.Filter,
			Resource: cfg.Audit.OTEL.Resource,
		})
		if err != nil {
			slog.Error("failed to create OTEL store, continuing without it", "error", err)
			otelStore = nil
		}
	}
```

Then in the `eventStores` assembly block (around line ~150), add:

```go
	if otelStore != nil {
		eventStores = append(eventStores, otelStore)
	}
```

**Step 2: Build and test**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go build ./... && go test ./internal/server/ -v
```

Expected: Build succeeds, existing server tests pass.

**Step 3: Cross-compile check**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && GOOS=windows go build ./...
```

**Step 4: Run full test suite**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./...
```

Expected: All tests pass.

**Step 5: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(otel): wire OTEL store into composite store chain"
```

---

## Task 6: Integration Test with Docker OTEL Collector

**Dependencies:** Task 5 must be complete.

**Files:**
- Create: `internal/store/otel/integration_test.go`
- Create: `internal/store/otel/testdata/otel-collector-config.yaml`

**Step 1: Create collector config**

Create `internal/store/otel/testdata/otel-collector-config.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
      http:
        endpoint: "0.0.0.0:4318"

exporters:
  file:
    path: /tmp/otel-output.json

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [file]
    traces:
      receivers: [otlp]
      exporters: [file]
```

**Step 2: Write integration test**

Create `internal/store/otel/integration_test.go`:

```go
//go:build otel_integration

package otel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestIntegration_OTELCollector requires Docker and the OTEL Collector image.
// Run with: go test -tags otel_integration -v ./internal/store/otel/
func TestIntegration_OTELCollector(t *testing.T) {
	// Check docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create temp dir for output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "otel-output.json")
	os.WriteFile(outputFile, []byte(""), 0644)

	// Get collector config path
	collectorCfg, _ := filepath.Abs("testdata/otel-collector-config.yaml")

	// Start OTEL Collector container
	containerName := fmt.Sprintf("otel-test-%d", time.Now().UnixNano())
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", containerName,
		"-p", "4317:4317",
		"-p", "4318:4318",
		"-v", collectorCfg+":/etc/otelcol/config.yaml",
		"-v", outputFile+":/tmp/otel-output.json",
		"otel/opentelemetry-collector:latest",
		"--config", "/etc/otelcol/config.yaml",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("start collector: %v\n%s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", containerName).Run()

	// Wait for collector to be ready
	time.Sleep(3 * time.Second)

	// Create OTEL store pointing at the collector
	store, err := New(ctx, Config{
		Endpoint: "localhost:4317",
		Protocol: "grpc",
		Timeout:  "10s",
		Signals:  config.OTELSignalsConfig{Logs: true},
		Batch:    config.OTELBatchConfig{MaxSize: 10, Timeout: "1s"},
		Filter:   config.OTELFilterConfig{},
		Resource: config.OTELResourceConfig{ServiceName: "agentsh-integration-test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send test events
	for i := 0; i < 5; i++ {
		ev := types.Event{
			ID:        fmt.Sprintf("evt-%d", i),
			Timestamp: time.Now().UTC(),
			Type:      "file_write",
			SessionID: "integration-test",
			Path:      fmt.Sprintf("/workspace/file-%d.txt", i),
		}
		if err := store.AppendEvent(ctx, ev); err != nil {
			t.Fatalf("append event %d: %v", i, err)
		}
	}

	// Close to flush
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Wait for collector to write output
	time.Sleep(3 * time.Second)

	// Read output file
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("collector output file is empty — events were not exported")
	}

	t.Logf("Collector output (%d bytes): %s", len(data), string(data[:min(len(data), 500)]))

	// Parse output (OTLP JSON format — line-delimited JSON objects)
	// Basic validation: should contain our service name and event type
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		// May be line-delimited, try first line
		t.Logf("output is not single JSON object (may be line-delimited), raw check")
	}

	output := string(data)
	if !contains(output, "agentsh-integration-test") {
		t.Error("output missing service name")
	}
	if !contains(output, "file_write") {
		t.Error("output missing event type")
	}

	t.Log("Integration test passed: events successfully exported to OTEL Collector")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

**Step 3: Run integration test (if Docker available)**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test -tags otel_integration -v -timeout 120s ./internal/store/otel/
```

Expected: Test passes if Docker is available and OTEL collector image can be pulled.

**Step 4: Run full test suite to ensure nothing is broken**

```bash
cd /home/eran/work/agentsh/.worktrees/feat-otel-export && go test ./...
```

Expected: All existing + new tests pass. The integration test is skipped without the build tag.

**Step 5: Commit**

```bash
git add internal/store/otel/integration_test.go internal/store/otel/testdata/
git commit -m "test(otel): add Docker-based OTEL Collector integration test"
```
