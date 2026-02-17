# OpenTelemetry Event Export Design

## Overview

Add an OTEL exporter as a new store backend in the composite store chain, enabling agentsh to export audit events to any OpenTelemetry-compatible collector. Events are exported as OTEL Logs and/or Spans, with configurable filtering and support for both gRPC and HTTP OTLP protocols.

## Motivation

agentsh currently persists events to SQLite, JSONL files, and optional webhooks. Organizations using OpenTelemetry-based observability stacks (Grafana, Datadog, Honeycomb, etc.) need a native way to ingest agentsh audit events alongside their existing telemetry pipelines for unified querying, alerting, and dashboarding.

## Architecture

### Integration Point

The OTEL exporter plugs into the existing composite store as another write-only backend:

```
composite.Store
  ├── SQLite       (primary, reads + writes)
  ├── JSONL        (write-only)
  ├── Webhook      (batched write-only)
  └── OTEL Store   (batched write-only)  ← NEW
```

This follows the same pattern as the webhook store — no changes to the event pipeline.

### Package Structure

```
internal/store/otel/
├── otel.go          # Store struct, AppendEvent, Close, init exporters
├── convert.go       # Event → OTLP LogRecord/Span conversion
├── filter.go        # Event filtering logic (include/exclude/risk)
└── otel_test.go     # Tests with in-memory exporter
```

### Data Flow

```
AppendEvent(ctx, event)
  │
  ├── filter.Match(event) ── false ──→ return nil (skip)
  │
  └── true
       │
       ├── if signals.logs:
       │     convertToLogRecord(event) → OTEL Logs SDK batch processor
       │
       └── if signals.spans:
             convertToSpan(event) → OTEL Traces SDK batch processor
```

The OTEL SDK handles batching and export internally via its `BatchProcessor`, so the store only converts and hands off.

### Initialization

```go
if cfg.Audit.OTEL.Enabled {
    otelStore, err := otel.New(ctx, otel.Config{
        Endpoint:   cfg.Audit.OTEL.Endpoint,
        Protocol:   cfg.Audit.OTEL.Protocol,
        TLS:        cfg.Audit.OTEL.TLS,
        Headers:    cfg.Audit.OTEL.Headers,
        Signals:    cfg.Audit.OTEL.Signals,
        Filter:     cfg.Audit.OTEL.Filter,
        Resource:   cfg.Audit.OTEL.Resource,
        Batch:      cfg.Audit.OTEL.Batch,
    })
    compositeStore = composite.New(primary, output, jsonlStore, webhookStore, otelStore)
}
```

## Configuration

New `otel` block under `audit`:

```yaml
audit:
  otel:
    enabled: false
    endpoint: "localhost:4317"
    protocol: grpc              # "grpc" or "http"
    tls:
      enabled: false
      cert_file: ""
      key_file: ""
      insecure: false           # skip TLS verification (dev only)
    headers:                    # custom headers (auth tokens, etc.)
      Authorization: "Bearer ${OTEL_TOKEN}"
    timeout: "10s"

    # Signal types to export (all enabled by default when otel.enabled=true)
    signals:
      logs: true
      spans: true

    # Batching (OTEL SDK defaults are good, but overridable)
    batch:
      max_size: 512
      timeout: "5s"

    # Event filtering
    filter:
      include_types: []         # glob patterns, e.g. ["file_*", "net_*"]
      exclude_types: []         # glob patterns, e.g. ["file_stat", "dir_list"]
      include_categories: []    # e.g. ["file", "network", "process"]
      exclude_categories: []
      min_risk_level: ""        # "low", "medium", "high", "critical"

    # Resource attributes (auto-detected, but overridable)
    resource:
      service_name: "agentsh"
      extra_attributes: {}      # additional key-value pairs
```

### Environment Variable Overrides

| Env Var | Config Field |
|---|---|
| `AGENTSH_OTEL_ENDPOINT` | `audit.otel.endpoint` |
| `AGENTSH_OTEL_PROTOCOL` | `audit.otel.protocol` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Fallback if `AGENTSH_OTEL_ENDPOINT` not set |

## Attribute Mapping

### Resource Attributes (set once per exporter)

| OTEL Attribute | Source |
|---|---|
| `service.name` | `"agentsh"` (or config override) |
| `service.version` | `agentsh_version` |
| `host.name` | `hostname` |
| `host.id` | `machine_id` |
| `host.arch` | `arch` |
| `os.type` | `os` |
| `os.version` | `os_version` |
| `os.description` | `os_distro` |
| `host.ip` | `ipv4_addresses[0]` |
| `container.id` | `container_id` |
| `container.image.name` | `container_image` |
| `k8s.namespace.name` | `k8s_namespace` |
| `k8s.pod.name` | `k8s_pod` |
| `k8s.node.name` | `k8s_node` |
| `k8s.cluster.name` | `k8s_cluster` |

### Per-Event Attributes

**Standard OTEL semantic conventions:**

| OTEL Attribute | Source |
|---|---|
| `process.pid` | `pid` |
| `process.parent_pid` | `ppid` |
| `process.executable.name` | `process_name` |
| `process.executable.path` | `executable` |
| `process.command_line` | `cmdline` (joined) |
| `process.cpu.utilization` | resource event fields |
| `process.memory.usage` | resource event fields |
| `user.id` | `uid` |
| `user.name` | `username` |

**agentsh-specific attributes (`agentsh.*` namespace):**

| OTEL Attribute | Source |
|---|---|
| `agentsh.event.id` | `event_id` |
| `agentsh.event.type` | `type` |
| `agentsh.event.category` | `category` |
| `agentsh.session.id` | `session_id` |
| `agentsh.command.id` | `command_id` |
| `agentsh.decision` | `decision` |
| `agentsh.policy.rule` | `policy_rule` |
| `agentsh.policy.name` | `policy_name` |
| `agentsh.risk.level` | `risk_level` |
| `agentsh.agent.id` | `agent_id` |
| `agentsh.agent.type` | `agent_type` |
| `agentsh.agent.framework` | `agent_framework` |
| `agentsh.tenant.id` | `tenant_id` |
| `agentsh.workspace.id` | `workspace_id` |
| `agentsh.resource.max_memory_mb` | resource limit fields |
| `agentsh.resource.cpu_quota_percent` | resource limit fields |
| `agentsh.perf.latency_us` | `latency_us` |
| `agentsh.perf.queue_time_us` | `queue_time_us` |
| `agentsh.perf.policy_eval_us` | `policy_eval_us` |
| `agentsh.perf.intercept_us` | `intercept_us` |
| `agentsh.perf.backend_us` | `backend_us` |
| `agentsh.error` | `error` |
| `agentsh.error.code` | `error_code` |

Event-type-specific fields (e.g. `path`, `domain`, `remote` from `types.Event.Fields`) are added as additional `agentsh.*` attributes.

### LogRecord Specifics

- **Body**: Human-readable summary, e.g. `"file_write: /workspace/foo.txt [allow]"`
- **SeverityNumber**: Derived from decision:
  - `INFO` — allow, audit
  - `WARN` — redirect, approve, soft_delete
  - `ERROR` — deny
- **TraceID / SpanID**: Carried from `trace_id` / `span_id` for correlation with existing tracing spans

### Span Specifics

- **Name**: Event type (e.g. `"file_write"`)
- **Kind**: `INTERNAL`
- **Status**: `OK` for allow, `ERROR` for deny
- **Duration**: `latency_us` if available, otherwise zero-duration point event

## Filtering

Filter evaluation order — include first, then exclude, then risk level:

```go
type Filter struct {
    IncludeTypes      []string  // glob patterns
    ExcludeTypes      []string  // glob patterns
    IncludeCategories []string  // exact match
    ExcludeCategories []string
    MinRiskLevel      string    // "", "low", "medium", "high", "critical"
}

func (f *Filter) Match(eventType, category, riskLevel string) bool
```

1. If `IncludeTypes` non-empty: event type must match at least one glob. Otherwise all types pass.
2. If `IncludeCategories` non-empty: event category must be in list. Otherwise all categories pass.
3. If event type matches any `ExcludeTypes` glob: reject.
4. If event category in `ExcludeCategories`: reject.
5. If `MinRiskLevel` set: event risk must meet or exceed threshold. Events with no risk level are filtered out.
6. Nil/empty filter passes everything.

Glob matching uses Go's `path.Match` (supports `*` and `?`).

## Error Handling & Resilience

The OTEL exporter must never block or crash the main event pipeline.

- **Non-blocking failures**: `AppendEvent()` hands off to the SDK's async batch processor and returns `nil` on export failures. The SDK retries with backoff internally; events that fail after retries are dropped.
- **Logging, not failing**: Export errors logged via `slog.Warn`. A dropped counter `agentsh_otel_export_dropped_total` is exposed via existing Prometheus metrics.
- **Graceful shutdown**: `Close()` calls SDK `Shutdown(ctx)` with timeout (default 10s) to flush pending batches. Remaining events after timeout are lost (acceptable since they're in SQLite).
- **Startup resilience**: If OTEL endpoint is unreachable at startup, the exporter initializes anyway — SDK retries on first export. Invalid config logs an error and starts without the exporter.

## Testing Strategy

### Unit Tests (`internal/store/otel/otel_test.go`)

- **Conversion tests**: Given a `types.Event`, assert the resulting LogRecord/Span has correct attributes, severity, body, resource attributes, and trace correlation.
- **Filter tests**: Table-driven tests covering include/exclude globs, category matching, risk level thresholds, empty filter (pass-all), edge cases.
- **Store tests**: Push events through store with OTEL SDK in-memory exporter, verify correct events arrive and filtered ones don't.
- **Close test**: Verify pending events are flushed on shutdown.

Uses OTEL SDK test utilities: `go.opentelemetry.io/otel/sdk/log/logtest` and `tracetest`.

### Integration Test (build-tag gated: `//go:build otel_integration`)

Uses `testcontainers-go` to run the official OTEL Collector Docker image:

1. Start collector container with OTLP gRPC receiver (`:4317`), HTTP receiver (`:4318`), and `file` exporter writing to `/tmp/otel-output.json`.
2. Create `otel.Store` pointing at the container.
3. Push test events via `AppendEvent()`.
4. Wait, then read `/tmp/otel-output.json` from container.
5. Assert: correct record count, attributes match, severity correct, trace IDs correlated.

Collector config embedded in test:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:
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

### Config Tests (`internal/config/`)

Extend existing config parsing tests to verify the `otel` block parses correctly, defaults apply, and env var overrides work.

## Dependencies

The project already imports `go.opentelemetry.io/otel` for tracing. Additional:

- `go.opentelemetry.io/otel/sdk/log` — log SDK
- `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc`
- `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp`
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc`
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp`
- `github.com/testcontainers/testcontainers-go` (test only)
