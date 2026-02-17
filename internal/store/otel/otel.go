// Package otel implements a store.EventStore that exports events via
// OpenTelemetry (OTLP). It converts agentsh events to OTEL log records
// and optionally trace spans, shipping them to a configured collector.
package otel

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/resource"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

// Config holds the configuration needed to construct a Store.
type Config struct {
	Endpoint string
	Protocol string // "grpc" or "http"

	TLSEnabled bool

	Headers map[string]string

	Timeout      time.Duration
	BatchTimeout time.Duration
	BatchMaxSize int

	Signals struct {
		Logs  bool
		Spans bool
	}

	Filter Filter

	Resource *resource.Resource
}

// Store implements store.EventStore by exporting events via OTEL.
// It is safe for concurrent use. Export errors are silently dropped
// so that audit recording never blocks the caller.
type Store struct {
	filter *Filter
	resource *resource.Resource

	logProvider   *sdklog.LoggerProvider
	logger        otellog.Logger
	traceProvider *sdktrace.TracerProvider

	enableLogs  bool
	enableSpans bool

	dropped atomic.Int64
}

// New creates a new OTEL Store. The context is used for creating exporters.
func New(ctx context.Context, cfg Config) (*Store, error) {
	s := &Store{
		filter:      &cfg.Filter,
		resource:    cfg.Resource,
		enableLogs:  cfg.Signals.Logs,
		enableSpans: cfg.Signals.Spans,
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	batchTimeout := cfg.BatchTimeout
	if batchTimeout == 0 {
		batchTimeout = 5 * time.Second
	}
	batchMaxSize := cfg.BatchMaxSize
	if batchMaxSize == 0 {
		batchMaxSize = 512
	}

	// Set up log signal.
	if s.enableLogs {
		logExp, err := newLogExporter(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("otel log exporter: %w", err)
		}

		batchProc := sdklog.NewBatchProcessor(logExp,
			sdklog.WithExportTimeout(timeout),
			sdklog.WithExportInterval(batchTimeout),
			sdklog.WithExportMaxBatchSize(batchMaxSize),
		)

		s.logProvider = sdklog.NewLoggerProvider(
			sdklog.WithProcessor(batchProc),
			sdklog.WithResource(cfg.Resource),
		)
		s.logger = s.logProvider.Logger("agentsh")
	}

	// Set up trace signal.
	if s.enableSpans {
		traceExp, err := newTraceExporter(ctx, cfg)
		if err != nil {
			// Clean up log provider if already created.
			if s.logProvider != nil {
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = s.logProvider.Shutdown(shutCtx)
			}
			return nil, fmt.Errorf("otel trace exporter: %w", err)
		}

		s.traceProvider = sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(traceExp),
			sdktrace.WithResource(cfg.Resource),
		)
	}

	return s, nil
}

// AppendEvent converts and exports the event via OTEL. Filtering is applied
// first. Export errors are silently dropped to avoid blocking the caller.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	// Resolve category.
	category := events.EventCategory[events.EventType(ev.Type)]

	// Extract risk_level from fields.
	var riskLevel string
	if ev.Fields != nil {
		if rl, ok := ev.Fields["risk_level"].(string); ok {
			riskLevel = rl
		}
	}

	// Apply filter.
	if !s.filter.Match(ev.Type, category, riskLevel) {
		return nil
	}

	// Export as log record.
	if s.enableLogs && s.logger != nil {
		rec := convertToLogRecord(ev)
		emitCtx := eventContext(ctx, ev)
		s.logger.Emit(emitCtx, rec)
	}

	return nil
}

// QueryEvents is not supported by the OTEL store. Events are exported
// in a fire-and-forget fashion and cannot be queried back.
func (s *Store) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, fmt.Errorf("otel store does not support queries")
}

// Close shuts down both the log and trace providers, flushing any
// pending records. A 10-second timeout is applied.
func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.logProvider != nil {
		if err := s.logProvider.Shutdown(ctx); err != nil {
			slog.Warn("otel log provider shutdown error", "error", err)
		}
	}

	if s.traceProvider != nil {
		if err := s.traceProvider.Shutdown(ctx); err != nil {
			slog.Warn("otel trace provider shutdown error", "error", err)
		}
	}

	return nil
}

// Dropped returns the total count of events that were dropped due to
// export errors or queue overflow.
func (s *Store) Dropped() int64 {
	return s.dropped.Load()
}

// newLogExporter creates an OTLP log exporter using the configured protocol.
func newLogExporter(ctx context.Context, cfg Config) (sdklog.Exporter, error) {
	switch cfg.Protocol {
	case "grpc":
		opts := []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, otlploggrpc.WithTimeout(cfg.Timeout))
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
		}
		if !cfg.TLSEnabled {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		return otlploggrpc.New(ctx, opts...)

	case "http":
		opts := []otlploghttp.Option{
			otlploghttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, otlploghttp.WithTimeout(cfg.Timeout))
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
		}
		if !cfg.TLSEnabled {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unsupported OTEL protocol %q", cfg.Protocol)
	}
}

// newTraceExporter creates an OTLP trace exporter using the configured protocol.
func newTraceExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch cfg.Protocol {
	case "grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, otlptracegrpc.WithTimeout(cfg.Timeout))
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		if !cfg.TLSEnabled {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptracegrpc.New(ctx, opts...)

	case "http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Timeout > 0 {
			opts = append(opts, otlptracehttp.WithTimeout(cfg.Timeout))
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		if !cfg.TLSEnabled {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return otlptracehttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unsupported OTEL protocol %q", cfg.Protocol)
	}
}
