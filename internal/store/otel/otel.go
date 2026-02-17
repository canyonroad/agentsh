// Package otel implements a store.EventStore that exports events via
// OpenTelemetry (OTLP). It converts agentsh events to OTEL log records,
// shipping them to a configured collector.
package otel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"

	sdklog "go.opentelemetry.io/otel/sdk/log"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
)

// Config holds the configuration needed to construct a Store.
type Config struct {
	Endpoint string
	Protocol string // "grpc" or "http"

	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSInsecure bool // skip server certificate verification

	Headers map[string]string

	Timeout      time.Duration
	BatchTimeout time.Duration
	BatchMaxSize int

	Signals struct {
		Logs bool
	}

	Filter Filter

	Resource *resource.Resource
}

// Store implements store.EventStore by exporting events via OTEL.
// It is safe for concurrent use. Export errors are silently dropped
// so that audit recording never blocks the caller.
type Store struct {
	filter   *Filter
	resource *resource.Resource

	logProvider *sdklog.LoggerProvider
	logger      otellog.Logger

	enableLogs bool
}

// New creates a new OTEL Store. The context is used for creating exporters.
func New(ctx context.Context, cfg Config) (*Store, error) {
	s := &Store{
		filter:     &cfg.Filter,
		resource:   cfg.Resource,
		enableLogs: cfg.Signals.Logs,
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

// Close shuts down the log provider, flushing any pending records.
// A 10-second timeout is applied.
func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.logProvider != nil {
		if err := s.logProvider.Shutdown(ctx); err != nil {
			slog.Warn("otel log provider shutdown error", "error", err)
			return err
		}
	}

	return nil
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
		if cfg.TLSEnabled {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: cfg.TLSInsecure,
			}
			if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
				if err != nil {
					return nil, fmt.Errorf("load TLS client cert: %w", err)
				}
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
			opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		} else {
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
		if cfg.TLSEnabled {
			tlsCfg := &tls.Config{
				InsecureSkipVerify: cfg.TLSInsecure,
			}
			if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
				cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
				if err != nil {
					return nil, fmt.Errorf("load TLS client cert: %w", err)
				}
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
			opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
		} else {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unsupported OTEL protocol %q", cfg.Protocol)
	}
}
