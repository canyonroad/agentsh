package otel

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// countingLogExporter implements sdklog.Exporter and counts exported records.
type countingLogExporter struct {
	mu      sync.Mutex
	count   atomic.Int64
	records []sdklog.Record
}

func (e *countingLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.count.Add(int64(len(records)))
	e.mu.Lock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	e.mu.Unlock()
	return nil
}

func (e *countingLogExporter) Shutdown(_ context.Context) error { return nil }
func (e *countingLogExporter) ForceFlush(_ context.Context) error { return nil }

func (e *countingLogExporter) Count() int64 {
	return e.count.Load()
}

func (e *countingLogExporter) Records() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]sdklog.Record, len(e.records))
	copy(cp, e.records)
	return cp
}

// newTestStore creates a Store wired to a countingLogExporter using a
// SimpleProcessor. This avoids needing a real OTLP endpoint for tests.
func newTestStore(t *testing.T, filter *Filter) (*Store, *countingLogExporter) {
	t.Helper()

	exp := &countingLogExporter{}

	// Use SimpleProcessor for synchronous, predictable behavior in tests.
	proc := sdklog.NewSimpleProcessor(exp)
	res := BuildResource("agentsh-test", nil)

	logProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(proc),
		sdklog.WithResource(res),
	)

	if filter == nil {
		filter = &Filter{}
	}

	s := &Store{
		filter:      filter,
		resource:    res,
		logProvider: logProvider,
		logger:      logProvider.Logger("agentsh-test"),
		enableLogs:  true,
		enableSpans: false,
	}

	return s, exp
}

func TestStore_AppendEvent_Basic(t *testing.T) {
	s, exp := newTestStore(t, nil)
	defer s.Close()

	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "sess-1",
		Path:      "/workspace/test.go",
	}

	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	if got := exp.Count(); got != 1 {
		t.Errorf("exported count = %d, want 1", got)
	}
}

func TestStore_AppendEvent_Filtered(t *testing.T) {
	// Only include "file" category events.
	filter := &Filter{
		IncludeCategories: []string{"file"},
	}

	s, exp := newTestStore(t, filter)
	defer s.Close()

	// File event should pass.
	fileEv := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "sess-1",
		Path:      "/workspace/test.go",
	}
	if err := s.AppendEvent(context.Background(), fileEv); err != nil {
		t.Fatalf("AppendEvent(file): %v", err)
	}

	// Network event should be filtered out.
	netEv := types.Event{
		Timestamp: time.Now(),
		Type:      "net_connect",
		SessionID: "sess-1",
		Remote:    "1.2.3.4:443",
	}
	if err := s.AppendEvent(context.Background(), netEv); err != nil {
		t.Fatalf("AppendEvent(net): %v", err)
	}

	if got := exp.Count(); got != 1 {
		t.Errorf("exported count = %d, want 1 (only file event should pass)", got)
	}
}

func TestStore_QueryEvents_NotSupported(t *testing.T) {
	s, _ := newTestStore(t, nil)
	defer s.Close()

	_, err := s.QueryEvents(context.Background(), types.EventQuery{})
	if err == nil {
		t.Fatal("expected error from QueryEvents")
	}
	want := "otel store does not support queries"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestStore_Close_Flushes(t *testing.T) {
	s, exp := newTestStore(t, nil)

	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_create",
		SessionID: "sess-1",
		Path:      "/workspace/new.go",
	}

	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	// Close should flush any pending records.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// With SimpleProcessor, the record is exported synchronously on Emit,
	// so the count should be 1 after Close.
	if got := exp.Count(); got != 1 {
		t.Errorf("exported count after Close = %d, want 1", got)
	}
}

func TestStore_AppendEvent_MultipleEvents(t *testing.T) {
	s, exp := newTestStore(t, nil)
	defer s.Close()

	for i := 0; i < 5; i++ {
		ev := types.Event{
			Timestamp: time.Now(),
			Type:      "file_read",
			SessionID: "sess-1",
			Path:      "/workspace/file.go",
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent[%d]: %v", i, err)
		}
	}

	if got := exp.Count(); got != 5 {
		t.Errorf("exported count = %d, want 5", got)
	}
}

func TestStore_AppendEvent_LogsDisabled(t *testing.T) {
	exp := &countingLogExporter{}
	proc := sdklog.NewSimpleProcessor(exp)
	res := BuildResource("agentsh-test", nil)
	logProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(proc),
		sdklog.WithResource(res),
	)

	s := &Store{
		filter:      &Filter{},
		resource:    res,
		logProvider: logProvider,
		logger:      logProvider.Logger("agentsh-test"),
		enableLogs:  false, // Logs disabled.
		enableSpans: false,
	}
	defer s.Close()

	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_write",
		SessionID: "sess-1",
		Path:      "/workspace/test.go",
	}

	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	if got := exp.Count(); got != 0 {
		t.Errorf("exported count = %d, want 0 (logs disabled)", got)
	}
}
