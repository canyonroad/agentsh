package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestNewDispatcher(t *testing.T) {
	d := NewDispatcher()
	if d == nil {
		t.Fatal("NewDispatcher returned nil")
	}
	if d.webhooks == nil {
		t.Error("webhooks map is nil")
	}
	if d.client == nil {
		t.Error("client is nil")
	}
}

func TestDispatcher_Register(t *testing.T) {
	d := NewDispatcher()

	cfg := WebhookConfig{
		Name:    "test",
		URL:     "http://example.com/webhook",
		Events:  []string{"file_read", "file_write"},
		Enabled: true,
	}

	if err := d.Register(cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Verify defaults were applied
	got := d.Get("test")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Method != http.MethodPost {
		t.Errorf("Method = %s, want POST", got.Method)
	}
	if got.BatchSize != 1 {
		t.Errorf("BatchSize = %d, want 1", got.BatchSize)
	}
	if got.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", got.FlushInterval)
	}
	if got.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", got.Timeout)
	}

	// Verify event set
	if !got.eventSet["file_read"] {
		t.Error("eventSet missing file_read")
	}
	if !got.eventSet["file_write"] {
		t.Error("eventSet missing file_write")
	}
}

func TestDispatcher_Register_Template(t *testing.T) {
	d := NewDispatcher()

	cfg := WebhookConfig{
		Name:     "test",
		URL:      "http://example.com/webhook",
		Template: `{"event": "{{.Event.Type}}"}`,
		Enabled:  true,
	}

	if err := d.Register(cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := d.Get("test")
	if got.tmpl == nil {
		t.Error("template not compiled")
	}
}

func TestDispatcher_Register_InvalidTemplate(t *testing.T) {
	d := NewDispatcher()

	cfg := WebhookConfig{
		Name:     "test",
		URL:      "http://example.com/webhook",
		Template: `{{.Invalid`,
		Enabled:  true,
	}

	err := d.Register(cfg)
	if err == nil {
		t.Error("expected error for invalid template")
	}
}

func TestDispatcher_Unregister(t *testing.T) {
	d := NewDispatcher()

	cfg := WebhookConfig{
		Name:    "test",
		URL:     "http://example.com/webhook",
		Enabled: true,
	}
	d.Register(cfg)

	d.Unregister("test")

	if d.Get("test") != nil {
		t.Error("webhook should be nil after unregister")
	}
}

func TestDispatcher_List(t *testing.T) {
	d := NewDispatcher()

	d.Register(WebhookConfig{Name: "wh1", URL: "http://example.com/1", Enabled: true})
	d.Register(WebhookConfig{Name: "wh2", URL: "http://example.com/2", Enabled: true})

	list := d.List()
	if len(list) != 2 {
		t.Errorf("len(List) = %d, want 2", len(list))
	}
}

func TestWebhookConfig_MatchesEvent(t *testing.T) {
	tests := []struct {
		name      string
		events    []string
		eventType string
		want      bool
	}{
		{
			name:      "empty events matches all",
			events:    []string{},
			eventType: "file_read",
			want:      true,
		},
		{
			name:      "wildcard matches all",
			events:    []string{"*"},
			eventType: "file_read",
			want:      true,
		},
		{
			name:      "exact match",
			events:    []string{"file_read", "file_write"},
			eventType: "file_read",
			want:      true,
		},
		{
			name:      "no match",
			events:    []string{"file_read", "file_write"},
			eventType: "net_connect",
			want:      false,
		},
		{
			name:      "prefix wildcard match",
			events:    []string{"file_*"},
			eventType: "file_read",
			want:      true,
		},
		{
			name:      "prefix wildcard no match",
			events:    []string{"file_*"},
			eventType: "net_connect",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WebhookConfig{
				eventSet: make(map[string]bool),
			}
			for _, e := range tt.events {
				cfg.eventSet[e] = true
			}

			if got := cfg.matchesEvent(tt.eventType); got != tt.want {
				t.Errorf("matchesEvent(%s) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestDispatcher_Dispatch(t *testing.T) {
	var received []types.Event
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev types.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("unmarshal event: %v", err)
		}
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:      "test",
		URL:       server.URL,
		Events:    []string{"file_read"},
		BatchSize: 1,
		Enabled:   true,
	})

	ctx := context.Background()
	ev := types.Event{
		ID:        "ev1",
		Type:      "file_read",
		SessionID: "sess1",
		Path:      "/tmp/test.txt",
	}

	d.Dispatch(ctx, ev)

	// Wait for async send
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
	if len(received) > 0 && received[0].ID != "ev1" {
		t.Errorf("event ID = %s, want ev1", received[0].ID)
	}
}

func TestDispatcher_Dispatch_FilteredOut(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:      "test",
		URL:       server.URL,
		Events:    []string{"file_read"},
		BatchSize: 1,
		Enabled:   true,
	})

	ctx := context.Background()
	ev := types.Event{
		Type: "net_connect", // Not in events list
	}

	d.Dispatch(ctx, ev)
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&callCount) != 0 {
		t.Error("webhook should not be called for filtered event")
	}
}

func TestDispatcher_Dispatch_Disabled(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:      "test",
		URL:       server.URL,
		Events:    []string{"*"},
		BatchSize: 1,
		Enabled:   false, // Disabled
	})

	ctx := context.Background()
	ev := types.Event{Type: "file_read"}

	d.Dispatch(ctx, ev)
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&callCount) != 0 {
		t.Error("disabled webhook should not be called")
	}
}

func TestDispatcher_Dispatch_Template(t *testing.T) {
	var receivedBody string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:      "test",
		URL:       server.URL,
		Template:  `{"type": "{{.Event.Type}}", "session": "{{.Event.SessionID}}"}`,
		BatchSize: 1,
		Enabled:   true,
	})

	ctx := context.Background()
	ev := types.Event{
		Type:      "file_read",
		SessionID: "sess-123",
	}

	d.Dispatch(ctx, ev)
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var parsed map[string]string
	if err := json.Unmarshal([]byte(receivedBody), &parsed); err != nil {
		t.Fatalf("parse response: %v (body: %s)", err, receivedBody)
	}

	if parsed["type"] != "file_read" {
		t.Errorf("type = %s, want file_read", parsed["type"])
	}
	if parsed["session"] != "sess-123" {
		t.Errorf("session = %s, want sess-123", parsed["session"])
	}
}

func TestDispatcher_Batching(t *testing.T) {
	var receivedBatches [][]types.Event
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []types.Event
		if err := json.Unmarshal(body, &events); err != nil {
			t.Errorf("unmarshal events: %v", err)
		}
		mu.Lock()
		receivedBatches = append(receivedBatches, events)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:          "test",
		URL:           server.URL,
		BatchSize:     3,
		FlushInterval: 5 * time.Second, // Long interval, won't trigger
		Enabled:       true,
	})

	ctx := context.Background()

	// Send 3 events to trigger batch
	for i := 0; i < 3; i++ {
		d.Dispatch(ctx, types.Event{
			ID:   "ev" + string(rune('0'+i)),
			Type: "file_read",
		})
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBatches) != 1 {
		t.Errorf("received %d batches, want 1", len(receivedBatches))
	}
	if len(receivedBatches) > 0 && len(receivedBatches[0]) != 3 {
		t.Errorf("batch size = %d, want 3", len(receivedBatches[0]))
	}
}

func TestDispatcher_Flush(t *testing.T) {
	var received []types.Event
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev types.Event
		json.Unmarshal(body, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:          "test",
		URL:           server.URL,
		BatchSize:     10, // Large batch, won't trigger automatically
		FlushInterval: time.Hour,
		Enabled:       true,
	})

	ctx := context.Background()
	d.Dispatch(ctx, types.Event{ID: "ev1", Type: "file_read"})

	// Force flush
	d.Flush(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Errorf("received %d events, want 1", len(received))
	}
}

func TestDispatcher_Retry(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:       "test",
		URL:        server.URL,
		BatchSize:  1,
		RetryCount: 3,
		RetryDelay: 10 * time.Millisecond,
		Enabled:    true,
	})

	ctx := context.Background()
	d.Dispatch(ctx, types.Event{Type: "file_read"})

	time.Sleep(200 * time.Millisecond)

	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestDispatcher_Headers(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name: "test",
		URL:  server.URL,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer token123",
		},
		BatchSize: 1,
		Enabled:   true,
	})

	ctx := context.Background()
	d.Dispatch(ctx, types.Event{Type: "file_read"})

	time.Sleep(100 * time.Millisecond)

	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %s, want custom-value", receivedHeaders.Get("X-Custom-Header"))
	}
	if receivedHeaders.Get("Authorization") != "Bearer token123" {
		t.Errorf("Authorization header not set correctly")
	}
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", receivedHeaders.Get("Content-Type"))
	}
}

func TestSlackWebhook(t *testing.T) {
	cfg := SlackWebhook("slack-alerts", "https://hooks.slack.com/test", []string{"*"})

	if cfg.Name != "slack-alerts" {
		t.Errorf("Name = %s, want slack-alerts", cfg.Name)
	}
	if cfg.Template == "" {
		t.Error("Template should not be empty")
	}
	if cfg.BatchSize != 1 {
		t.Errorf("BatchSize = %d, want 1", cfg.BatchSize)
	}
	if !cfg.Enabled {
		t.Error("should be enabled by default")
	}
}

func TestPagerDutyWebhook(t *testing.T) {
	cfg := PagerDutyWebhook("pd-alerts", "https://events.pagerduty.com/v2/enqueue", "routing-key-123", []string{"blocked_*"})

	if cfg.Name != "pd-alerts" {
		t.Errorf("Name = %s, want pd-alerts", cfg.Name)
	}
	if cfg.Template == "" {
		t.Error("Template should not be empty")
	}
	if cfg.RetryCount != 2 {
		t.Errorf("RetryCount = %d, want 2", cfg.RetryCount)
	}
}

func TestGenericWebhook(t *testing.T) {
	cfg := GenericWebhook("generic", "http://example.com/events", []string{"file_*"})

	if cfg.Name != "generic" {
		t.Errorf("Name = %s, want generic", cfg.Name)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", cfg.FlushInterval)
	}
}

func TestDispatchBatch(t *testing.T) {
	var received []types.Event
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev types.Event
		json.Unmarshal(body, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	d.Register(WebhookConfig{
		Name:      "test",
		URL:       server.URL,
		BatchSize: 1,
		Enabled:   true,
	})

	ctx := context.Background()
	events := []types.Event{
		{ID: "ev1", Type: "file_read"},
		{ID: "ev2", Type: "file_write"},
	}

	d.DispatchBatch(ctx, events)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Errorf("received %d events, want 2", len(received))
	}
}
