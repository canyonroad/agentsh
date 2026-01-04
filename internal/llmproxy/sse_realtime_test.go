package llmproxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

// TestProxy_SSEStreamingRealTime tests that SSE events are streamed in real-time
// (not buffered until the entire response completes).
func TestProxy_SSEStreamingRealTime(t *testing.T) {
	eventDelay := 100 * time.Millisecond
	eventCount := 5

	// Track when each event is sent by the mock server
	eventsSent := make(chan time.Time, eventCount)

	// Create a mock SSE server with delays between events
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)

		for i := 0; i < eventCount; i++ {
			event := fmt.Sprintf("event: delta\ndata: {\"index\": %d}\n\n", i)
			w.Write([]byte(event))
			flusher.Flush()
			eventsSent <- time.Now()
			time.Sleep(eventDelay)
		}
		close(eventsSent)
	}))
	defer upstream.Close()

	storageDir := t.TempDir()

	cfg := Config{
		SessionID: "sse-realtime-test",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
		},
		DLP: config.DLPConfig{Mode: "disabled"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	// Make streaming request through proxy
	proxyURL := "http://" + proxy.Addr().String() + "/v1/messages"
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(`{"stream": true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test-key")

	client := &http.Client{Timeout: 30 * time.Second}
	startTime := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Track when each chunk is received by the client
	chunksReceived := make([]time.Time, 0, eventCount)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunksReceived = append(chunksReceived, time.Now())
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	}

	totalDuration := time.Since(startTime)
	expectedDuration := time.Duration(eventCount) * eventDelay

	// Log timing info
	t.Logf("Total duration: %v (expected ~%v)", totalDuration, expectedDuration)
	t.Logf("Chunks received: %d", len(chunksReceived))

	if len(chunksReceived) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunksReceived))
	}

	// The key test: If streaming works, chunks should arrive spread over time.
	// If buffered, all chunks would arrive at once at the end.
	firstChunkTime := chunksReceived[0].Sub(startTime)
	lastChunkTime := chunksReceived[len(chunksReceived)-1].Sub(startTime)
	spreadDuration := lastChunkTime - firstChunkTime

	t.Logf("First chunk at: %v", firstChunkTime)
	t.Logf("Last chunk at: %v", lastChunkTime)
	t.Logf("Spread: %v", spreadDuration)

	// First chunk should arrive quickly (within 200ms of start)
	if firstChunkTime > 200*time.Millisecond {
		t.Errorf("First chunk took too long: %v (suggests buffering)", firstChunkTime)
	}

	// Chunks should be spread over time (at least 300ms spread for 5 events × 100ms)
	minExpectedSpread := time.Duration(eventCount-2) * eventDelay // Allow some slack
	if spreadDuration < minExpectedSpread {
		t.Errorf("Chunks arrived too quickly (%v spread), suggests buffering instead of streaming. Expected at least %v spread.",
			spreadDuration, minExpectedSpread)
	}

	// Total time should be close to expected (within 500ms)
	if totalDuration < expectedDuration-200*time.Millisecond {
		t.Errorf("Total duration too short: %v < %v", totalDuration, expectedDuration)
	}
}
