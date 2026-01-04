package llmproxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsSSEResponse(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "SSE response",
			contentType: "text/event-stream",
			want:        true,
		},
		{
			name:        "SSE with charset",
			contentType: "text/event-stream; charset=utf-8",
			want:        true,
		},
		{
			name:        "JSON response",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "Empty content type",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", tt.contentType)

			got := IsSSEResponse(resp)
			if got != tt.want {
				t.Errorf("IsSSEResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStreamingResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStreamingResponseWriter(rec)

	// Write header
	sw.Header().Set("Content-Type", "text/event-stream")
	sw.WriteHeader(http.StatusOK)

	// Write some chunks
	chunks := []string{
		"data: chunk1\n\n",
		"data: chunk2\n\n",
		"data: chunk3\n\n",
	}

	for _, chunk := range chunks {
		n, err := sw.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if n != len(chunk) {
			t.Errorf("Write() = %d, want %d", n, len(chunk))
		}
	}

	// Check status
	if sw.Status() != http.StatusOK {
		t.Errorf("Status() = %d, want %d", sw.Status(), http.StatusOK)
	}

	// Check buffered data
	expectedData := strings.Join(chunks, "")
	if string(sw.Data()) != expectedData {
		t.Errorf("Data() = %q, want %q", string(sw.Data()), expectedData)
	}

	// Check recorder received all data
	if rec.Body.String() != expectedData {
		t.Errorf("Recorder body = %q, want %q", rec.Body.String(), expectedData)
	}
}

func TestSSEProxyTransport_SSEResponse(t *testing.T) {
	// Create an SSE server
	sseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		// Send some SSE events
		flusher := w.(http.Flusher)
		events := []string{
			"event: message\ndata: {\"text\": \"Hello\"}\n\n",
			"event: message\ndata: {\"text\": \"World\"}\n\n",
		}

		for _, event := range events {
			w.Write([]byte(event))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer sseServer.Close()

	// Track if callback was called
	var callbackResp *http.Response
	var callbackBody []byte

	rec := httptest.NewRecorder()
	transport := newSSEProxyTransport(
		http.DefaultTransport,
		rec,
		func(resp *http.Response, body []byte) {
			callbackResp = resp
			callbackBody = body
		},
	)

	// Make request through transport
	req, _ := http.NewRequest("POST", sseServer.URL+"/v1/messages", nil)
	resp, err := transport.RoundTrip(req)

	// Should return nil response and errSSEHandled
	if resp != nil {
		t.Errorf("Expected nil response for SSE, got %v", resp)
	}
	if err != errSSEHandled {
		t.Errorf("Expected errSSEHandled, got %v", err)
	}

	// Check callback was called
	if callbackResp == nil {
		t.Fatal("Callback was not called")
	}
	if callbackResp.StatusCode != http.StatusOK {
		t.Errorf("Callback response status = %d, want %d", callbackResp.StatusCode, http.StatusOK)
	}

	// Check body was captured
	expectedBody := "event: message\ndata: {\"text\": \"Hello\"}\n\nevent: message\ndata: {\"text\": \"World\"}\n\n"
	if string(callbackBody) != expectedBody {
		t.Errorf("Callback body = %q, want %q", string(callbackBody), expectedBody)
	}

	// Check recorder received the streamed response
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Recorder Content-Type = %q, want text/event-stream", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != expectedBody {
		t.Errorf("Recorder body = %q, want %q", rec.Body.String(), expectedBody)
	}
}

func TestSSEProxyTransport_NonSSEResponse(t *testing.T) {
	// Create a regular JSON server
	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer jsonServer.Close()

	var callbackCalled bool
	rec := httptest.NewRecorder()
	transport := newSSEProxyTransport(
		http.DefaultTransport,
		rec,
		func(resp *http.Response, body []byte) {
			callbackCalled = true
		},
	)

	// Make request through transport
	req, _ := http.NewRequest("POST", jsonServer.URL+"/v1/messages", nil)
	resp, err := transport.RoundTrip(req)

	// Should return normal response for non-SSE
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected response for non-SSE")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Callback should NOT be called for non-SSE
	if callbackCalled {
		t.Error("Callback should not be called for non-SSE responses")
	}

	// Read body
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"result": "ok"}` {
		t.Errorf("Response body = %q, want %q", string(body), `{"result": "ok"}`)
	}
}

func TestSSEProxyTransport_StreamingBehavior(t *testing.T) {
	// Create a slow SSE server to verify streaming behavior
	chunkSent := make(chan struct{})
	sseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)

		// Send first chunk
		w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		close(chunkSent)

		// Wait a bit then send second chunk
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("data: second\n\n"))
		flusher.Flush()
	}))
	defer sseServer.Close()

	// Use a pipe-based writer to verify streaming
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	// Custom response writer using pipe
	pipeWriter := &pipeResponseWriter{
		header: make(http.Header),
		pw:     pw,
	}

	go func() {
		transport := newSSEProxyTransport(
			http.DefaultTransport,
			pipeWriter,
			nil,
		)

		req, _ := http.NewRequest("POST", sseServer.URL+"/v1/messages", nil)
		transport.RoundTrip(req)
	}()

	// Wait for first chunk to be sent
	select {
	case <-chunkSent:
	case <-time.After(time.Second):
		t.Fatal("Timed out waiting for first chunk")
	}

	// Read from pipe - should get first chunk immediately without waiting for stream to complete
	scanner := bufio.NewScanner(pr)
	if !scanner.Scan() {
		t.Fatal("Expected to read first line")
	}
	firstLine := scanner.Text()
	if firstLine != "data: first" {
		t.Errorf("First line = %q, want %q", firstLine, "data: first")
	}
}

// pipeResponseWriter implements http.ResponseWriter for pipe-based testing
type pipeResponseWriter struct {
	header     http.Header
	statusCode int
	pw         *io.PipeWriter
}

func (p *pipeResponseWriter) Header() http.Header {
	return p.header
}

func (p *pipeResponseWriter) WriteHeader(statusCode int) {
	p.statusCode = statusCode
}

func (p *pipeResponseWriter) Write(data []byte) (int, error) {
	return p.pw.Write(data)
}

func (p *pipeResponseWriter) Flush() {
	// Pipe is unbuffered, so no explicit flush needed
}

func TestSSEProxyTransport_LargeStream(t *testing.T) {
	// Test handling of large SSE streams
	var totalEvents int
	sseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)

		// Send many events
		for i := 0; i < 100; i++ {
			w.Write([]byte("data: event\n\n"))
			flusher.Flush()
			totalEvents++
		}
	}))
	defer sseServer.Close()

	var callbackBody []byte
	rec := httptest.NewRecorder()
	transport := newSSEProxyTransport(
		http.DefaultTransport,
		rec,
		func(resp *http.Response, body []byte) {
			callbackBody = body
		},
	)

	req, _ := http.NewRequest("POST", sseServer.URL+"/v1/messages", nil)
	_, err := transport.RoundTrip(req)

	if err != errSSEHandled {
		t.Errorf("Expected errSSEHandled, got %v", err)
	}

	// Verify all events were captured
	eventCount := bytes.Count(callbackBody, []byte("data: event\n\n"))
	if eventCount != 100 {
		t.Errorf("Captured %d events, want 100", eventCount)
	}

	// Verify recorder got same events
	recEventCount := bytes.Count(rec.Body.Bytes(), []byte("data: event\n\n"))
	if recEventCount != 100 {
		t.Errorf("Recorder got %d events, want 100", recEventCount)
	}
}
