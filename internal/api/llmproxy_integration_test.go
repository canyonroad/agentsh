//go:build integration

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestIntegration_LLMProxyStartedOnSessionCreate verifies that the embedded LLM proxy
// is automatically started when a session is created with proxy.mode = "embedded".
func TestIntegration_LLMProxyStartedOnSessionCreate(t *testing.T) {
	// Create a mock upstream LLM server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "msg_test",
			"type": "message",
			"content": [{"type": "text", "text": "Hello!"}],
			"usage": {"input_tokens": 10, "output_tokens": 5}
		}`))
	}))
	defer upstream.Close()

	// Set up store and session manager
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	ws := t.TempDir()

	// Configure with embedded LLM proxy pointing to mock upstream
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()

	// Enable embedded LLM proxy
	cfg.Proxy.Mode = "embedded"
	cfg.Proxy.Port = 0 // Auto-select port
	cfg.Proxy.Providers.Anthropic = upstream.URL
	cfg.Proxy.Providers.OpenAI = upstream.URL

	// Disable DLP for simpler testing
	cfg.DLP.Mode = "disabled"

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}

	broker := events.NewBroker()
	app := NewApp(cfg, sessions, store, engine, broker, nil, nil, nil, metrics.New(), nil)

	// Create a session - this should start the LLM proxy
	ctx := context.Background()
	req := types.CreateSessionRequest{
		Workspace: ws,
	}
	snap, code, err := app.createSessionCore(ctx, req)
	if err != nil {
		t.Fatalf("createSessionCore failed: %v", err)
	}
	if code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", code)
	}

	// Get the session to check proxy URL
	sess, ok := sessions.Get(snap.ID)
	if !ok {
		t.Fatal("session not found after creation")
	}
	defer func() {
		// Clean up session (stops proxy)
		sessions.Destroy(snap.ID)
	}()

	// Verify the proxy URL is set on the session
	proxyURL := sess.LLMProxyURL()
	if proxyURL == "" {
		t.Error("expected LLM proxy URL to be set on session")
	}
	if !strings.HasPrefix(proxyURL, "http://127.0.0.1:") {
		t.Errorf("expected proxy URL to start with http://127.0.0.1:, got %s", proxyURL)
	}

	// Verify llm_proxy_started event was stored
	evs, err := store.QueryEvents(ctx, types.EventQuery{
		SessionID: snap.ID,
		Types:     []string{"llm_proxy_started"},
	})
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	if len(evs) == 0 {
		t.Error("expected llm_proxy_started event to be stored")
	} else {
		ev := evs[0]
		if ev.SessionID != snap.ID {
			t.Errorf("expected session ID %s, got %s", snap.ID, ev.SessionID)
		}
		if ev.Fields["proxy_url"] != proxyURL {
			t.Errorf("expected proxy_url %s in event, got %v", proxyURL, ev.Fields["proxy_url"])
		}
	}

	// Verify the proxy actually works by making a request
	client := &http.Client{Timeout: 5 * time.Second}
	proxyReq, err := http.NewRequest("POST", proxyURL+"/v1/messages",
		strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"Hi"}]}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	proxyReq.Header.Set("x-api-key", "test-key")
	proxyReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(proxyReq)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 from proxy, got %d: %s", resp.StatusCode, string(body))
	}

	// Verify response body
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hello!") {
		t.Errorf("expected response to contain 'Hello!', got: %s", string(body))
	}
}

// TestIntegration_LLMProxyEnvVarsInSession verifies that LLM proxy environment
// variables are correctly set on the session for use by child processes.
func TestIntegration_LLMProxyEnvVarsInSession(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	ws := t.TempDir()

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()
	cfg.Proxy.Mode = "embedded"
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL
	cfg.Proxy.Providers.OpenAI = upstream.URL
	cfg.DLP.Mode = "disabled"

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}

	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)

	ctx := context.Background()
	req := types.CreateSessionRequest{Workspace: ws}
	snap, _, err := app.createSessionCore(ctx, req)
	if err != nil {
		t.Fatalf("createSessionCore failed: %v", err)
	}

	sess, ok := sessions.Get(snap.ID)
	if !ok {
		t.Fatal("session not found")
	}
	defer sessions.Destroy(snap.ID)

	// Get LLM proxy environment variables
	envVars := sess.LLMProxyEnvVars()
	if envVars == nil {
		t.Fatal("expected LLMProxyEnvVars to return non-nil map")
	}

	// Verify required env vars
	proxyURL := sess.LLMProxyURL()

	if envVars["ANTHROPIC_BASE_URL"] != proxyURL {
		t.Errorf("ANTHROPIC_BASE_URL: expected %s, got %s", proxyURL, envVars["ANTHROPIC_BASE_URL"])
	}
	if envVars["OPENAI_BASE_URL"] != proxyURL {
		t.Errorf("OPENAI_BASE_URL: expected %s, got %s", proxyURL, envVars["OPENAI_BASE_URL"])
	}
	if envVars["AGENTSH_SESSION_ID"] != snap.ID {
		t.Errorf("AGENTSH_SESSION_ID: expected %s, got %s", snap.ID, envVars["AGENTSH_SESSION_ID"])
	}
}

// TestIntegration_LLMProxyNotStartedWhenDisabled verifies that the LLM proxy
// is not started when proxy.mode is "disabled".
func TestIntegration_LLMProxyNotStartedWhenDisabled(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	ws := t.TempDir()

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()

	// Disable LLM proxy
	cfg.Proxy.Mode = "disabled"

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}

	broker := events.NewBroker()
	app := NewApp(cfg, sessions, store, engine, broker, nil, nil, nil, metrics.New(), nil)

	ctx := context.Background()
	req := types.CreateSessionRequest{Workspace: ws}
	snap, _, err := app.createSessionCore(ctx, req)
	if err != nil {
		t.Fatalf("createSessionCore failed: %v", err)
	}

	sess, ok := sessions.Get(snap.ID)
	if !ok {
		t.Fatal("session not found")
	}
	defer sessions.Destroy(snap.ID)

	// Verify proxy URLs are NOT set
	if sess.ProxyURL() != "" {
		t.Errorf("expected empty network proxy URL when disabled, got %s", sess.ProxyURL())
	}
	if sess.LLMProxyURL() != "" {
		t.Errorf("expected empty LLM proxy URL when disabled, got %s", sess.LLMProxyURL())
	}

	// Verify no llm_proxy_started event was stored
	evs, err := store.QueryEvents(ctx, types.EventQuery{
		SessionID: snap.ID,
		Types:     []string{"llm_proxy_started"},
	})
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	if len(evs) != 0 {
		t.Error("llm_proxy_started event should not be stored when proxy is disabled")
	}
}

// TestIntegration_LLMProxyBothDialects verifies that the proxy correctly handles
// both Anthropic and OpenAI request formats.
func TestIntegration_LLMProxyBothDialects(t *testing.T) {
	var anthropicCalled, openaiCalled bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Detect dialect by path
		if strings.Contains(r.URL.Path, "messages") {
			anthropicCalled = true
			w.Write([]byte(`{"content":[{"text":"Anthropic"}],"usage":{"input_tokens":5,"output_tokens":3}}`))
		} else if strings.Contains(r.URL.Path, "chat/completions") {
			openaiCalled = true
			w.Write([]byte(`{"choices":[{"message":{"content":"OpenAI"}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`))
		}
	}))
	defer upstream.Close()

	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sessions.BaseDir = t.TempDir()
	cfg.Proxy.Mode = "embedded"
	cfg.Proxy.Port = 0
	cfg.Proxy.Providers.Anthropic = upstream.URL
	cfg.Proxy.Providers.OpenAI = upstream.URL
	cfg.DLP.Mode = "disabled"

	engine, err := policy.NewEngine(&policy.Policy{Version: 1, Name: "test"}, false)
	if err != nil {
		t.Fatal(err)
	}

	app := NewApp(cfg, sessions, store, engine, events.NewBroker(), nil, nil, nil, metrics.New(), nil)

	ctx := context.Background()
	snap, _, err := app.createSessionCore(ctx, types.CreateSessionRequest{Workspace: t.TempDir()})
	if err != nil {
		t.Fatalf("createSessionCore failed: %v", err)
	}

	sess, _ := sessions.Get(snap.ID)
	defer sessions.Destroy(snap.ID)

	proxyURL := sess.LLMProxyURL()
	client := &http.Client{Timeout: 5 * time.Second}

	// Test Anthropic dialect
	anthReq, _ := http.NewRequest("POST", proxyURL+"/v1/messages",
		strings.NewReader(`{"model":"claude","messages":[{"role":"user","content":"Hi"}]}`))
	anthReq.Header.Set("x-api-key", "test-key")
	anthReq.Header.Set("Content-Type", "application/json")

	anthResp, err := client.Do(anthReq)
	if err != nil {
		t.Fatalf("Anthropic request failed: %v", err)
	}
	anthResp.Body.Close()

	if !anthropicCalled {
		t.Error("expected Anthropic upstream to be called")
	}

	// Test OpenAI dialect
	openaiReq, _ := http.NewRequest("POST", proxyURL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`))
	openaiReq.Header.Set("Authorization", "Bearer sk-test")
	openaiReq.Header.Set("Content-Type", "application/json")

	openaiResp, err := client.Do(openaiReq)
	if err != nil {
		t.Fatalf("OpenAI request failed: %v", err)
	}
	openaiResp.Body.Close()

	if !openaiCalled {
		t.Error("expected OpenAI upstream to be called")
	}
}
