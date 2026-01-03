# Custom Provider URLs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rename `proxy.upstreams` to `proxy.providers`, merge OpenAI/ChatGPT dialects, and allow custom base URLs for alternative endpoints.

**Architecture:** Simplify from 3 dialects to 2 (Anthropic, OpenAI). ChatGPT login becomes a special case within OpenAI dialect, only active when using default OpenAI URL. Custom URLs route all traffic to the configured endpoint.

**Tech Stack:** Go, YAML config

---

### Task 1: Update Config Struct

**Files:**
- Modify: `internal/config/proxy.go:10-14`

**Step 1: Rename ProxyUpstreamsConfig to ProxyProvidersConfig**

Replace lines 10-14:

```go
type ProxyProvidersConfig struct {
	Anthropic string `yaml:"anthropic"`
	OpenAI    string `yaml:"openai"`
}
```

**Step 2: Update ProxyConfig struct field**

Replace line 7:

```go
	Providers ProxyProvidersConfig `yaml:"providers"`
```

**Step 3: Add IsCustomOpenAI helper method**

Add after line 14:

```go
// IsCustomOpenAI returns true if a non-default OpenAI URL is configured.
func (c ProxyProvidersConfig) IsCustomOpenAI() bool {
	return c.OpenAI != "" && c.OpenAI != "https://api.openai.com"
}
```

**Step 4: Update DefaultProxyConfig**

Replace lines 47-57:

```go
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: ProxyProvidersConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
		},
	}
}
```

**Step 5: Run tests to verify compile**

Run: `go build ./internal/config/...`
Expected: Compile errors (other packages still reference Upstreams)

**Step 6: Commit**

```bash
git add internal/config/proxy.go
git commit -m "refactor(config): rename Upstreams to Providers, remove ChatGPT field"
```

---

### Task 2: Update Config Defaults

**Files:**
- Modify: `internal/config/config.go:573-585`

**Step 1: Update proxy defaults in applyDefaultsWithSource**

Replace lines 573-585:

```go
	// Apply proxy defaults field by field
	if cfg.Proxy.Mode == "" {
		cfg.Proxy.Mode = "embedded"
	}
	if cfg.Proxy.Providers.Anthropic == "" {
		cfg.Proxy.Providers.Anthropic = "https://api.anthropic.com"
	}
	if cfg.Proxy.Providers.OpenAI == "" {
		cfg.Proxy.Providers.OpenAI = "https://api.openai.com"
	}
	// Port 0 is valid (means random), so don't override it
```

**Step 2: Run tests to verify compile**

Run: `go build ./internal/config/...`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "refactor(config): update defaults to use Providers"
```

---

### Task 3: Simplify Dialect Detection

**Files:**
- Modify: `internal/llmproxy/dialect.go`

**Step 1: Remove DialectChatGPT constant**

Replace lines 15-20:

```go
const (
	DialectUnknown   Dialect = "unknown"
	DialectAnthropic Dialect = "anthropic"
	DialectOpenAI    Dialect = "openai"
)
```

**Step 2: Add ChatGPT upstream constant**

Add after the Dialect constants (around line 20):

```go
// chatGPTUpstream is the hardcoded ChatGPT backend URL, used only when
// OpenAI provider is set to the default URL and an OAuth token is detected.
const chatGPTUpstream = "https://chatgpt.com/backend-api"
```

**Step 3: Update DefaultDialectConfigs - remove ChatGPT**

Replace lines 35-58:

```go
// DefaultDialectConfigs returns the default configuration for each dialect.
func DefaultDialectConfigs() map[Dialect]*DialectConfig {
	anthropicURL, _ := url.Parse("https://api.anthropic.com")
	openaiURL, _ := url.Parse("https://api.openai.com")

	return map[Dialect]*DialectConfig{
		DialectAnthropic: {
			Upstream:     anthropicURL,
			AuthHeader:   "x-api-key",
			PathPrefixes: []string{"/v1/messages", "/v1/complete"},
		},
		DialectOpenAI: {
			Upstream:     openaiURL,
			AuthHeader:   "Authorization",
			PathPrefixes: []string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/backend-api/"},
		},
	}
}
```

**Step 4: Simplify Detect method**

Replace lines 73-110:

```go
// Detect determines the dialect from the request.
// Detection order:
// 1. x-api-key header -> Anthropic
// 2. anthropic-version header -> Anthropic
// 3. Authorization header present -> OpenAI
// 4. No auth -> Unknown
func (d *DialectDetector) Detect(r *http.Request) Dialect {
	// 1. Anthropic x-api-key header
	if r.Header.Get("x-api-key") != "" {
		return DialectAnthropic
	}

	// 2. Anthropic version header
	if r.Header.Get("anthropic-version") != "" {
		return DialectAnthropic
	}

	// 3. Any Authorization header -> OpenAI dialect
	if r.Header.Get("Authorization") != "" {
		return DialectOpenAI
	}

	return DialectUnknown
}
```

**Step 5: Add IsChatGPTToken helper**

Add after the Detect method:

```go
// IsChatGPTToken returns true if the Authorization header contains an OAuth token
// (non-sk-* Bearer token), indicating ChatGPT login flow.
func IsChatGPTToken(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	// OpenAI API keys start with sk-, ChatGPT OAuth tokens don't
	return !strings.HasPrefix(token, "sk-")
}
```

**Step 6: Run tests to see what breaks**

Run: `go test ./internal/llmproxy/... 2>&1 | head -50`
Expected: FAIL (tests reference DialectChatGPT)

**Step 7: Commit**

```bash
git add internal/llmproxy/dialect.go
git commit -m "refactor(llmproxy): simplify to 2 dialects, add ChatGPT token detection"
```

---

### Task 4: Update Dialect Tests

**Files:**
- Modify: `internal/llmproxy/dialect_test.go`

**Step 1: Update ChatGPT OAuth test**

Replace lines 49-60:

```go
func TestDialectDetector_OpenAI_OAuth(t *testing.T) {
	d := NewDialectDetector(nil)

	// Bearer without sk- prefix -> still OpenAI dialect
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

	got := d.Detect(req)
	if got != DialectOpenAI {
		t.Errorf("expected OpenAI, got %s", got)
	}
}
```

**Step 2: Add IsChatGPTToken test**

Add at end of file:

```go
func TestIsChatGPTToken(t *testing.T) {
	tests := []struct {
		name     string
		auth     string
		expected bool
	}{
		{"sk- token", "Bearer sk-proj-abc123", false},
		{"OAuth token", "Bearer eyJhbGciOiJIUzI1NiJ9...", true},
		{"empty", "", false},
		{"no bearer", "Basic abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			got := IsChatGPTToken(req)
			if got != tt.expected {
				t.Errorf("IsChatGPTToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}
```

**Step 3: Run dialect tests**

Run: `go test ./internal/llmproxy/... -run TestDialect -v`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/llmproxy/dialect_test.go
git commit -m "test(llmproxy): update dialect tests for simplified detection"
```

---

### Task 5: Update Proxy Initialization

**Files:**
- Modify: `internal/llmproxy/proxy.go`

**Step 1: Add fields to Proxy struct**

Replace lines 36-48:

```go
// Proxy is an HTTP proxy that intercepts LLM API requests.
type Proxy struct {
	cfg             Config
	detector        *DialectDetector
	rewriter        *RequestRewriter
	dlp             *DLPProcessor
	storage         *Storage
	logger          *slog.Logger
	isCustomOpenAI  bool
	chatGPTUpstream *url.URL

	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
}
```

**Step 2: Update New function**

Replace lines 50-90:

```go
// New creates a new LLM proxy.
func New(cfg Config, storagePath string, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Build dialect configs with any overrides from ProxyConfig.Providers
	configs := DefaultDialectConfigs()
	if cfg.Proxy.Providers.Anthropic != "" {
		if u, err := parseURL(cfg.Proxy.Providers.Anthropic); err == nil {
			configs[DialectAnthropic].Upstream = u
		}
	}
	if cfg.Proxy.Providers.OpenAI != "" {
		if u, err := parseURL(cfg.Proxy.Providers.OpenAI); err == nil {
			configs[DialectOpenAI].Upstream = u
		}
	}

	// Parse ChatGPT upstream for fallback
	chatGPTURL, _ := parseURL(chatGPTUpstream)

	detector := NewDialectDetector(configs)
	rewriter := NewRequestRewriter(detector)
	dlp := NewDLPProcessor(cfg.DLP)
	storage, err := NewStorage(storagePath, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("create storage: %w", err)
	}

	return &Proxy{
		cfg:             cfg,
		detector:        detector,
		rewriter:        rewriter,
		dlp:             dlp,
		storage:         storage,
		logger:          logger,
		isCustomOpenAI:  cfg.Proxy.Providers.IsCustomOpenAI(),
		chatGPTUpstream: chatGPTURL,
	}, nil
}
```

**Step 3: Run build to check compile**

Run: `go build ./internal/llmproxy/...`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add internal/llmproxy/proxy.go
git commit -m "refactor(llmproxy): update proxy init to use Providers config"
```

---

### Task 6: Update Request Routing for ChatGPT

**Files:**
- Modify: `internal/llmproxy/proxy.go`

**Step 1: Add getUpstreamForRequest method**

Add after the New function (around line 90):

```go
// getUpstreamForRequest returns the appropriate upstream URL for the request.
// For OpenAI dialect with default URL, it checks if this is a ChatGPT OAuth
// token and routes to ChatGPT backend if so.
func (p *Proxy) getUpstreamForRequest(r *http.Request, dialect Dialect) *url.URL {
	if dialect == DialectOpenAI && !p.isCustomOpenAI && IsChatGPTToken(r) {
		return p.chatGPTUpstream
	}
	return p.detector.GetUpstream(dialect)
}
```

**Step 2: Update ServeHTTP to use getUpstreamForRequest**

Replace line 208 (where upstream is fetched):

```go
	upstream := p.getUpstreamForRequest(r, dialect)
```

**Step 3: Update rewrite for ChatGPT paths**

In the Rewrite method of dialect.go, the ChatGPT path handling needs to check if we're routing to ChatGPT. Update `internal/llmproxy/dialect.go` lines 130-163.

Replace the Rewrite method:

```go
// Rewrite modifies the request for forwarding to the upstream provider.
// It updates the URL scheme/host and adjusts headers as needed.
func (rw *RequestRewriter) Rewrite(r *http.Request, dialect Dialect, upstream *url.URL) (*http.Request, error) {
	if upstream == nil {
		upstream = rw.detector.GetUpstream(dialect)
	}
	if upstream == nil {
		return r, nil // passthrough unchanged
	}

	// Clone the request
	outReq := r.Clone(r.Context())

	// Update URL to point to upstream
	outReq.URL.Scheme = upstream.Scheme
	outReq.URL.Host = upstream.Host

	// For ChatGPT backend-api, the path structure is different
	if upstream.Host == "chatgpt.com" {
		// Requests come in as /backend-api/..., upstream expects the same
		// but we need to ensure the base path is correct
		if !strings.HasPrefix(outReq.URL.Path, "/backend-api") {
			outReq.URL.Path = "/backend-api" + outReq.URL.Path
		}
	}

	// Set Host header to upstream
	outReq.Host = upstream.Host

	// Remove proxy-specific headers
	outReq.Header.Del("X-LLM-Dialect")
	outReq.Header.Del("X-Forwarded-Host")
	outReq.Header.Del("X-Session-ID") // We capture this but don't forward

	return outReq, nil
}
```

**Step 4: Update Rewrite call in proxy.go**

Replace line 200-201:

```go
	// Rewrite request for upstream
	outReq, err := p.rewriter.Rewrite(r, dialect, upstream)
```

**Step 5: Run tests**

Run: `go test ./internal/llmproxy/... -v 2>&1 | tail -30`
Expected: Some tests may need updates

**Step 6: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/dialect.go
git commit -m "feat(llmproxy): route ChatGPT OAuth tokens to backend when using default URL"
```

---

### Task 7: Update Proxy Tests

**Files:**
- Modify: `internal/llmproxy/proxy_test.go`

**Step 1: Update all Upstreams references to Providers**

Find and replace all occurrences:
- `config.ProxyUpstreamsConfig` → `config.ProxyProvidersConfig`
- `Upstreams:` → `Providers:`

Lines to update: 87-89, 230-232, 406-409, 531-533

**Step 2: Run all proxy tests**

Run: `go test ./internal/llmproxy/... -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/proxy_test.go
git commit -m "test(llmproxy): update tests to use Providers config"
```

---

### Task 8: Add Integration Test for Custom Provider

**Files:**
- Modify: `internal/llmproxy/proxy_test.go`

**Step 1: Add test for custom OpenAI provider**

Add at end of file:

```go
// TestProxy_CustomOpenAIProvider tests that a custom OpenAI URL routes all traffic there.
func TestProxy_CustomOpenAIProvider(t *testing.T) {
	var receivedPath string
	var receivedAuth string

	// Create a mock custom provider server
	customProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")

		resp := map[string]interface{}{
			"id":      "chatcmpl-test",
			"object":  "chat.completion",
			"choices": []map[string]interface{}{},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer customProvider.Close()

	storageDir := t.TempDir()

	// Custom OpenAI provider URL
	cfg := Config{
		SessionID: "test-custom-provider",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				OpenAI: customProvider.URL, // Custom URL
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

	// Test with OAuth token (would normally go to ChatGPT, but custom URL overrides)
	proxyURL := "http://" + proxy.Addr().String() + "/v1/chat/completions"
	req, _ := http.NewRequest(http.MethodPost, proxyURL, strings.NewReader(`{"test": true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.oauth-token") // OAuth token

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Verify request went to custom provider (not ChatGPT)
	if receivedPath != "/v1/chat/completions" {
		t.Errorf("unexpected path at custom provider: %s", receivedPath)
	}
	if receivedAuth != "Bearer eyJhbGciOiJIUzI1NiJ9.oauth-token" {
		t.Errorf("auth header not passed: %s", receivedAuth)
	}
}
```

**Step 2: Run the new test**

Run: `go test ./internal/llmproxy/... -run TestProxy_CustomOpenAIProvider -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/proxy_test.go
git commit -m "test(llmproxy): add integration test for custom OpenAI provider"
```

---

### Task 9: Run Full Test Suite

**Step 1: Run all tests**

Run: `go test ./... -count=1`
Expected: PASS

**Step 2: Run build**

Run: `go build ./...`
Expected: SUCCESS

**Step 3: Commit any remaining fixes**

If any tests fail, fix them and commit.

---

### Task 10: Update Documentation

**Files:**
- Modify: `docs/plans/2026-01-02-custom-provider-urls-design.md` (already exists, verify accurate)

**Step 1: Verify design doc matches implementation**

Read the design doc and verify it matches what was implemented.

**Step 2: Final commit**

```bash
git add -A
git commit -m "docs: finalize custom provider URLs implementation"
```
