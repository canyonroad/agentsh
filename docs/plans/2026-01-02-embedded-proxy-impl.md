# Embedded LLM Proxy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an embedded HTTP proxy to agentsh that intercepts LLM API requests, applies DLP redaction, and logs request/response pairs with token usage.

**Architecture:** The proxy runs inside the agentsh session lifecycle, starting before the agent process and binding to a random port. It detects LLM provider dialect (Anthropic/OpenAI/ChatGPT) from request headers, applies DLP patterns to request bodies, forwards to upstream, and logs everything to session storage.

**Tech Stack:** Go standard library (`net/http`, `net/http/httputil`), existing session/config patterns from agentsh.

---

## Task 1: Add Proxy and DLP Configuration

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/proxy.go`
- Test: `internal/config/proxy_test.go`

**Step 1: Write the failing test**

```go
// internal/config/proxy_test.go
package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProxyConfigDefaults(t *testing.T) {
	cfg := DefaultProxyConfig()
	if cfg.Mode != "embedded" {
		t.Errorf("expected mode 'embedded', got %q", cfg.Mode)
	}
	if cfg.Port != 0 {
		t.Errorf("expected port 0 (random), got %d", cfg.Port)
	}
}

func TestDLPConfigParse(t *testing.T) {
	yaml := `
dlp:
  mode: redact
  patterns:
    email: true
    phone: false
  custom_patterns:
    - name: customer_id
      display: identifier
      regex: "CUST-[0-9]{8}"
`
	var cfg struct {
		DLP DLPConfig `yaml:"dlp"`
	}
	if err := yaml.Unmarshal([]byte(yaml), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DLP.Mode != "redact" {
		t.Errorf("expected mode 'redact', got %q", cfg.DLP.Mode)
	}
	if len(cfg.DLP.CustomPatterns) != 1 {
		t.Fatalf("expected 1 custom pattern, got %d", len(cfg.DLP.CustomPatterns))
	}
	if cfg.DLP.CustomPatterns[0].Display != "identifier" {
		t.Errorf("expected display 'identifier', got %q", cfg.DLP.CustomPatterns[0].Display)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -run TestProxyConfig -v`
Expected: FAIL with "undefined: DefaultProxyConfig"

**Step 3: Write the configuration structs**

```go
// internal/config/proxy.go
package config

// ProxyConfig configures the embedded LLM proxy.
type ProxyConfig struct {
	// Mode: embedded (default) | disabled
	Mode string `yaml:"mode"`

	// Port for embedded proxy (0 = random available)
	Port int `yaml:"port"`

	// Upstreams overrides default upstream URLs
	Upstreams ProxyUpstreamsConfig `yaml:"upstreams"`
}

// ProxyUpstreamsConfig holds upstream URL overrides.
type ProxyUpstreamsConfig struct {
	Anthropic string `yaml:"anthropic"`
	OpenAI    string `yaml:"openai"`
	ChatGPT   string `yaml:"chatgpt"`
}

// DLPConfig configures Data Loss Prevention.
type DLPConfig struct {
	// Mode: redact | disabled
	Mode string `yaml:"mode"`

	// Patterns enables/disables built-in patterns
	Patterns DLPPatternsConfig `yaml:"patterns"`

	// CustomPatterns are user-defined patterns
	CustomPatterns []CustomPatternConfig `yaml:"custom_patterns"`
}

// DLPPatternsConfig controls built-in pattern activation.
type DLPPatternsConfig struct {
	Email      bool `yaml:"email"`
	Phone      bool `yaml:"phone"`
	CreditCard bool `yaml:"credit_card"`
	SSN        bool `yaml:"ssn"`
	APIKeys    bool `yaml:"api_keys"`
}

// CustomPatternConfig defines a custom DLP pattern.
type CustomPatternConfig struct {
	Name    string `yaml:"name"`    // Internal name for logs
	Display string `yaml:"display"` // Display name for LLM (defaults to Name)
	Regex   string `yaml:"regex"`
}

// StorageConfig configures LLM request storage.
type StorageConfig struct {
	StoreBodies bool                   `yaml:"store_bodies"`
	Retention   StorageRetentionConfig `yaml:"retention"`
}

// StorageRetentionConfig controls storage limits.
type StorageRetentionConfig struct {
	MaxAgeDays int    `yaml:"max_age_days"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	Eviction   string `yaml:"eviction"` // oldest_first | largest_first
}

// DefaultProxyConfig returns default proxy configuration.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Upstreams: ProxyUpstreamsConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
			ChatGPT:   "https://chatgpt.com/backend-api",
		},
	}
}

// DefaultDLPConfig returns default DLP configuration.
func DefaultDLPConfig() DLPConfig {
	return DLPConfig{
		Mode: "redact",
		Patterns: DLPPatternsConfig{
			Email:      true,
			Phone:      true,
			CreditCard: true,
			SSN:        true,
			APIKeys:    true,
		},
	}
}

// DefaultStorageConfig returns default storage configuration.
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		StoreBodies: false,
		Retention: StorageRetentionConfig{
			MaxAgeDays: 30,
			MaxSizeMB:  500,
			Eviction:   "oldest_first",
		},
	}
}
```

**Step 4: Add to main Config struct**

Modify `internal/config/config.go` - add fields to Config struct:

```go
type Config struct {
	// ... existing fields ...
	Proxy   ProxyConfig   `yaml:"proxy"`
	DLP     DLPConfig     `yaml:"dlp"`
	Storage StorageConfig `yaml:"storage"`
}
```

**Step 5: Run test to verify it passes**

Run: `go test ./internal/config/... -run TestProxyConfig -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/proxy.go internal/config/proxy_test.go internal/config/config.go
git commit -m "feat(config): add proxy, DLP, and storage configuration"
```

---

## Task 2: Implement Dialect Detection

**Files:**
- Modify: `internal/llmproxy/dialect.go`
- Create: `internal/llmproxy/dialect_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/dialect_test.go
package llmproxy

import (
	"net/http"
	"testing"
)

func TestDialectDetector_Anthropic(t *testing.T) {
	d := NewDialectDetector(nil)

	// x-api-key header -> Anthropic
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-ant-xxx")

	got := d.Detect(req)
	if got != DialectAnthropic {
		t.Errorf("expected Anthropic, got %s", got)
	}
}

func TestDialectDetector_AnthropicVersion(t *testing.T) {
	d := NewDialectDetector(nil)

	// anthropic-version header -> Anthropic
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("anthropic-version", "2024-01-01")
	req.Header.Set("Authorization", "Bearer xxx")

	got := d.Detect(req)
	if got != DialectAnthropic {
		t.Errorf("expected Anthropic, got %s", got)
	}
}

func TestDialectDetector_OpenAI_APIKey(t *testing.T) {
	d := NewDialectDetector(nil)

	// Bearer sk-xxx -> OpenAI API
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-proj-abc123")

	got := d.Detect(req)
	if got != DialectOpenAI {
		t.Errorf("expected OpenAI, got %s", got)
	}
}

func TestDialectDetector_ChatGPT_OAuth(t *testing.T) {
	d := NewDialectDetector(nil)

	// Bearer without sk- prefix -> ChatGPT
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

	got := d.Detect(req)
	if got != DialectChatGPT {
		t.Errorf("expected ChatGPT, got %s", got)
	}
}

func TestDialectDetector_NoAuth(t *testing.T) {
	d := NewDialectDetector(nil)

	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	// No auth headers

	got := d.Detect(req)
	if got != DialectUnknown {
		t.Errorf("expected Unknown, got %s", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/... -run TestDialectDetector -v`
Expected: Some tests FAIL (current detection logic differs from spec)

**Step 3: Update dialect detection per spec**

Update `internal/llmproxy/dialect.go` - replace `Detect` method:

```go
// Detect determines the dialect from the request.
// Detection order:
// 1. x-api-key header -> Anthropic
// 2. anthropic-version header -> Anthropic
// 3. Authorization: Bearer sk-* -> OpenAI API
// 4. Authorization: Bearer <other> -> ChatGPT login
// 5. No auth -> Unknown
func (d *DialectDetector) Detect(r *http.Request) Dialect {
	// 1. Anthropic x-api-key header
	if r.Header.Get("x-api-key") != "" {
		return DialectAnthropic
	}

	// 2. Anthropic version header
	if r.Header.Get("anthropic-version") != "" {
		return DialectAnthropic
	}

	// 3. Check Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return DialectUnknown
	}

	// Parse Bearer token
	if !strings.HasPrefix(auth, "Bearer ") {
		return DialectUnknown
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	// 4. Token starts with sk- -> OpenAI API
	if strings.HasPrefix(token, "sk-") {
		return DialectOpenAI
	}

	// 5. Other Bearer token -> ChatGPT login (OAuth)
	return DialectChatGPT
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/... -run TestDialectDetector -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/dialect.go internal/llmproxy/dialect_test.go
git commit -m "feat(llmproxy): implement dialect detection per spec"
```

---

## Task 3: Implement DLP Processor

**Files:**
- Modify: `internal/llmproxy/dlp.go`
- Create: `internal/llmproxy/dlp_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/dlp_test.go
package llmproxy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDLPProcessor_RedactEmail(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}
	p := NewDLPProcessor(cfg)

	input := []byte(`{"content": "Contact john@example.com for help"}`)
	result := p.Process(input)

	expected := `{"content": "Contact [REDACTED:email] for help"}`
	if string(result.ProcessedData) != expected {
		t.Errorf("got %s, want %s", result.ProcessedData, expected)
	}
	if len(result.Redactions) != 1 {
		t.Errorf("expected 1 redaction, got %d", len(result.Redactions))
	}
	if result.Redactions[0].Type != "email" {
		t.Errorf("expected type 'email', got %q", result.Redactions[0].Type)
	}
}

func TestDLPProcessor_CustomPattern(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		CustomPatterns: []config.CustomPatternConfig{
			{Name: "customer_id", Display: "identifier", Regex: `CUST-\d{8}`},
		},
	}
	p := NewDLPProcessor(cfg)

	input := []byte(`{"content": "Customer CUST-12345678 called"}`)
	result := p.Process(input)

	expected := `{"content": "Customer [REDACTED:identifier] called"}`
	if string(result.ProcessedData) != expected {
		t.Errorf("got %s, want %s", result.ProcessedData, expected)
	}
	// Internal type should use name, not display
	if result.Redactions[0].Type != "customer_id" {
		t.Errorf("expected internal type 'customer_id', got %q", result.Redactions[0].Type)
	}
}

func TestDLPProcessor_Disabled(t *testing.T) {
	cfg := config.DLPConfig{Mode: "disabled"}
	p := NewDLPProcessor(cfg)

	input := []byte(`{"content": "john@example.com"}`)
	result := p.Process(input)

	if string(result.ProcessedData) != string(input) {
		t.Errorf("disabled mode should not modify input")
	}
	if result.Modified {
		t.Error("disabled mode should report not modified")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/... -run TestDLPProcessor -v`
Expected: FAIL (signature mismatch, needs config.DLPConfig)

**Step 3: Refactor DLP processor to use config types**

Update `internal/llmproxy/dlp.go` to accept `config.DLPConfig`:

```go
package llmproxy

import (
	"encoding/json"
	"regexp"
	"sync"

	"github.com/agentsh/agentsh/internal/config"
)

// Built-in regex patterns for PII detection.
var builtinPatterns = map[string]string{
	"email":       `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"phone":       `(?:\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,
	"credit_card": `\b(?:\d[ -]*?){13,19}\b`,
	"ssn":         `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,
	"api_key":     `(?i)(?:sk|api|key|secret|token)[-_]?[a-zA-Z0-9]{20,}`,
}

type compiledPattern struct {
	name    string // internal name for logs
	display string // display name for redaction text
	regex   *regexp.Regexp
}

// DLPProcessor processes data for PII detection and redaction.
type DLPProcessor struct {
	mode     string
	patterns []*compiledPattern
	mu       sync.RWMutex
}

// NewDLPProcessor creates a new DLP processor from configuration.
func NewDLPProcessor(cfg config.DLPConfig) *DLPProcessor {
	dp := &DLPProcessor{
		mode:     cfg.Mode,
		patterns: make([]*compiledPattern, 0),
	}

	if cfg.Mode == "disabled" {
		return dp
	}

	// Add enabled built-in patterns
	if cfg.Patterns.Email {
		dp.addPattern("email", "email", builtinPatterns["email"])
	}
	if cfg.Patterns.Phone {
		dp.addPattern("phone", "phone", builtinPatterns["phone"])
	}
	if cfg.Patterns.CreditCard {
		dp.addPattern("credit_card", "credit_card", builtinPatterns["credit_card"])
	}
	if cfg.Patterns.SSN {
		dp.addPattern("ssn", "ssn", builtinPatterns["ssn"])
	}
	if cfg.Patterns.APIKeys {
		dp.addPattern("api_key", "api_key", builtinPatterns["api_key"])
	}

	// Add custom patterns
	for _, cp := range cfg.CustomPatterns {
		display := cp.Display
		if display == "" {
			display = cp.Name
		}
		dp.addPattern(cp.Name, display, cp.Regex)
	}

	return dp
}

func (dp *DLPProcessor) addPattern(name, display, pattern string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return // skip invalid patterns
	}
	dp.patterns = append(dp.patterns, &compiledPattern{
		name:    name,
		display: display,
		regex:   re,
	})
}

// DLPResult contains the result of DLP processing.
type DLPResult struct {
	ProcessedData []byte
	Redactions    []Redaction
	Modified      bool
}

// Redaction describes a single redaction event.
type Redaction struct {
	Field string `json:"field,omitempty"`
	Type  string `json:"type"`  // internal name
	Count int    `json:"count"`
}

// Process applies DLP to the given data.
func (dp *DLPProcessor) Process(data []byte) *DLPResult {
	result := &DLPResult{
		ProcessedData: data,
		Redactions:    make([]Redaction, 0),
		Modified:      false,
	}

	if dp.mode == "disabled" || len(dp.patterns) == 0 {
		return result
	}

	// Try to parse as JSON for structured processing
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		modified := dp.processJSON(jsonData, "", result)
		if modified {
			result.Modified = true
			if newData, err := json.Marshal(jsonData); err == nil {
				result.ProcessedData = newData
			}
		}
	} else {
		// Process as plain text
		result.ProcessedData, result.Modified = dp.processText(data, "", result)
	}

	return result
}

func (dp *DLPProcessor) processJSON(v interface{}, path string, result *DLPResult) bool {
	modified := false

	switch val := v.(type) {
	case map[string]interface{}:
		for k, vv := range val {
			fieldPath := k
			if path != "" {
				fieldPath = path + "." + k
			}
			if s, ok := vv.(string); ok {
				processed, changed := dp.processText([]byte(s), fieldPath, result)
				if changed {
					val[k] = string(processed)
					modified = true
				}
			} else {
				if dp.processJSON(vv, fieldPath, result) {
					modified = true
				}
			}
		}
	case []interface{}:
		for i, vv := range val {
			fieldPath := path + "[" + itoa(i) + "]"
			if s, ok := vv.(string); ok {
				processed, changed := dp.processText([]byte(s), fieldPath, result)
				if changed {
					val[i] = string(processed)
					modified = true
				}
			} else {
				if dp.processJSON(vv, fieldPath, result) {
					modified = true
				}
			}
		}
	}

	return modified
}

func (dp *DLPProcessor) processText(data []byte, path string, result *DLPResult) ([]byte, bool) {
	text := string(data)
	modified := false

	for _, pattern := range dp.patterns {
		matches := pattern.regex.FindAllString(text, -1)
		if len(matches) == 0 {
			continue
		}

		uniqueMatches := make(map[string]bool)
		for _, m := range matches {
			uniqueMatches[m] = true
		}

		result.Redactions = append(result.Redactions, Redaction{
			Field: path,
			Type:  pattern.name, // internal name for logs
			Count: len(uniqueMatches),
		})

		// Replace with display name
		text = pattern.regex.ReplaceAllString(text, "[REDACTED:"+pattern.display+"]")
		modified = true
	}

	return []byte(text), modified
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/... -run TestDLPProcessor -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/dlp.go internal/llmproxy/dlp_test.go
git commit -m "feat(llmproxy): implement DLP processor with custom pattern support"
```

---

## Task 4: Implement Token Usage Extraction

**Files:**
- Create: `internal/llmproxy/usage.go`
- Create: `internal/llmproxy/usage_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/usage_test.go
package llmproxy

import "testing"

func TestExtractUsage_Anthropic(t *testing.T) {
	body := []byte(`{
		"content": [{"text": "Hello"}],
		"usage": {"input_tokens": 150, "output_tokens": 892}
	}`)

	usage, err := ExtractUsage(body, DialectAnthropic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 150 {
		t.Errorf("expected input_tokens 150, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 892 {
		t.Errorf("expected output_tokens 892, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_OpenAI(t *testing.T) {
	body := []byte(`{
		"choices": [{"message": {"content": "Hello"}}],
		"usage": {"prompt_tokens": 150, "completion_tokens": 892, "total_tokens": 1042}
	}`)

	usage, err := ExtractUsage(body, DialectOpenAI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 150 {
		t.Errorf("expected input_tokens 150, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 892 {
		t.Errorf("expected output_tokens 892, got %d", usage.OutputTokens)
	}
}

func TestExtractUsage_NoUsage(t *testing.T) {
	body := []byte(`{"content": "Hello"}`)

	usage, err := ExtractUsage(body, DialectAnthropic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Error("expected zero tokens when usage not present")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/... -run TestExtractUsage -v`
Expected: FAIL with "undefined: ExtractUsage"

**Step 3: Implement usage extraction**

```go
// internal/llmproxy/usage.go
package llmproxy

import "encoding/json"

// Usage represents normalized token usage.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ExtractUsage extracts token usage from a response body.
func ExtractUsage(body []byte, dialect Dialect) (Usage, error) {
	var usage Usage

	switch dialect {
	case DialectAnthropic:
		var resp struct {
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return usage, nil // not an error, just no usage
		}
		usage.InputTokens = resp.Usage.InputTokens
		usage.OutputTokens = resp.Usage.OutputTokens

	case DialectOpenAI, DialectChatGPT:
		var resp struct {
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return usage, nil
		}
		usage.InputTokens = resp.Usage.PromptTokens
		usage.OutputTokens = resp.Usage.CompletionTokens
	}

	return usage, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/... -run TestExtractUsage -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/usage.go internal/llmproxy/usage_test.go
git commit -m "feat(llmproxy): implement token usage extraction"
```

---

## Task 5: Implement LLM Request Storage

**Files:**
- Create: `internal/llmproxy/storage.go`
- Create: `internal/llmproxy/storage_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/storage_test.go
package llmproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorage_LogRequest(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStorage(dir, "test-session")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()

	entry := &RequestLogEntry{
		ID:        "req_001",
		SessionID: "test-session",
		Timestamp: time.Now().UTC(),
		Dialect:   DialectAnthropic,
		Request: RequestInfo{
			Method:   "POST",
			Path:     "/v1/messages",
			BodySize: 100,
		},
	}

	if err := s.LogRequest(entry); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}

	// Verify file exists
	logFile := filepath.Join(dir, "test-session", "llm-requests.jsonl")
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("expected log file to exist")
	}
}

func TestStorage_LogResponse(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStorage(dir, "test-session")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()

	entry := &ResponseLogEntry{
		RequestID:  "req_001",
		SessionID:  "test-session",
		Timestamp:  time.Now().UTC(),
		DurationMs: 1234,
		Response: ResponseInfo{
			Status:   200,
			BodySize: 500,
		},
		Usage: Usage{InputTokens: 100, OutputTokens: 200},
	}

	if err := s.LogResponse(entry); err != nil {
		t.Fatalf("LogResponse: %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/... -run TestStorage -v`
Expected: FAIL (Storage implementation incomplete)

**Step 3: Implement storage**

```go
// internal/llmproxy/storage.go
package llmproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RequestLogEntry represents a logged request.
type RequestLogEntry struct {
	ID        string      `json:"id"`
	SessionID string      `json:"session_id"`
	Timestamp time.Time   `json:"timestamp"`
	Dialect   Dialect     `json:"dialect"`
	Request   RequestInfo `json:"request"`
	DLP       *DLPInfo    `json:"dlp,omitempty"`
}

// RequestInfo contains request details.
type RequestInfo struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	BodySize int    `json:"body_size"`
	BodyHash string `json:"body_hash,omitempty"`
}

// ResponseLogEntry represents a logged response.
type ResponseLogEntry struct {
	RequestID  string       `json:"request_id"`
	SessionID  string       `json:"session_id"`
	Timestamp  time.Time    `json:"timestamp"`
	DurationMs int64        `json:"duration_ms"`
	Response   ResponseInfo `json:"response"`
	Usage      Usage        `json:"usage,omitempty"`
}

// ResponseInfo contains response details.
type ResponseInfo struct {
	Status   int    `json:"status"`
	BodySize int    `json:"body_size"`
	BodyHash string `json:"body_hash,omitempty"`
}

// DLPInfo contains DLP processing information.
type DLPInfo struct {
	Redactions []Redaction `json:"redactions"`
}

// Storage handles request/response logging to disk.
type Storage struct {
	basePath  string
	sessionID string
	file      *os.File
	mu        sync.Mutex
}

// NewStorage creates a new storage instance.
func NewStorage(basePath, sessionID string) (*Storage, error) {
	sessionDir := filepath.Join(basePath, sessionID)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}

	logPath := filepath.Join(sessionDir, "llm-requests.jsonl")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &Storage{
		basePath:  basePath,
		sessionID: sessionID,
		file:      f,
	}, nil
}

// LogRequest logs a request entry.
func (s *Storage) LogRequest(entry *RequestLogEntry) error {
	return s.writeEntry(entry)
}

// LogResponse logs a response entry.
func (s *Storage) LogResponse(entry *ResponseLogEntry) error {
	return s.writeEntry(entry)
}

func (s *Storage) writeEntry(entry interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	if _, err := s.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}

	return nil
}

// Close closes the storage.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// HashBody computes a SHA256 hash of the body.
func HashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	h := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(h[:])
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/... -run TestStorage -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/storage.go internal/llmproxy/storage_test.go
git commit -m "feat(llmproxy): implement request/response storage"
```

---

## Task 6: Refactor Proxy Core

**Files:**
- Modify: `internal/llmproxy/proxy.go`
- Create: `internal/llmproxy/proxy_test.go`

**Step 1: Write the failing test**

```go
// internal/llmproxy/proxy_test.go
package llmproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestProxy_AnthropicPassthrough(t *testing.T) {
	// Mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			t.Error("expected x-api-key header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"text":"Hello"}],"usage":{"input_tokens":10,"output_tokens":20}}`))
	}))
	defer upstream.Close()

	cfg := Config{
		SessionID: "test-session",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DLPConfig{Mode: "disabled"},
	}
	cfg.Proxy.Upstreams.Anthropic = upstream.URL

	p, err := New(cfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Stop(context.Background())

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Make request through proxy
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages", strings.NewReader(`{"messages":[]}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Hello") {
		t.Errorf("unexpected response: %s", body)
	}
}

func TestProxy_DLPRedaction(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":10,"output_tokens":5}}`))
	}))
	defer upstream.Close()

	cfg := Config{
		SessionID: "test-session",
		Proxy:     config.DefaultProxyConfig(),
		DLP: config.DLPConfig{
			Mode:     "redact",
			Patterns: config.DLPPatternsConfig{Email: true},
		},
	}
	cfg.Proxy.Upstreams.Anthropic = upstream.URL

	p, err := New(cfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Stop(context.Background())
	p.Start(context.Background())

	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"Email me at john@example.com"}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if !strings.Contains(receivedBody, "[REDACTED:email]") {
		t.Errorf("expected email to be redacted, got: %s", receivedBody)
	}
	if strings.Contains(receivedBody, "john@example.com") {
		t.Error("email should have been redacted")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/llmproxy/... -run TestProxy -v`
Expected: FAIL (Config type mismatch)

**Step 3: Refactor proxy to use new config and components**

Update `internal/llmproxy/proxy.go` - significant refactor to:
- Use `config.ProxyConfig` and `config.DLPConfig`
- Integrate with new DLP processor
- Integrate with new storage
- Extract token usage from responses
- Buffer streaming responses

(This is a large refactor - see the spec for complete implementation. Key changes:)

```go
// Config for the proxy
type Config struct {
	SessionID string
	Proxy     config.ProxyConfig
	DLP       config.DLPConfig
	Storage   config.StorageConfig
}

// New creates a new LLM proxy
func New(cfg Config, storagePath string, logger *slog.Logger) (*Proxy, error) {
	// ... initialize components with new config types
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/llmproxy/... -run TestProxy -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/llmproxy/proxy.go internal/llmproxy/proxy_test.go
git commit -m "feat(llmproxy): refactor proxy with config, DLP, storage integration"
```

---

## Task 7: Integrate with Session Lifecycle

**Files:**
- Create: `internal/session/llmproxy.go`
- Create: `internal/session/llmproxy_test.go`
- Modify: `internal/api/session_create.go` (or equivalent)

**Step 1: Write the failing test**

```go
// internal/session/llmproxy_test.go
package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestSession_LLMProxyEnvVars(t *testing.T) {
	cfg := config.DefaultProxyConfig()
	dlpCfg := config.DefaultDLPConfig()
	storageCfg := config.DefaultStorageConfig()

	sess := &Session{
		ID:        "test-session",
		Workspace: "/tmp/test",
	}

	proxyURL, cleanup, err := StartLLMProxy(sess, cfg, dlpCfg, storageCfg, "/tmp/storage")
	if err != nil {
		t.Fatalf("StartLLMProxy: %v", err)
	}
	defer cleanup()

	if proxyURL == "" {
		t.Error("expected proxy URL")
	}

	envVars := sess.LLMProxyEnvVars()
	if envVars["ANTHROPIC_BASE_URL"] != proxyURL {
		t.Errorf("ANTHROPIC_BASE_URL = %q, want %q", envVars["ANTHROPIC_BASE_URL"], proxyURL)
	}
	if envVars["OPENAI_BASE_URL"] != proxyURL {
		t.Errorf("OPENAI_BASE_URL = %q, want %q", envVars["OPENAI_BASE_URL"], proxyURL)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/session/... -run TestSession_LLMProxy -v`
Expected: FAIL with "undefined: StartLLMProxy"

**Step 3: Implement session integration**

```go
// internal/session/llmproxy.go
package session

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/llmproxy"
)

// StartLLMProxy starts the embedded LLM proxy for a session.
func StartLLMProxy(sess *Session, proxyCfg config.ProxyConfig, dlpCfg config.DLPConfig, storageCfg config.StorageConfig, storagePath string) (string, func() error, error) {
	if proxyCfg.Mode == "disabled" {
		return "", func() error { return nil }, nil
	}

	cfg := llmproxy.Config{
		SessionID: sess.ID,
		Proxy:     proxyCfg,
		DLP:       dlpCfg,
		Storage:   storageCfg,
	}

	proxy, err := llmproxy.New(cfg, storagePath, slog.Default())
	if err != nil {
		return "", nil, fmt.Errorf("create llm proxy: %w", err)
	}

	if err := proxy.Start(context.Background()); err != nil {
		return "", nil, fmt.Errorf("start llm proxy: %w", err)
	}

	proxyURL := fmt.Sprintf("http://%s", proxy.Addr().String())

	sess.mu.Lock()
	sess.llmProxyURL = proxyURL
	sess.mu.Unlock()

	cleanup := func() error {
		return proxy.Stop(context.Background())
	}

	return proxyURL, cleanup, nil
}

// LLMProxyEnvVars returns environment variables for the agent process.
func (s *Session) LLMProxyEnvVars() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.llmProxyURL == "" {
		return nil
	}

	return map[string]string{
		"ANTHROPIC_BASE_URL": s.llmProxyURL,
		"OPENAI_BASE_URL":    s.llmProxyURL,
		"AGENTSH_SESSION_ID": s.ID,
	}
}
```

Also add `llmProxyURL string` to the Session struct in `manager.go`.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/session/... -run TestSession_LLMProxy -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/session/llmproxy.go internal/session/llmproxy_test.go internal/session/manager.go
git commit -m "feat(session): integrate LLM proxy with session lifecycle"
```

---

## Task 8: Add CLI Proxy Status Command

**Files:**
- Create: `internal/cli/proxy_cmd.go`
- Create: `internal/cli/proxy_cmd_test.go`
- Modify: `internal/cli/root.go`

**Step 1: Write the failing test**

```go
// internal/cli/proxy_cmd_test.go
package cli

import (
	"bytes"
	"testing"
)

func TestProxyStatusCmd(t *testing.T) {
	// This is a basic smoke test - full integration testing
	// requires a running server with a session
	cmd := newProxyCmd()
	if cmd.Use != "proxy" {
		t.Errorf("expected 'proxy' command, got %q", cmd.Use)
	}

	// Check subcommands exist
	statusCmd, _, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Errorf("expected 'status' subcommand: %v", err)
	}
	if statusCmd == nil {
		t.Error("status subcommand not found")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestProxyStatusCmd -v`
Expected: FAIL with "undefined: newProxyCmd"

**Step 3: Implement proxy CLI commands**

```go
// internal/cli/proxy_cmd.go
package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the LLM proxy",
	}

	cmd.AddCommand(newProxyStatusCmd())
	return cmd
}

func newProxyStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [SESSION_ID]",
		Short: "Show LLM proxy status",
		Long: `Show status of the embedded LLM proxy for a session.

Examples:
  # Status for latest session
  agentsh proxy status

  # Status for specific session
  agentsh proxy status abc123`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			sessionID := ""
			if len(args) > 0 {
				sessionID = args[0]
			}

			status, err := c.GetProxyStatus(cmd.Context(), sessionID)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Proxy: %s on %s\n", status.State, status.Address)
			fmt.Fprintf(cmd.OutOrStdout(), "Mode: %s\n", status.Mode)
			fmt.Fprintf(cmd.OutOrStdout(), "DLP: %s (%d patterns active)\n", status.DLPMode, status.ActivePatterns)
			fmt.Fprintf(cmd.OutOrStdout(), "Requests: %d (%d with redactions)\n", status.TotalRequests, status.RequestsWithRedactions)
			fmt.Fprintf(cmd.OutOrStdout(), "Tokens: %d in / %d out\n", status.TotalInputTokens, status.TotalOutputTokens)

			return nil
		},
	}

	return cmd
}
```

Add to `root.go`:

```go
rootCmd.AddCommand(newProxyCmd())
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -run TestProxyStatusCmd -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/proxy_cmd.go internal/cli/proxy_cmd_test.go internal/cli/root.go
git commit -m "feat(cli): add proxy status command"
```

---

## Task 9: Enhance Session Logs Command

**Files:**
- Modify: `internal/cli/session.go`
- Modify: `internal/cli/session_test.go` (if exists)

**Step 1: Add --type=llm flag to session logs**

Add `--type` flag to existing logs command to filter by event type including new `llm` type.

**Step 2: Commit**

```bash
git add internal/cli/session.go
git commit -m "feat(cli): add --type=llm filter to session logs"
```

---

## Task 10: Enhance Report with LLM Stats

**Files:**
- Modify: `internal/report/generator.go`
- Modify: `internal/report/format.go`
- Modify: `internal/report/generator_test.go`

**Step 1: Write the failing test**

Add test that expects LLM usage section in detailed report.

**Step 2: Add LLM stats to report generation**

Parse `llm-requests.jsonl` from session storage and aggregate stats.

**Step 3: Add LLM section to markdown formatter**

**Step 4: Commit**

```bash
git add internal/report/
git commit -m "feat(report): add LLM usage and DLP stats to reports"
```

---

## Task 11: Integration Testing

**Files:**
- Create: `internal/llmproxy/integration_test.go`

**Step 1: Write integration test**

```go
// internal/llmproxy/integration_test.go
//go:build integration

package llmproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

func TestIntegration_FullFlow(t *testing.T) {
	// 1. Start mock LLM upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Verify DLP was applied
		if strings.Contains(string(body), "john@example.com") {
			t.Error("email should have been redacted before reaching upstream")
		}
		w.Write([]byte(`{"content":[{"text":"OK"}],"usage":{"input_tokens":50,"output_tokens":100}}`))
	}))
	defer upstream.Close()

	// 2. Configure and start proxy
	cfg := Config{
		SessionID: "integration-test",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultStorageConfig(),
	}
	cfg.Proxy.Upstreams.Anthropic = upstream.URL

	storageDir := t.TempDir()
	p, err := New(cfg, storageDir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop(ctx)

	// 3. Send request with PII
	req, _ := http.NewRequest("POST", "http://"+p.Addr().String()+"/v1/messages",
		strings.NewReader(`{"content":"Contact john@example.com please"}`))
	req.Header.Set("x-api-key", "test-key")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// 4. Verify storage has logs
	// (check file exists and contains expected entries)
}
```

**Step 2: Run integration test**

Run: `go test ./internal/llmproxy/... -tags=integration -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/llmproxy/integration_test.go
git commit -m "test(llmproxy): add integration tests"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Configuration structs | `internal/config/proxy.go` |
| 2 | Dialect detection | `internal/llmproxy/dialect.go` |
| 3 | DLP processor | `internal/llmproxy/dlp.go` |
| 4 | Token extraction | `internal/llmproxy/usage.go` |
| 5 | Request storage | `internal/llmproxy/storage.go` |
| 6 | Proxy core refactor | `internal/llmproxy/proxy.go` |
| 7 | Session integration | `internal/session/llmproxy.go` |
| 8 | CLI proxy command | `internal/cli/proxy_cmd.go` |
| 9 | Session logs enhancement | `internal/cli/session.go` |
| 10 | Report enhancement | `internal/report/` |
| 11 | Integration tests | `internal/llmproxy/integration_test.go` |
