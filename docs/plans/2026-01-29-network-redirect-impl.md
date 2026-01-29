# Network Redirect Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add DNS and connect-level redirect capability for agentsh-wrapped processes on Linux.

**Architecture:** Extend existing policy engine with `dns_redirects` and `connect_redirects` rule types. DNS interception via uprobe on getaddrinfo, connect interception via existing eBPF infrastructure. Events emitted through existing broker.

**Tech Stack:** Go, cilium/ebpf, CO-RE BPF programs

---

### Task 1: Add Rule Types to Policy Model

**Files:**
- Modify: `internal/policy/model.go`

**Step 1: Add DnsRedirectRule struct**

Add after line ~135 (after existing rule types):

```go
// DnsRedirectRule redirects DNS resolution for matching hostnames
type DnsRedirectRule struct {
	Name       string `yaml:"name"`
	Match      string `yaml:"match"`                // regex pattern for hostname
	ResolveTo  string `yaml:"resolve_to"`           // IP address to return
	Visibility string `yaml:"visibility,omitempty"` // silent, audit_only, warn
	OnFailure  string `yaml:"on_failure,omitempty"` // fail_closed, fail_open, retry_original
}

// ConnectRedirectRule redirects TCP connections for matching host:port
type ConnectRedirectRule struct {
	Name       string                    `yaml:"name"`
	Match      string                    `yaml:"match"`                // regex pattern for host:port
	RedirectTo string                    `yaml:"redirect_to"`          // new host:port destination
	TLS        *ConnectRedirectTLSConfig `yaml:"tls,omitempty"`
	Visibility string                    `yaml:"visibility,omitempty"` // silent, audit_only, warn
	Message    string                    `yaml:"message,omitempty"`
	OnFailure  string                    `yaml:"on_failure,omitempty"` // fail_closed, fail_open, retry_original
}

// ConnectRedirectTLSConfig controls TLS handling for connect redirects
type ConnectRedirectTLSConfig struct {
	Mode string `yaml:"mode,omitempty"` // passthrough, rewrite_sni
	SNI  string `yaml:"sni,omitempty"`  // required if mode is rewrite_sni
}
```

**Step 2: Add rules to Policy struct**

Find the Policy struct and add:

```go
type Policy struct {
	// ... existing fields
	DnsRedirectRules     []DnsRedirectRule     `yaml:"dns_redirects,omitempty"`
	ConnectRedirectRules []ConnectRedirectRule `yaml:"connect_redirects,omitempty"`
}
```

**Step 3: Run tests**

Run: `go build ./...`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add internal/policy/model.go
git commit -m "feat(policy): add DnsRedirectRule and ConnectRedirectRule types"
```

---

### Task 2: Add Validation for Redirect Rules

**Files:**
- Modify: `internal/policy/model.go` (Validate method)

**Step 1: Add validation logic**

Find the `Validate()` method and add validation for new rules:

```go
func (p *Policy) Validate() error {
	// ... existing validation

	// Validate DNS redirect rules
	for i, r := range p.DnsRedirectRules {
		if r.Name == "" {
			return fmt.Errorf("dns_redirects[%d]: name is required", i)
		}
		if r.Match == "" {
			return fmt.Errorf("dns_redirects[%d]: match is required", i)
		}
		if _, err := regexp.Compile(r.Match); err != nil {
			return fmt.Errorf("dns_redirects[%d]: invalid match regex: %w", i, err)
		}
		if r.ResolveTo == "" {
			return fmt.Errorf("dns_redirects[%d]: resolve_to is required", i)
		}
		if net.ParseIP(r.ResolveTo) == nil {
			return fmt.Errorf("dns_redirects[%d]: resolve_to must be valid IP", i)
		}
		if r.Visibility != "" && r.Visibility != "silent" && r.Visibility != "audit_only" && r.Visibility != "warn" {
			return fmt.Errorf("dns_redirects[%d]: visibility must be silent, audit_only, or warn", i)
		}
		if r.OnFailure != "" && r.OnFailure != "fail_closed" && r.OnFailure != "fail_open" && r.OnFailure != "retry_original" {
			return fmt.Errorf("dns_redirects[%d]: on_failure must be fail_closed, fail_open, or retry_original", i)
		}
	}

	// Validate connect redirect rules
	for i, r := range p.ConnectRedirectRules {
		if r.Name == "" {
			return fmt.Errorf("connect_redirects[%d]: name is required", i)
		}
		if r.Match == "" {
			return fmt.Errorf("connect_redirects[%d]: match is required", i)
		}
		if _, err := regexp.Compile(r.Match); err != nil {
			return fmt.Errorf("connect_redirects[%d]: invalid match regex: %w", i, err)
		}
		if r.RedirectTo == "" {
			return fmt.Errorf("connect_redirects[%d]: redirect_to is required", i)
		}
		if r.TLS != nil {
			if r.TLS.Mode != "" && r.TLS.Mode != "passthrough" && r.TLS.Mode != "rewrite_sni" {
				return fmt.Errorf("connect_redirects[%d]: tls.mode must be passthrough or rewrite_sni", i)
			}
			if r.TLS.Mode == "rewrite_sni" && r.TLS.SNI == "" {
				return fmt.Errorf("connect_redirects[%d]: tls.sni required when mode is rewrite_sni", i)
			}
		}
		if r.Visibility != "" && r.Visibility != "silent" && r.Visibility != "audit_only" && r.Visibility != "warn" {
			return fmt.Errorf("connect_redirects[%d]: visibility must be silent, audit_only, or warn", i)
		}
		if r.OnFailure != "" && r.OnFailure != "fail_closed" && r.OnFailure != "fail_open" && r.OnFailure != "retry_original" {
			return fmt.Errorf("connect_redirects[%d]: on_failure must be fail_closed, fail_open, or retry_original", i)
		}
	}

	return nil
}
```

**Step 2: Run tests**

Run: `go test ./internal/policy/...`
Expected: Tests pass

**Step 3: Commit**

```bash
git add internal/policy/model.go
git commit -m "feat(policy): add validation for redirect rules"
```

---

### Task 3: Add Event Types for Redirects

**Files:**
- Modify: `internal/events/types.go`
- Modify: `internal/events/schema.go`

**Step 1: Add event type constants**

In `types.go`, add to the EventType constants:

```go
const (
	// ... existing events
	EventDNSRedirect          EventType = "dns_redirect"
	EventConnectRedirect      EventType = "connect_redirect"
	EventConnectRedirectFallback EventType = "connect_redirect_fallback"
)
```

**Step 2: Add to EventCategory map**

```go
var EventCategory = map[EventType]string{
	// ... existing mappings
	EventDNSRedirect:             "network",
	EventConnectRedirect:         "network",
	EventConnectRedirectFallback: "network",
}
```

**Step 3: Add event schemas**

In `schema.go`, add:

```go
// DNSRedirectEvent records DNS resolution redirects
type DNSRedirectEvent struct {
	BaseEvent
	OriginalHost string `json:"original_host"`
	ResolvedTo   string `json:"resolved_to"`
	Rule         string `json:"rule"`
	Visibility   string `json:"visibility"`
}

// ConnectRedirectEvent records TCP connection redirects
type ConnectRedirectEvent struct {
	BaseEvent
	Original    string `json:"original"`     // host:port
	RedirectedTo string `json:"redirected_to"` // host:port
	Rule        string `json:"rule"`
	TLSMode     string `json:"tls_mode,omitempty"`
	Visibility  string `json:"visibility"`
	Message     string `json:"message,omitempty"`
}

// ConnectRedirectFallbackEvent records fallback to original destination
type ConnectRedirectFallbackEvent struct {
	BaseEvent
	Original          string `json:"original"`
	RedirectAttempted string `json:"redirect_attempted"`
	Error             string `json:"error"`
	Action            string `json:"action"` // fail_open, retry_original
	Status            string `json:"status"` // connected_to_original, failed
	Rule              string `json:"rule"`
}
```

**Step 4: Run tests**

Run: `go build ./...`
Expected: Build succeeds

**Step 5: Commit**

```bash
git add internal/events/types.go internal/events/schema.go
git commit -m "feat(events): add DNS and connect redirect event types"
```

---

### Task 4: Add Compiled Rules to Policy Engine

**Files:**
- Modify: `internal/policy/engine.go`

**Step 1: Add compiled rule types**

Add after existing compiled types:

```go
type compiledDnsRedirectRule struct {
	rule    DnsRedirectRule
	pattern *regexp.Regexp
}

type compiledConnectRedirectRule struct {
	rule    ConnectRedirectRule
	pattern *regexp.Regexp
}
```

**Step 2: Add fields to Engine struct**

```go
type Engine struct {
	// ... existing fields
	dnsRedirectRules     []compiledDnsRedirectRule
	connectRedirectRules []compiledConnectRedirectRule
}
```

**Step 3: Add compilation in NewEngine**

In the `NewEngine` function, add:

```go
// Compile DNS redirect rules
for _, r := range p.DnsRedirectRules {
	pattern, _ := regexp.Compile(r.Match) // Already validated
	e.dnsRedirectRules = append(e.dnsRedirectRules, compiledDnsRedirectRule{
		rule:    r,
		pattern: pattern,
	})
}

// Compile connect redirect rules
for _, r := range p.ConnectRedirectRules {
	pattern, _ := regexp.Compile(r.Match) // Already validated
	e.connectRedirectRules = append(e.connectRedirectRules, compiledConnectRedirectRule{
		rule:    r,
		pattern: pattern,
	})
}
```

**Step 4: Run tests**

Run: `go build ./...`
Expected: Build succeeds

**Step 5: Commit**

```bash
git add internal/policy/engine.go
git commit -m "feat(policy): compile DNS and connect redirect rules in engine"
```

---

### Task 5: Add Evaluation Methods to Engine

**Files:**
- Modify: `internal/policy/engine.go`

**Step 1: Add DNS redirect evaluation**

```go
// DnsRedirectResult contains the result of DNS redirect evaluation
type DnsRedirectResult struct {
	Matched    bool
	Rule       string
	ResolveTo  string
	Visibility string
	OnFailure  string
}

// EvaluateDnsRedirect checks if a hostname should be redirected
func (e *Engine) EvaluateDnsRedirect(hostname string) *DnsRedirectResult {
	for _, r := range e.dnsRedirectRules {
		if r.pattern.MatchString(hostname) {
			visibility := r.rule.Visibility
			if visibility == "" {
				visibility = "audit_only"
			}
			onFailure := r.rule.OnFailure
			if onFailure == "" {
				onFailure = "fail_closed"
			}
			return &DnsRedirectResult{
				Matched:    true,
				Rule:       r.rule.Name,
				ResolveTo:  r.rule.ResolveTo,
				Visibility: visibility,
				OnFailure:  onFailure,
			}
		}
	}
	return &DnsRedirectResult{Matched: false}
}
```

**Step 2: Add connect redirect evaluation**

```go
// ConnectRedirectResult contains the result of connect redirect evaluation
type ConnectRedirectResult struct {
	Matched    bool
	Rule       string
	RedirectTo string
	TLSMode    string
	SNI        string
	Visibility string
	Message    string
	OnFailure  string
}

// EvaluateConnectRedirect checks if a connection should be redirected
func (e *Engine) EvaluateConnectRedirect(hostPort string) *ConnectRedirectResult {
	for _, r := range e.connectRedirectRules {
		if r.pattern.MatchString(hostPort) {
			visibility := r.rule.Visibility
			if visibility == "" {
				visibility = "audit_only"
			}
			onFailure := r.rule.OnFailure
			if onFailure == "" {
				onFailure = "fail_closed"
			}
			tlsMode := "passthrough"
			sni := ""
			if r.rule.TLS != nil {
				if r.rule.TLS.Mode != "" {
					tlsMode = r.rule.TLS.Mode
				}
				sni = r.rule.TLS.SNI
			}
			return &ConnectRedirectResult{
				Matched:    true,
				Rule:       r.rule.Name,
				RedirectTo: r.rule.RedirectTo,
				TLSMode:    tlsMode,
				SNI:        sni,
				Visibility: visibility,
				Message:    r.rule.Message,
				OnFailure:  onFailure,
			}
		}
	}
	return &ConnectRedirectResult{Matched: false}
}
```

**Step 3: Run tests**

Run: `go test ./internal/policy/...`
Expected: Tests pass

**Step 4: Commit**

```bash
git add internal/policy/engine.go
git commit -m "feat(policy): add DNS and connect redirect evaluation methods"
```

---

### Task 6: Write Unit Tests for Redirect Rules

**Files:**
- Create: `internal/policy/redirect_test.go`

**Step 1: Create test file**

```go
package policy

import (
	"testing"
)

func TestDnsRedirectRuleValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    DnsRedirectRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*\\.anthropic\\.com",
				ResolveTo: "10.0.0.50",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: DnsRedirectRule{
				Match:     ".*\\.anthropic\\.com",
				ResolveTo: "10.0.0.50",
			},
			wantErr: true,
		},
		{
			name: "invalid regex",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     "[invalid",
				ResolveTo: "10.0.0.50",
			},
			wantErr: true,
		},
		{
			name: "invalid IP",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "not-an-ip",
			},
			wantErr: true,
		},
		{
			name: "invalid visibility",
			rule: DnsRedirectRule{
				Name:       "test",
				Match:      ".*",
				ResolveTo:  "10.0.0.1",
				Visibility: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Version:          1,
				Name:             "test",
				DnsRedirectRules: []DnsRedirectRule{tt.rule},
			}
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnectRedirectRuleValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    ConnectRedirectRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      "api\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy:443",
			},
			wantErr: false,
		},
		{
			name: "valid with TLS passthrough",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "passthrough"},
			},
			wantErr: false,
		},
		{
			name: "rewrite_sni without sni",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "rewrite_sni"},
			},
			wantErr: true,
		},
		{
			name: "rewrite_sni with sni",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "proxy.internal"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Version:              1,
				Name:                 "test",
				ConnectRedirectRules: []ConnectRedirectRule{tt.rule},
			}
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateDnsRedirect(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		DnsRedirectRules: []DnsRedirectRule{
			{
				Name:       "anthropic-redirect",
				Match:      ".*\\.anthropic\\.com",
				ResolveTo:  "10.0.0.50",
				Visibility: "warn",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostname string
		wantMatch bool
		wantIP    string
	}{
		{"api.anthropic.com", true, "10.0.0.50"},
		{"console.anthropic.com", true, "10.0.0.50"},
		{"google.com", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			result := engine.EvaluateDnsRedirect(tt.hostname)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateDnsRedirect(%s) matched = %v, want %v", tt.hostname, result.Matched, tt.wantMatch)
			}
			if result.Matched && result.ResolveTo != tt.wantIP {
				t.Errorf("EvaluateDnsRedirect(%s) resolveTo = %v, want %v", tt.hostname, result.ResolveTo, tt.wantIP)
			}
		})
	}
}

func TestEvaluateConnectRedirect(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []ConnectRedirectRule{
			{
				Name:       "anthropic-redirect",
				Match:      "api\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy.internal:443",
				Message:    "Routed through Vertex",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostPort   string
		wantMatch  bool
		wantTarget string
	}{
		{"api.anthropic.com:443", true, "vertex-proxy.internal:443"},
		{"api.anthropic.com:80", false, ""},
		{"google.com:443", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostPort, func(t *testing.T) {
			result := engine.EvaluateConnectRedirect(tt.hostPort)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateConnectRedirect(%s) matched = %v, want %v", tt.hostPort, result.Matched, tt.wantMatch)
			}
			if result.Matched && result.RedirectTo != tt.wantTarget {
				t.Errorf("EvaluateConnectRedirect(%s) redirectTo = %v, want %v", tt.hostPort, result.RedirectTo, tt.wantTarget)
			}
		})
	}
}
```

**Step 2: Run tests**

Run: `go test ./internal/policy/... -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/policy/redirect_test.go
git commit -m "test(policy): add unit tests for redirect rules"
```

---

### Task 7: Add Hostname-to-IP Correlation Map

**Files:**
- Create: `internal/netmonitor/redirect/correlation.go`

**Step 1: Create correlation map**

```go
package redirect

import (
	"net"
	"sync"
	"time"
)

// HostnameEntry stores resolved IPs for a hostname
type HostnameEntry struct {
	Hostname  string
	IPs       []net.IP
	ExpiresAt time.Time
}

// CorrelationMap maps hostnames to IPs and vice versa for connect redirect matching
type CorrelationMap struct {
	mu          sync.RWMutex
	hostnameToIP map[string]*HostnameEntry
	ipToHostname map[string]string // IP string -> hostname
	ttl         time.Duration
}

// NewCorrelationMap creates a new correlation map with the given TTL
func NewCorrelationMap(ttl time.Duration) *CorrelationMap {
	return &CorrelationMap{
		hostnameToIP: make(map[string]*HostnameEntry),
		ipToHostname: make(map[string]string),
		ttl:          ttl,
	}
}

// AddResolution records a DNS resolution
func (m *CorrelationMap) AddResolution(hostname string, ips []net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := &HostnameEntry{
		Hostname:  hostname,
		IPs:       ips,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	m.hostnameToIP[hostname] = entry

	for _, ip := range ips {
		m.ipToHostname[ip.String()] = hostname
	}
}

// LookupHostname returns the hostname for an IP address
func (m *CorrelationMap) LookupHostname(ip net.IP) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostname, ok := m.ipToHostname[ip.String()]
	if !ok {
		return "", false
	}

	// Check if entry is still valid
	entry, exists := m.hostnameToIP[hostname]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return hostname, true
}

// Cleanup removes expired entries
func (m *CorrelationMap) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for hostname, entry := range m.hostnameToIP {
		if now.After(entry.ExpiresAt) {
			for _, ip := range entry.IPs {
				delete(m.ipToHostname, ip.String())
			}
			delete(m.hostnameToIP, hostname)
		}
	}
}
```

**Step 2: Run tests**

Run: `go build ./...`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add internal/netmonitor/redirect/correlation.go
git commit -m "feat(redirect): add hostname-to-IP correlation map"
```

---

### Task 8: Write Tests for Correlation Map

**Files:**
- Create: `internal/netmonitor/redirect/correlation_test.go`

**Step 1: Create test file**

```go
package redirect

import (
	"net"
	"testing"
	"time"
)

func TestCorrelationMap_AddAndLookup(t *testing.T) {
	m := NewCorrelationMap(time.Minute)

	ips := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	m.AddResolution("api.anthropic.com", ips)

	// Lookup by first IP
	hostname, ok := m.LookupHostname(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Error("expected to find hostname for 10.0.0.1")
	}
	if hostname != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %s", hostname)
	}

	// Lookup by second IP
	hostname, ok = m.LookupHostname(net.ParseIP("10.0.0.2"))
	if !ok {
		t.Error("expected to find hostname for 10.0.0.2")
	}
	if hostname != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %s", hostname)
	}

	// Lookup unknown IP
	_, ok = m.LookupHostname(net.ParseIP("192.168.1.1"))
	if ok {
		t.Error("expected not to find hostname for unknown IP")
	}
}

func TestCorrelationMap_Expiry(t *testing.T) {
	m := NewCorrelationMap(10 * time.Millisecond)

	ips := []net.IP{net.ParseIP("10.0.0.1")}
	m.AddResolution("api.anthropic.com", ips)

	// Should find immediately
	_, ok := m.LookupHostname(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Error("expected to find hostname immediately after adding")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should not find after expiry
	_, ok = m.LookupHostname(net.ParseIP("10.0.0.1"))
	if ok {
		t.Error("expected not to find hostname after expiry")
	}
}

func TestCorrelationMap_Cleanup(t *testing.T) {
	m := NewCorrelationMap(10 * time.Millisecond)

	ips := []net.IP{net.ParseIP("10.0.0.1")}
	m.AddResolution("api.anthropic.com", ips)

	time.Sleep(20 * time.Millisecond)
	m.Cleanup()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.hostnameToIP) != 0 {
		t.Errorf("expected hostnameToIP to be empty after cleanup, got %d entries", len(m.hostnameToIP))
	}
	if len(m.ipToHostname) != 0 {
		t.Errorf("expected ipToHostname to be empty after cleanup, got %d entries", len(m.ipToHostname))
	}
}
```

**Step 2: Run tests**

Run: `go test ./internal/netmonitor/redirect/... -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/netmonitor/redirect/correlation_test.go
git commit -m "test(redirect): add correlation map tests"
```

---

### Task 9: Integrate DNS Redirect with Existing DNS Interceptor

**Files:**
- Modify: `internal/netmonitor/dns.go`

**Step 1: Read existing DNS interceptor structure**

First, read the existing dns.go to understand the structure.

**Step 2: Add redirect evaluation to DNS interception**

This task requires reading the existing code and integrating the redirect evaluation. The specific changes depend on the current structure of dns.go.

Key integration points:
1. After parsing DNS query hostname
2. Call `engine.EvaluateDnsRedirect(hostname)`
3. If matched, modify response to return redirected IP
4. Emit DNSRedirectEvent if visibility is not "silent"
5. Update correlation map with the redirect

**Step 3: Run tests**

Run: `go test ./internal/netmonitor/... -v`
Expected: Tests pass

**Step 4: Commit**

```bash
git add internal/netmonitor/dns.go
git commit -m "feat(dns): integrate DNS redirect evaluation"
```

---

### Task 10: Integrate Connect Redirect with eBPF Collector

**Files:**
- Modify: `internal/netmonitor/ebpf/collector.go`

**Step 1: Read existing collector structure**

First, read the existing collector.go to understand how connect events are processed.

**Step 2: Add redirect evaluation to connect handling**

Key integration points:
1. When connect event is received from eBPF
2. Look up hostname from correlation map using destination IP
3. Call `engine.EvaluateConnectRedirect(hostname:port)`
4. If matched, modify the destination in the response/map
5. Emit ConnectRedirectEvent if visibility is not "silent"

**Step 3: Run tests**

Run: `go test ./internal/netmonitor/ebpf/... -v`
Expected: Tests pass

**Step 4: Commit**

```bash
git add internal/netmonitor/ebpf/collector.go
git commit -m "feat(ebpf): integrate connect redirect evaluation"
```

---

### Task 11: Add Integration Test

**Files:**
- Create: `internal/netmonitor/redirect/integration_test.go`

**Step 1: Create integration test**

```go
//go:build integration

package redirect

import (
	"testing"

	"github.com/your-org/agentsh/internal/policy"
)

func TestDNSRedirectIntegration(t *testing.T) {
	// Load test policy with DNS redirects
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:       "anthropic-to-vertex",
				Match:      ".*\\.anthropic\\.com",
				ResolveTo:  "10.0.0.50",
				Visibility: "audit_only",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Test DNS evaluation
	result := engine.EvaluateDnsRedirect("api.anthropic.com")
	if !result.Matched {
		t.Error("expected DNS redirect to match")
	}
	if result.ResolveTo != "10.0.0.50" {
		t.Errorf("expected resolve_to 10.0.0.50, got %s", result.ResolveTo)
	}
}

func TestConnectRedirectIntegration(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-to-vertex",
				Match:      "api\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy.internal:443",
				Message:    "Routed through Vertex AI",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	result := engine.EvaluateConnectRedirect("api.anthropic.com:443")
	if !result.Matched {
		t.Error("expected connect redirect to match")
	}
	if result.RedirectTo != "vertex-proxy.internal:443" {
		t.Errorf("expected redirect_to vertex-proxy.internal:443, got %s", result.RedirectTo)
	}
}
```

**Step 2: Run integration tests**

Run: `go test ./internal/netmonitor/redirect/... -tags=integration -v`
Expected: Tests pass

**Step 3: Commit**

```bash
git add internal/netmonitor/redirect/integration_test.go
git commit -m "test(redirect): add integration tests"
```

---

### Task 12: Update Documentation

**Files:**
- Modify: `docs/plans/2026-01-29-network-redirect-design.md` (mark as implemented)

**Step 1: Add implementation status**

Add to the top of the design doc:

```markdown
**Status:** Implemented (Tasks 1-11 complete)
**Branch:** feature/network-redirect
```

**Step 2: Commit**

```bash
git add docs/plans/2026-01-29-network-redirect-design.md
git commit -m "docs: mark network redirect design as implemented"
```

---

## Summary

**Tasks 1-6:** Policy model, validation, events, engine compilation and evaluation
**Tasks 7-8:** Hostname-to-IP correlation map for connect redirects
**Tasks 9-10:** Integration with existing DNS and eBPF infrastructure
**Tasks 11-12:** Integration tests and documentation

Each task is self-contained with clear file paths, code, and commit points.
