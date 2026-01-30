package redirect

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"gopkg.in/yaml.v3"
)

// TestEndToEndDNSToConnectFlow tests the full flow:
// 1. DNS resolution is intercepted and redirected
// 2. Correlation map is updated with hostname -> IP
// 3. Connect redirect can match by hostname using correlation map
func TestEndToEndDNSToConnectFlow(t *testing.T) {
	// Create policy with both DNS and connect redirects
	p := &policy.Policy{
		Version: 1,
		Name:    "e2e-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:       "anthropic-dns",
				Match:      `api\.anthropic\.com`,
				ResolveTo:  "10.0.0.50",
				Visibility: "audit_only",
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-connect",
				Match:      `api\.anthropic\.com:443`,
				RedirectTo: "vertex-proxy.internal:443",
				Message:    "Routed to Vertex AI",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Step 1: Simulate DNS interception
	hostname := "api.anthropic.com"
	dnsResult := engine.EvaluateDnsRedirect(hostname)
	if !dnsResult.Matched {
		t.Fatal("DNS redirect should match")
	}

	// Step 2: Simulate DNS response - correlation map records the mapping
	correlationMap := NewCorrelationMap(5 * time.Minute)
	redirectIP := net.ParseIP(dnsResult.ResolveTo)
	correlationMap.AddResolution(hostname, []net.IP{redirectIP})

	// Step 3: Later, when connect() happens, we only have the IP
	// Simulate looking up the hostname from the IP
	foundHostname, found := correlationMap.LookupHostname(redirectIP)
	if !found {
		t.Fatal("should find hostname from correlation map")
	}
	if foundHostname != hostname {
		t.Errorf("expected hostname %s, got %s", hostname, foundHostname)
	}

	// Step 4: Evaluate connect redirect using the correlated hostname
	hostPort := foundHostname + ":443"
	connectResult := engine.EvaluateConnectRedirect(hostPort)
	if !connectResult.Matched {
		t.Fatal("connect redirect should match")
	}
	if connectResult.RedirectTo != "vertex-proxy.internal:443" {
		t.Errorf("expected redirect to vertex-proxy.internal:443, got %s", connectResult.RedirectTo)
	}
	if connectResult.Message != "Routed to Vertex AI" {
		t.Errorf("expected message 'Routed to Vertex AI', got %s", connectResult.Message)
	}
}

// TestMultipleIPsCorrelation tests that all IPs from a DNS response can be correlated
func TestMultipleIPsCorrelation(t *testing.T) {
	correlationMap := NewCorrelationMap(5 * time.Minute)

	hostname := "api.anthropic.com"
	ips := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
		net.ParseIP("10.0.0.3"),
	}

	correlationMap.AddResolution(hostname, ips)

	// All IPs should resolve to the same hostname
	for _, ip := range ips {
		found, ok := correlationMap.LookupHostname(ip)
		if !ok {
			t.Errorf("should find hostname for IP %s", ip)
		}
		if found != hostname {
			t.Errorf("expected hostname %s for IP %s, got %s", hostname, ip, found)
		}
	}
}

// TestIPv6Correlation tests that IPv6 addresses work correctly
func TestIPv6Correlation(t *testing.T) {
	correlationMap := NewCorrelationMap(5 * time.Minute)

	hostname := "api.anthropic.com"
	ipv6 := net.ParseIP("2001:db8::1")

	correlationMap.AddResolution(hostname, []net.IP{ipv6})

	found, ok := correlationMap.LookupHostname(ipv6)
	if !ok {
		t.Error("should find hostname for IPv6 address")
	}
	if found != hostname {
		t.Errorf("expected hostname %s, got %s", hostname, found)
	}
}

// TestCorrelationMapOverwrite tests that new resolution overwrites old one
func TestCorrelationMapOverwrite(t *testing.T) {
	correlationMap := NewCorrelationMap(5 * time.Minute)

	hostname := "api.anthropic.com"
	oldIP := net.ParseIP("10.0.0.1")
	newIP := net.ParseIP("10.0.0.2")

	// First resolution
	correlationMap.AddResolution(hostname, []net.IP{oldIP})

	// Second resolution with new IP
	correlationMap.AddResolution(hostname, []net.IP{newIP})

	// New IP should work
	found, ok := correlationMap.LookupHostname(newIP)
	if !ok {
		t.Error("should find hostname for new IP")
	}
	if found != hostname {
		t.Errorf("expected hostname %s, got %s", hostname, found)
	}

	// Old IP should still work (we don't remove old mappings until cleanup)
	found, ok = correlationMap.LookupHostname(oldIP)
	if !ok {
		t.Error("old IP should still be in map until cleanup")
	}
}

// TestPolicyYAMLParsing tests that policy can be loaded from YAML
func TestPolicyYAMLParsing(t *testing.T) {
	yamlContent := `
version: 1
name: yaml-test
dns_redirects:
  - name: anthropic-dns
    match: ".*\\.anthropic\\.com"
    resolve_to: "10.0.0.50"
    visibility: audit_only
    on_failure: fail_closed
connect_redirects:
  - name: anthropic-connect
    match: "api\\.anthropic\\.com:443"
    redirect_to: "vertex-proxy.internal:443"
    tls:
      mode: passthrough
    visibility: warn
    message: "Routed through Vertex AI"
    on_failure: fail_open
`

	p := &policy.Policy{}
	err := yaml.Unmarshal([]byte(yamlContent), p)
	if err != nil {
		t.Fatalf("failed to parse policy YAML: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("failed to validate policy: %v", err)
	}

	if len(p.DnsRedirectRules) != 1 {
		t.Errorf("expected 1 DNS redirect rule, got %d", len(p.DnsRedirectRules))
	}
	if len(p.ConnectRedirectRules) != 1 {
		t.Errorf("expected 1 connect redirect rule, got %d", len(p.ConnectRedirectRules))
	}

	// Verify DNS rule
	dnsRule := p.DnsRedirectRules[0]
	if dnsRule.Name != "anthropic-dns" {
		t.Errorf("expected DNS rule name 'anthropic-dns', got %s", dnsRule.Name)
	}
	if dnsRule.ResolveTo != "10.0.0.50" {
		t.Errorf("expected resolve_to '10.0.0.50', got %s", dnsRule.ResolveTo)
	}
	if dnsRule.Visibility != "audit_only" {
		t.Errorf("expected visibility 'audit_only', got %s", dnsRule.Visibility)
	}
	if dnsRule.OnFailure != "fail_closed" {
		t.Errorf("expected on_failure 'fail_closed', got %s", dnsRule.OnFailure)
	}

	// Verify connect rule
	connectRule := p.ConnectRedirectRules[0]
	if connectRule.Name != "anthropic-connect" {
		t.Errorf("expected connect rule name 'anthropic-connect', got %s", connectRule.Name)
	}
	if connectRule.RedirectTo != "vertex-proxy.internal:443" {
		t.Errorf("expected redirect_to 'vertex-proxy.internal:443', got %s", connectRule.RedirectTo)
	}
	if connectRule.TLS == nil || connectRule.TLS.Mode != "passthrough" {
		t.Error("expected TLS mode 'passthrough'")
	}
	if connectRule.Visibility != "warn" {
		t.Errorf("expected visibility 'warn', got %s", connectRule.Visibility)
	}
	if connectRule.Message != "Routed through Vertex AI" {
		t.Errorf("expected message 'Routed through Vertex AI', got %s", connectRule.Message)
	}
	if connectRule.OnFailure != "fail_open" {
		t.Errorf("expected on_failure 'fail_open', got %s", connectRule.OnFailure)
	}

	// Create engine and test evaluation
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	dnsResult := engine.EvaluateDnsRedirect("api.anthropic.com")
	if !dnsResult.Matched {
		t.Error("DNS redirect should match")
	}

	connectResult := engine.EvaluateConnectRedirect("api.anthropic.com:443")
	if !connectResult.Matched {
		t.Error("connect redirect should match")
	}
}

// TestDefaultValues tests that default values are applied correctly
func TestDefaultValues(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "defaults-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:      "no-defaults",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				// No visibility or on_failure specified
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "no-defaults",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				// No TLS, visibility, or on_failure specified
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Check DNS defaults
	dnsResult := engine.EvaluateDnsRedirect("example.com")
	if dnsResult.Visibility != "audit_only" {
		t.Errorf("expected default visibility 'audit_only', got %s", dnsResult.Visibility)
	}
	if dnsResult.OnFailure != "fail_closed" {
		t.Errorf("expected default on_failure 'fail_closed', got %s", dnsResult.OnFailure)
	}

	// Check connect defaults
	connectResult := engine.EvaluateConnectRedirect("example.com:443")
	if connectResult.Visibility != "audit_only" {
		t.Errorf("expected default visibility 'audit_only', got %s", connectResult.Visibility)
	}
	if connectResult.OnFailure != "fail_closed" {
		t.Errorf("expected default on_failure 'fail_closed', got %s", connectResult.OnFailure)
	}
	if connectResult.TLSMode != "passthrough" {
		t.Errorf("expected default TLS mode 'passthrough', got %s", connectResult.TLSMode)
	}
}

// TestSNIRewriteConfiguration tests SNI rewrite configuration and evaluation
func TestSNIRewriteConfiguration(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "sni-test",
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-passthrough",
				Match:      `api\.anthropic\.com:443`,
				RedirectTo: "vertex-proxy.internal:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough"},
				Message:    "Vertex presents cert for api.anthropic.com",
			},
			{
				Name:       "openai-rewrite-sni",
				Match:      `api\.openai\.com:443`,
				RedirectTo: "azure-openai.internal:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "azure-openai.internal"},
				Message:    "Azure needs its own hostname in SNI",
			},
			{
				Name:       "custom-api-rewrite",
				Match:      `custom-llm\.example\.com:443`,
				RedirectTo: "10.0.0.100:8443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "internal-llm.corp.local"},
				Message:    "Internal LLM endpoint",
			},
		},
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("policy validation failed: %v", err)
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	tests := []struct {
		name           string
		hostPort       string
		wantMatch      bool
		wantRedirectTo string
		wantTLSMode    string
		wantSNI        string
		wantMessage    string
	}{
		{
			name:           "passthrough keeps original SNI",
			hostPort:       "api.anthropic.com:443",
			wantMatch:      true,
			wantRedirectTo: "vertex-proxy.internal:443",
			wantTLSMode:    "passthrough",
			wantSNI:        "", // empty means keep original
			wantMessage:    "Vertex presents cert for api.anthropic.com",
		},
		{
			name:           "rewrite SNI for Azure OpenAI",
			hostPort:       "api.openai.com:443",
			wantMatch:      true,
			wantRedirectTo: "azure-openai.internal:443",
			wantTLSMode:    "rewrite_sni",
			wantSNI:        "azure-openai.internal",
			wantMessage:    "Azure needs its own hostname in SNI",
		},
		{
			name:           "rewrite SNI for internal endpoint",
			hostPort:       "custom-llm.example.com:443",
			wantMatch:      true,
			wantRedirectTo: "10.0.0.100:8443",
			wantTLSMode:    "rewrite_sni",
			wantSNI:        "internal-llm.corp.local",
			wantMessage:    "Internal LLM endpoint",
		},
		{
			name:      "no match for unknown host",
			hostPort:  "other.example.com:443",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.EvaluateConnectRedirect(tt.hostPort)

			if result.Matched != tt.wantMatch {
				t.Errorf("matched = %v, want %v", result.Matched, tt.wantMatch)
				return
			}

			if !tt.wantMatch {
				return
			}

			if result.RedirectTo != tt.wantRedirectTo {
				t.Errorf("RedirectTo = %s, want %s", result.RedirectTo, tt.wantRedirectTo)
			}
			if result.TLSMode != tt.wantTLSMode {
				t.Errorf("TLSMode = %s, want %s", result.TLSMode, tt.wantTLSMode)
			}
			if result.SNI != tt.wantSNI {
				t.Errorf("SNI = %s, want %s", result.SNI, tt.wantSNI)
			}
			if result.Message != tt.wantMessage {
				t.Errorf("Message = %s, want %s", result.Message, tt.wantMessage)
			}
		})
	}
}

// TestSNIRewriteValidation tests that invalid SNI configurations are rejected
func TestSNIRewriteValidation(t *testing.T) {
	tests := []struct {
		name    string
		rule    policy.ConnectRedirectRule
		wantErr bool
		errMsg  string
	}{
		{
			name: "passthrough without SNI is valid",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough"},
			},
			wantErr: false,
		},
		{
			name: "passthrough with SNI is valid (SNI ignored)",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough", SNI: "ignored.example.com"},
			},
			wantErr: false,
		},
		{
			name: "rewrite_sni with SNI is valid",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "proxy.internal"},
			},
			wantErr: false,
		},
		{
			name: "rewrite_sni without SNI is invalid",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni"},
			},
			wantErr: true,
			errMsg:  "tls.sni required when mode is rewrite_sni",
		},
		{
			name: "invalid TLS mode is rejected",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "mitm"},
			},
			wantErr: true,
			errMsg:  "tls.mode must be passthrough or rewrite_sni",
		},
		{
			name: "no TLS config defaults to passthrough",
			rule: policy.ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				// No TLS config
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policy.Policy{
				Version:              1,
				Name:                 "test",
				ConnectRedirectRules: []policy.ConnectRedirectRule{tt.rule},
			}

			err := p.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected validation error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected validation error: %v", err)
				}
			}
		})
	}
}

// TestEndToEndWithSNIRewrite tests the full flow with SNI rewrite
func TestEndToEndWithSNIRewrite(t *testing.T) {
	// Simulate: Client wants to connect to api.openai.com:443
	// Policy: Redirect to azure-openai.internal:443 with SNI rewrite

	p := &policy.Policy{
		Version: 1,
		Name:    "e2e-sni-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:      "openai-dns",
				Match:     `api\.openai\.com`,
				ResolveTo: "10.0.0.100", // Azure endpoint IP
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "openai-connect",
				Match:      `api\.openai\.com:443`,
				RedirectTo: "azure-openai.internal:443",
				TLS: &policy.ConnectRedirectTLSConfig{
					Mode: "rewrite_sni",
					SNI:  "azure-openai.internal",
				},
				Visibility: "warn",
				Message:    "Redirected to Azure OpenAI",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Step 1: DNS resolution
	hostname := "api.openai.com"
	dnsResult := engine.EvaluateDnsRedirect(hostname)
	if !dnsResult.Matched {
		t.Fatal("DNS redirect should match")
	}
	t.Logf("DNS: %s -> %s", hostname, dnsResult.ResolveTo)

	// Step 2: Correlation map
	correlationMap := NewCorrelationMap(5 * time.Minute)
	correlationMap.AddResolution(hostname, []net.IP{net.ParseIP(dnsResult.ResolveTo)})

	// Step 3: Connect redirect evaluation
	hostPort := hostname + ":443"
	connectResult := engine.EvaluateConnectRedirect(hostPort)
	if !connectResult.Matched {
		t.Fatal("connect redirect should match")
	}

	// Verify the full redirect configuration
	t.Logf("Connect: %s -> %s", hostPort, connectResult.RedirectTo)
	t.Logf("TLS Mode: %s", connectResult.TLSMode)
	t.Logf("SNI: %s", connectResult.SNI)

	if connectResult.RedirectTo != "azure-openai.internal:443" {
		t.Errorf("expected redirect to azure-openai.internal:443, got %s", connectResult.RedirectTo)
	}
	if connectResult.TLSMode != "rewrite_sni" {
		t.Errorf("expected TLS mode rewrite_sni, got %s", connectResult.TLSMode)
	}
	if connectResult.SNI != "azure-openai.internal" {
		t.Errorf("expected SNI azure-openai.internal, got %s", connectResult.SNI)
	}
	if connectResult.Visibility != "warn" {
		t.Errorf("expected visibility warn, got %s", connectResult.Visibility)
	}

	// This test demonstrates what the eBPF layer would do:
	// 1. Intercept connect() to resolved IP (10.0.0.100:443)
	// 2. Look up hostname from correlation map: api.openai.com
	// 3. Evaluate redirect: azure-openai.internal:443 with SNI rewrite
	// 4. Modify sockaddr to point to azure-openai.internal
	// 5. When TLS ClientHello is sent, rewrite SNI from api.openai.com to azure-openai.internal
	// 6. Azure server sees correct SNI, presents valid cert, connection succeeds
}

// helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestComplexRegexPatterns tests various regex patterns
func TestComplexRegexPatterns(t *testing.T) {
	p := &policy.Policy{
		Version: 1,
		Name:    "regex-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:      "exact-match",
				Match:     `^api\.anthropic\.com$`,
				ResolveTo: "10.0.0.1",
			},
			{
				Name:      "subdomain-wildcard",
				Match:     `.*\.internal\.anthropic\.com`,
				ResolveTo: "10.0.0.2",
			},
			{
				Name:      "alternation",
				Match:     `(api|console)\.openai\.com`,
				ResolveTo: "10.0.0.3",
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "any-https",
				Match:      `.*:443`,
				RedirectTo: "https-proxy:443",
			},
			{
				Name:       "specific-port-range",
				Match:      `.*:(8080|8443)`,
				RedirectTo: "alt-proxy:8080",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		evalType  string
		input     string
		wantMatch bool
		wantRule  string
	}{
		// DNS tests
		{"exact match", "dns", "api.anthropic.com", true, "exact-match"},
		{"exact match fails on subdomain", "dns", "v2.api.anthropic.com", false, ""},
		{"subdomain wildcard", "dns", "test.internal.anthropic.com", true, "subdomain-wildcard"},
		{"alternation api", "dns", "api.openai.com", true, "alternation"},
		{"alternation console", "dns", "console.openai.com", true, "alternation"},
		{"alternation fails", "dns", "other.openai.com", false, ""},

		// Connect tests
		{"any https", "connect", "example.com:443", true, "any-https"},
		{"port 8080", "connect", "example.com:8080", true, "specific-port-range"},
		{"port 8443", "connect", "example.com:8443", true, "specific-port-range"},
		{"port 80 no match", "connect", "example.com:80", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matched bool
			var rule string

			if tt.evalType == "dns" {
				result := engine.EvaluateDnsRedirect(tt.input)
				matched = result.Matched
				rule = result.Rule
			} else {
				result := engine.EvaluateConnectRedirect(tt.input)
				matched = result.Matched
				rule = result.Rule
			}

			if matched != tt.wantMatch {
				t.Errorf("expected matched=%v, got %v", tt.wantMatch, matched)
			}
			if matched && rule != tt.wantRule {
				t.Errorf("expected rule %s, got %s", tt.wantRule, rule)
			}
		})
	}
}
