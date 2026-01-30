//go:build integration

package redirect

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
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

func TestCombinedRedirectIntegration(t *testing.T) {
	// Test a policy with both DNS and connect redirects
	p := &policy.Policy{
		Version: 1,
		Name:    "combined-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:       "anthropic-dns",
				Match:      ".*\\.anthropic\\.com",
				ResolveTo:  "10.0.0.50",
				Visibility: "audit_only",
				OnFailure:  "fail_closed",
			},
			{
				Name:       "openai-dns",
				Match:      ".*\\.openai\\.com",
				ResolveTo:  "10.0.0.51",
				Visibility: "warn",
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "anthropic-connect",
				Match:      ".*\\.anthropic\\.com:443",
				RedirectTo: "vertex-proxy.internal:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough"},
				Visibility: "audit_only",
				Message:    "Routed through Vertex AI",
			},
			{
				Name:       "openai-connect",
				Match:      ".*\\.openai\\.com:443",
				RedirectTo: "azure-proxy.internal:443",
				TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "azure-proxy.internal"},
				Visibility: "warn",
				Message:    "Routed through Azure OpenAI",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	t.Run("DNS redirect anthropic", func(t *testing.T) {
		result := engine.EvaluateDnsRedirect("api.anthropic.com")
		if !result.Matched {
			t.Error("expected DNS redirect to match")
		}
		if result.ResolveTo != "10.0.0.50" {
			t.Errorf("expected resolve_to 10.0.0.50, got %s", result.ResolveTo)
		}
		if result.Rule != "anthropic-dns" {
			t.Errorf("expected rule anthropic-dns, got %s", result.Rule)
		}
		if result.Visibility != "audit_only" {
			t.Errorf("expected visibility audit_only, got %s", result.Visibility)
		}
		if result.OnFailure != "fail_closed" {
			t.Errorf("expected on_failure fail_closed, got %s", result.OnFailure)
		}
	})

	t.Run("DNS redirect openai", func(t *testing.T) {
		result := engine.EvaluateDnsRedirect("api.openai.com")
		if !result.Matched {
			t.Error("expected DNS redirect to match")
		}
		if result.ResolveTo != "10.0.0.51" {
			t.Errorf("expected resolve_to 10.0.0.51, got %s", result.ResolveTo)
		}
		if result.Rule != "openai-dns" {
			t.Errorf("expected rule openai-dns, got %s", result.Rule)
		}
		if result.Visibility != "warn" {
			t.Errorf("expected visibility warn, got %s", result.Visibility)
		}
	})

	t.Run("DNS redirect no match", func(t *testing.T) {
		result := engine.EvaluateDnsRedirect("api.example.com")
		if result.Matched {
			t.Error("expected DNS redirect not to match")
		}
	})

	t.Run("Connect redirect anthropic", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("api.anthropic.com:443")
		if !result.Matched {
			t.Error("expected connect redirect to match")
		}
		if result.RedirectTo != "vertex-proxy.internal:443" {
			t.Errorf("expected redirect_to vertex-proxy.internal:443, got %s", result.RedirectTo)
		}
		if result.Rule != "anthropic-connect" {
			t.Errorf("expected rule anthropic-connect, got %s", result.Rule)
		}
		if result.TLSMode != "passthrough" {
			t.Errorf("expected TLS mode passthrough, got %s", result.TLSMode)
		}
		if result.Message != "Routed through Vertex AI" {
			t.Errorf("expected message 'Routed through Vertex AI', got %s", result.Message)
		}
	})

	t.Run("Connect redirect openai", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("api.openai.com:443")
		if !result.Matched {
			t.Error("expected connect redirect to match")
		}
		if result.RedirectTo != "azure-proxy.internal:443" {
			t.Errorf("expected redirect_to azure-proxy.internal:443, got %s", result.RedirectTo)
		}
		if result.Rule != "openai-connect" {
			t.Errorf("expected rule openai-connect, got %s", result.Rule)
		}
		if result.TLSMode != "rewrite_sni" {
			t.Errorf("expected TLS mode rewrite_sni, got %s", result.TLSMode)
		}
		if result.SNI != "azure-proxy.internal" {
			t.Errorf("expected SNI azure-proxy.internal, got %s", result.SNI)
		}
		if result.Visibility != "warn" {
			t.Errorf("expected visibility warn, got %s", result.Visibility)
		}
	})

	t.Run("Connect redirect no match (wrong port)", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("api.anthropic.com:80")
		if result.Matched {
			t.Error("expected connect redirect not to match for port 80")
		}
	})

	t.Run("Connect redirect no match (unknown host)", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("api.example.com:443")
		if result.Matched {
			t.Error("expected connect redirect not to match for unknown host")
		}
	})
}

func TestPolicyValidationIntegration(t *testing.T) {
	t.Run("Valid policy", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "valid-test",
			DnsRedirectRules: []policy.DnsRedirectRule{
				{
					Name:       "test-dns",
					Match:      ".*\\.example\\.com",
					ResolveTo:  "10.0.0.1",
					Visibility: "silent",
					OnFailure:  "fail_open",
				},
			},
			ConnectRedirectRules: []policy.ConnectRedirectRule{
				{
					Name:       "test-connect",
					Match:      ".*:443",
					RedirectTo: "proxy:443",
					TLS:        &policy.ConnectRedirectTLSConfig{Mode: "passthrough"},
					Visibility: "audit_only",
					OnFailure:  "retry_original",
				},
			},
		}

		if err := p.Validate(); err != nil {
			t.Errorf("expected valid policy, got error: %v", err)
		}
	})

	t.Run("Invalid DNS redirect - bad regex", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "invalid-test",
			DnsRedirectRules: []policy.DnsRedirectRule{
				{
					Name:      "bad-regex",
					Match:     "[invalid",
					ResolveTo: "10.0.0.1",
				},
			},
		}

		if err := p.Validate(); err == nil {
			t.Error("expected validation error for invalid regex")
		}
	})

	t.Run("Invalid DNS redirect - bad IP", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "invalid-test",
			DnsRedirectRules: []policy.DnsRedirectRule{
				{
					Name:      "bad-ip",
					Match:     ".*",
					ResolveTo: "not-an-ip",
				},
			},
		}

		if err := p.Validate(); err == nil {
			t.Error("expected validation error for invalid IP")
		}
	})

	t.Run("Invalid connect redirect - rewrite_sni without SNI", func(t *testing.T) {
		p := &policy.Policy{
			Version: 1,
			Name:    "invalid-test",
			ConnectRedirectRules: []policy.ConnectRedirectRule{
				{
					Name:       "bad-tls",
					Match:      ".*:443",
					RedirectTo: "proxy:443",
					TLS:        &policy.ConnectRedirectTLSConfig{Mode: "rewrite_sni"},
				},
			},
		}

		if err := p.Validate(); err == nil {
			t.Error("expected validation error for rewrite_sni without SNI")
		}
	})
}

func TestRuleOrderingIntegration(t *testing.T) {
	// Verify that more specific rules are evaluated before general ones
	// when placed first in the list
	p := &policy.Policy{
		Version: 1,
		Name:    "ordering-test",
		DnsRedirectRules: []policy.DnsRedirectRule{
			{
				Name:      "specific",
				Match:     "^api\\.anthropic\\.com$",
				ResolveTo: "10.0.0.1",
			},
			{
				Name:      "general",
				Match:     ".*\\.anthropic\\.com",
				ResolveTo: "10.0.0.2",
			},
		},
		ConnectRedirectRules: []policy.ConnectRedirectRule{
			{
				Name:       "specific",
				Match:      "^api\\.anthropic\\.com:443$",
				RedirectTo: "specific-proxy:443",
			},
			{
				Name:       "general",
				Match:      ".*\\.anthropic\\.com:443",
				RedirectTo: "general-proxy:443",
			},
		},
	}

	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	t.Run("DNS specific rule matches first", func(t *testing.T) {
		result := engine.EvaluateDnsRedirect("api.anthropic.com")
		if result.Rule != "specific" {
			t.Errorf("expected specific rule to match first, got %s", result.Rule)
		}
		if result.ResolveTo != "10.0.0.1" {
			t.Errorf("expected resolve_to 10.0.0.1, got %s", result.ResolveTo)
		}
	})

	t.Run("DNS general rule matches other subdomains", func(t *testing.T) {
		result := engine.EvaluateDnsRedirect("console.anthropic.com")
		if result.Rule != "general" {
			t.Errorf("expected general rule to match, got %s", result.Rule)
		}
		if result.ResolveTo != "10.0.0.2" {
			t.Errorf("expected resolve_to 10.0.0.2, got %s", result.ResolveTo)
		}
	})

	t.Run("Connect specific rule matches first", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("api.anthropic.com:443")
		if result.Rule != "specific" {
			t.Errorf("expected specific rule to match first, got %s", result.Rule)
		}
		if result.RedirectTo != "specific-proxy:443" {
			t.Errorf("expected redirect_to specific-proxy:443, got %s", result.RedirectTo)
		}
	})

	t.Run("Connect general rule matches other subdomains", func(t *testing.T) {
		result := engine.EvaluateConnectRedirect("console.anthropic.com:443")
		if result.Rule != "general" {
			t.Errorf("expected general rule to match, got %s", result.Rule)
		}
		if result.RedirectTo != "general-proxy:443" {
			t.Errorf("expected redirect_to general-proxy:443, got %s", result.RedirectTo)
		}
	})
}
