package policy

import (
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestPathRedirector_Redirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path redirect tests use Unix-style paths")
	}
	rules := []PathRedirectRule{
		{
			Name:          "redirect-home",
			SourcePattern: "/home/**",
			TargetBase:    "/workspace/.scratch",
			Operations:    []string{"write", "create"},
			PreserveTree:  true,
		},
		{
			Name:          "redirect-tmp",
			SourcePattern: "/tmp/**",
			TargetBase:    "/workspace/.tmp",
			Operations:    []string{"*"},
			PreserveTree:  false,
		},
	}

	pr, err := NewPathRedirector(rules)
	if err != nil {
		t.Fatalf("NewPathRedirector: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		operation    string
		wantPath     string
		wantRedirect bool
	}{
		{
			name:         "redirect home write with tree",
			path:         "/home/user/file.txt",
			operation:    "write",
			wantPath:     "/workspace/.scratch/home/user/file.txt",
			wantRedirect: true,
		},
		{
			name:         "redirect home create with tree",
			path:         "/home/user/subdir/file.txt",
			operation:    "create",
			wantPath:     "/workspace/.scratch/home/user/subdir/file.txt",
			wantRedirect: true,
		},
		{
			name:         "no redirect home read",
			path:         "/home/user/file.txt",
			operation:    "read",
			wantPath:     "/home/user/file.txt",
			wantRedirect: false,
		},
		{
			name:         "redirect tmp without tree",
			path:         "/tmp/foo/bar/file.txt",
			operation:    "write",
			wantPath:     "/workspace/.tmp/file.txt",
			wantRedirect: true,
		},
		{
			name:         "no redirect unmatched path",
			path:         "/var/log/syslog",
			operation:    "write",
			wantPath:     "/var/log/syslog",
			wantRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRedirect := pr.Redirect(tt.path, tt.operation)
			if gotPath != tt.wantPath {
				t.Errorf("Redirect() path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotRedirect != tt.wantRedirect {
				t.Errorf("Redirect() redirected = %v, want %v", gotRedirect, tt.wantRedirect)
			}
		})
	}
}

func TestPathRedirector_RedirectWithInfo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path redirect tests use Unix-style paths")
	}
	rules := []PathRedirectRule{
		{
			Name:          "redirect-home",
			SourcePattern: "/home/**",
			TargetBase:    "/workspace/.scratch",
			Operations:    []string{"write"},
			PreserveTree:  true,
		},
	}

	pr, err := NewPathRedirector(rules)
	if err != nil {
		t.Fatalf("NewPathRedirector: %v", err)
	}

	// Test redirect
	info := pr.RedirectWithInfo("/home/user/file.txt", "write")
	if info == nil {
		t.Fatal("expected redirect info, got nil")
	}
	if info.OriginalPath != "/home/user/file.txt" {
		t.Errorf("OriginalPath = %q, want %q", info.OriginalPath, "/home/user/file.txt")
	}
	if info.RedirectPath != "/workspace/.scratch/home/user/file.txt" {
		t.Errorf("RedirectPath = %q, want %q", info.RedirectPath, "/workspace/.scratch/home/user/file.txt")
	}
	if info.Operation != "write" {
		t.Errorf("Operation = %q, want %q", info.Operation, "write")
	}

	// Test no redirect
	info = pr.RedirectWithInfo("/home/user/file.txt", "read")
	if info != nil {
		t.Errorf("expected nil for read operation, got %+v", info)
	}
}

func TestPathRedirector_Nil(t *testing.T) {
	var pr *PathRedirector
	path, redirected := pr.Redirect("/home/user/file.txt", "write")
	if redirected {
		t.Error("nil PathRedirector should not redirect")
	}
	if path != "/home/user/file.txt" {
		t.Errorf("path = %q, want original", path)
	}
}

func TestCheckFile_WithRedirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path redirect tests use Unix-style paths")
	}
	policy := &Policy{
		Version: 1,
		Name:    "test",
		FileRules: []FileRule{
			{
				Name:         "redirect-home-writes",
				Paths:        []string{"/home/**"},
				Operations:   []string{"write", "create"},
				Decision:     "redirect",
				Message:      "Writes outside workspace redirected",
				RedirectTo:   "/workspace/.scratch",
				PreserveTree: true,
			},
			{
				Name:       "allow-workspace",
				Paths:      []string{"/workspace/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Test redirect
	dec := engine.CheckFile("/home/user/file.txt", "write")
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Errorf("PolicyDecision = %q, want redirect", dec.PolicyDecision)
	}
	if dec.FileRedirect == nil {
		t.Fatal("expected FileRedirect, got nil")
	}
	if dec.FileRedirect.RedirectPath != "/workspace/.scratch/home/user/file.txt" {
		t.Errorf("RedirectPath = %q, want /workspace/.scratch/home/user/file.txt", dec.FileRedirect.RedirectPath)
	}

	// Test allow (no redirect)
	dec = engine.CheckFile("/workspace/myproject/file.txt", "write")
	if dec.PolicyDecision != types.DecisionAllow {
		t.Errorf("PolicyDecision = %q, want allow", dec.PolicyDecision)
	}
	if dec.FileRedirect != nil {
		t.Errorf("expected nil FileRedirect for allow, got %+v", dec.FileRedirect)
	}
}

func TestCheckCommand_WithEnhancedRedirect(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "redirect-curl",
				Commands: []string{"curl", "wget"},
				Decision: "redirect",
				Message:  "Network requests routed through audited fetch",
				RedirectTo: &CommandRedirect{
					Command:     "agentsh-fetch",
					Args:        []string{"--audit"},
					ArgsAppend:  []string{"--log-session"},
					Environment: map[string]string{"AGENTSH_AUDIT": "1"},
				},
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dec := engine.CheckCommand("curl", []string{"https://example.com"})
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Errorf("PolicyDecision = %q, want redirect", dec.PolicyDecision)
	}
	if dec.Redirect == nil {
		t.Fatal("expected Redirect, got nil")
	}
	if dec.Redirect.Command != "agentsh-fetch" {
		t.Errorf("Redirect.Command = %q, want agentsh-fetch", dec.Redirect.Command)
	}
	if len(dec.Redirect.Args) != 1 || dec.Redirect.Args[0] != "--audit" {
		t.Errorf("Redirect.Args = %v, want [--audit]", dec.Redirect.Args)
	}
	if len(dec.Redirect.ArgsAppend) != 1 || dec.Redirect.ArgsAppend[0] != "--log-session" {
		t.Errorf("Redirect.ArgsAppend = %v, want [--log-session]", dec.Redirect.ArgsAppend)
	}
	if dec.Redirect.Environment["AGENTSH_AUDIT"] != "1" {
		t.Errorf("Redirect.Environment = %v, want AGENTSH_AUDIT=1", dec.Redirect.Environment)
	}
}

func TestDecision_AuditAndSoftDelete(t *testing.T) {
	policy := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "audit-git",
				Commands: []string{"git"},
				Decision: "audit",
				Message:  "Git commands are audited",
			},
		},
		FileRules: []FileRule{
			{
				Name:       "soft-delete",
				Paths:      []string{"/workspace/**"},
				Operations: []string{"delete"},
				Decision:   "soft_delete",
				Message:    "Deletions go to trash",
			},
		},
	}

	engine, err := NewEngine(policy, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Test audit decision
	dec := engine.CheckCommand("git", []string{"push"})
	if dec.PolicyDecision != types.DecisionAudit {
		t.Errorf("PolicyDecision = %q, want audit", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow (audit is allow + logging)", dec.EffectiveDecision)
	}

	// Test soft_delete decision
	dec = engine.CheckFile("/workspace/file.txt", "delete")
	if dec.PolicyDecision != types.DecisionSoftDelete {
		t.Errorf("PolicyDecision = %q, want soft_delete", dec.PolicyDecision)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision = %q, want allow (soft_delete proceeds with trash)", dec.EffectiveDecision)
	}
}

// --- DNS and Connect Redirect Tests ---

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
			name: "missing match",
			rule: DnsRedirectRule{
				Name:      "test",
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
			name: "missing resolve_to",
			rule: DnsRedirectRule{
				Name:  "test",
				Match: ".*",
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
			name: "valid visibility silent",
			rule: DnsRedirectRule{
				Name:       "test",
				Match:      ".*",
				ResolveTo:  "10.0.0.1",
				Visibility: "silent",
			},
			wantErr: false,
		},
		{
			name: "valid visibility audit_only",
			rule: DnsRedirectRule{
				Name:       "test",
				Match:      ".*",
				ResolveTo:  "10.0.0.1",
				Visibility: "audit_only",
			},
			wantErr: false,
		},
		{
			name: "valid visibility warn",
			rule: DnsRedirectRule{
				Name:       "test",
				Match:      ".*",
				ResolveTo:  "10.0.0.1",
				Visibility: "warn",
			},
			wantErr: false,
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
		{
			name: "valid on_failure fail_closed",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				OnFailure: "fail_closed",
			},
			wantErr: false,
		},
		{
			name: "valid on_failure fail_open",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				OnFailure: "fail_open",
			},
			wantErr: false,
		},
		{
			name: "valid on_failure retry_original",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				OnFailure: "retry_original",
			},
			wantErr: false,
		},
		{
			name: "invalid on_failure",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				OnFailure: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid IPv6 address",
			rule: DnsRedirectRule{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "::1",
			},
			wantErr: false,
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
			name: "missing name",
			rule: ConnectRedirectRule{
				Match:      ".*:443",
				RedirectTo: "proxy:443",
			},
			wantErr: true,
		},
		{
			name: "missing match",
			rule: ConnectRedirectRule{
				Name:       "test",
				RedirectTo: "proxy:443",
			},
			wantErr: true,
		},
		{
			name: "invalid regex",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      "[invalid",
				RedirectTo: "proxy:443",
			},
			wantErr: true,
		},
		{
			name: "missing redirect_to",
			rule: ConnectRedirectRule{
				Name:  "test",
				Match: ".*:443",
			},
			wantErr: true,
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
			name: "valid with TLS rewrite_sni and sni",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "proxy.internal"},
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
			name: "invalid TLS mode",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "valid visibility silent",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				Visibility: "silent",
			},
			wantErr: false,
		},
		{
			name: "valid visibility audit_only",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				Visibility: "audit_only",
			},
			wantErr: false,
		},
		{
			name: "valid visibility warn",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				Visibility: "warn",
			},
			wantErr: false,
		},
		{
			name: "invalid visibility",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				Visibility: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid on_failure fail_closed",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				OnFailure:  "fail_closed",
			},
			wantErr: false,
		},
		{
			name: "valid on_failure fail_open",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				OnFailure:  "fail_open",
			},
			wantErr: false,
		},
		{
			name: "valid on_failure retry_original",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				OnFailure:  "retry_original",
			},
			wantErr: false,
		},
		{
			name: "invalid on_failure",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				OnFailure:  "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid with message",
			rule: ConnectRedirectRule{
				Name:       "test",
				Match:      ".*:443",
				RedirectTo: "proxy:443",
				Message:    "Routed through proxy",
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
			{
				Name:      "exact-match",
				Match:     "^example\\.com$",
				ResolveTo: "192.168.1.1",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostname       string
		wantMatch      bool
		wantIP         string
		wantRule       string
		wantVisibility string
	}{
		{"api.anthropic.com", true, "10.0.0.50", "anthropic-redirect", "warn"},
		{"console.anthropic.com", true, "10.0.0.50", "anthropic-redirect", "warn"},
		{"sub.domain.anthropic.com", true, "10.0.0.50", "anthropic-redirect", "warn"},
		{"example.com", true, "192.168.1.1", "exact-match", "audit_only"}, // default visibility
		{"google.com", false, "", "", ""},
		{"anthropic.com.evil.com", false, "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			result := engine.EvaluateDnsRedirect(tt.hostname)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateDnsRedirect(%s) matched = %v, want %v", tt.hostname, result.Matched, tt.wantMatch)
			}
			if result.Matched {
				if result.ResolveTo != tt.wantIP {
					t.Errorf("EvaluateDnsRedirect(%s) resolveTo = %v, want %v", tt.hostname, result.ResolveTo, tt.wantIP)
				}
				if result.Rule != tt.wantRule {
					t.Errorf("EvaluateDnsRedirect(%s) rule = %v, want %v", tt.hostname, result.Rule, tt.wantRule)
				}
				if result.Visibility != tt.wantVisibility {
					t.Errorf("EvaluateDnsRedirect(%s) visibility = %v, want %v", tt.hostname, result.Visibility, tt.wantVisibility)
				}
			}
		})
	}
}

func TestEvaluateDnsRedirect_Defaults(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		DnsRedirectRules: []DnsRedirectRule{
			{
				Name:      "test",
				Match:     ".*",
				ResolveTo: "10.0.0.1",
				// No Visibility or OnFailure set
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	result := engine.EvaluateDnsRedirect("anything.com")
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Visibility != "audit_only" {
		t.Errorf("Visibility = %q, want audit_only (default)", result.Visibility)
	}
	if result.OnFailure != "fail_closed" {
		t.Errorf("OnFailure = %q, want fail_closed (default)", result.OnFailure)
	}
}

func TestEvaluateDnsRedirect_NoRules(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	result := engine.EvaluateDnsRedirect("example.com")
	if result.Matched {
		t.Error("expected no match when no rules defined")
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
			{
				Name:       "all-https",
				Match:      ".*:443",
				RedirectTo: "https-proxy.internal:8443",
				TLS:        &ConnectRedirectTLSConfig{Mode: "rewrite_sni", SNI: "proxy.internal"},
				Visibility: "silent",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostPort       string
		wantMatch      bool
		wantTarget     string
		wantRule       string
		wantTLSMode    string
		wantSNI        string
		wantVisibility string
		wantMessage    string
	}{
		{"api.anthropic.com:443", true, "vertex-proxy.internal:443", "anthropic-redirect", "passthrough", "", "audit_only", "Routed through Vertex"},
		{"google.com:443", true, "https-proxy.internal:8443", "all-https", "rewrite_sni", "proxy.internal", "silent", ""},
		{"other.example.com:443", true, "https-proxy.internal:8443", "all-https", "rewrite_sni", "proxy.internal", "silent", ""},
		{"api.anthropic.com:80", false, "", "", "", "", "", ""},
		{"google.com:80", false, "", "", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostPort, func(t *testing.T) {
			result := engine.EvaluateConnectRedirect(tt.hostPort)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateConnectRedirect(%s) matched = %v, want %v", tt.hostPort, result.Matched, tt.wantMatch)
			}
			if result.Matched {
				if result.RedirectTo != tt.wantTarget {
					t.Errorf("EvaluateConnectRedirect(%s) redirectTo = %v, want %v", tt.hostPort, result.RedirectTo, tt.wantTarget)
				}
				if result.Rule != tt.wantRule {
					t.Errorf("EvaluateConnectRedirect(%s) rule = %v, want %v", tt.hostPort, result.Rule, tt.wantRule)
				}
				if result.TLSMode != tt.wantTLSMode {
					t.Errorf("EvaluateConnectRedirect(%s) tlsMode = %v, want %v", tt.hostPort, result.TLSMode, tt.wantTLSMode)
				}
				if result.SNI != tt.wantSNI {
					t.Errorf("EvaluateConnectRedirect(%s) sni = %v, want %v", tt.hostPort, result.SNI, tt.wantSNI)
				}
				if result.Visibility != tt.wantVisibility {
					t.Errorf("EvaluateConnectRedirect(%s) visibility = %v, want %v", tt.hostPort, result.Visibility, tt.wantVisibility)
				}
				if result.Message != tt.wantMessage {
					t.Errorf("EvaluateConnectRedirect(%s) message = %v, want %v", tt.hostPort, result.Message, tt.wantMessage)
				}
			}
		})
	}
}

func TestEvaluateConnectRedirect_Defaults(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []ConnectRedirectRule{
			{
				Name:       "test",
				Match:      ".*",
				RedirectTo: "proxy:443",
				// No TLS, Visibility, or OnFailure set
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	result := engine.EvaluateConnectRedirect("anything:443")
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.TLSMode != "passthrough" {
		t.Errorf("TLSMode = %q, want passthrough (default)", result.TLSMode)
	}
	if result.Visibility != "audit_only" {
		t.Errorf("Visibility = %q, want audit_only (default)", result.Visibility)
	}
	if result.OnFailure != "fail_closed" {
		t.Errorf("OnFailure = %q, want fail_closed (default)", result.OnFailure)
	}
}

func TestEvaluateConnectRedirect_NoRules(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	result := engine.EvaluateConnectRedirect("example.com:443")
	if result.Matched {
		t.Error("expected no match when no rules defined")
	}
}

func TestEvaluateConnectRedirect_RuleOrder(t *testing.T) {
	// Test that rules are evaluated in order (first match wins)
	p := &Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []ConnectRedirectRule{
			{
				Name:       "specific",
				Match:      "api\\.example\\.com:443",
				RedirectTo: "specific-proxy:443",
			},
			{
				Name:       "wildcard",
				Match:      ".*:443",
				RedirectTo: "general-proxy:443",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Specific rule should match first
	result := engine.EvaluateConnectRedirect("api.example.com:443")
	if result.Rule != "specific" {
		t.Errorf("expected specific rule to match first, got %q", result.Rule)
	}
	if result.RedirectTo != "specific-proxy:443" {
		t.Errorf("redirectTo = %q, want specific-proxy:443", result.RedirectTo)
	}

	// Other hostnames should hit the wildcard rule
	result = engine.EvaluateConnectRedirect("other.example.com:443")
	if result.Rule != "wildcard" {
		t.Errorf("expected wildcard rule to match, got %q", result.Rule)
	}
}

func TestDnsRedirect_ComplexPatterns(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		DnsRedirectRules: []DnsRedirectRule{
			{
				Name:      "prefix-match",
				Match:     "^api-.*\\.example\\.com$",
				ResolveTo: "10.0.0.1",
			},
			{
				Name:      "suffix-match",
				Match:     ".*\\.internal$",
				ResolveTo: "10.0.0.2",
			},
			{
				Name:      "alternation",
				Match:     "^(dev|staging)\\.myapp\\.com$",
				ResolveTo: "10.0.0.3",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostname  string
		wantMatch bool
		wantIP    string
	}{
		{"api-v1.example.com", true, "10.0.0.1"},
		{"api-v2.example.com", true, "10.0.0.1"},
		{"api.example.com", false, ""},
		{"service.internal", true, "10.0.0.2"},
		{"deep.nested.internal", true, "10.0.0.2"},
		{"dev.myapp.com", true, "10.0.0.3"},
		{"staging.myapp.com", true, "10.0.0.3"},
		{"prod.myapp.com", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			result := engine.EvaluateDnsRedirect(tt.hostname)
			if result.Matched != tt.wantMatch {
				t.Errorf("matched = %v, want %v", result.Matched, tt.wantMatch)
			}
			if result.Matched && result.ResolveTo != tt.wantIP {
				t.Errorf("resolveTo = %v, want %v", result.ResolveTo, tt.wantIP)
			}
		})
	}
}

func TestEvaluateDnsRedirect_CaseNormalization(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		DnsRedirectRules: []DnsRedirectRule{
			{
				Name:      "example",
				Match:     `^example\.com$`,
				ResolveTo: "127.0.0.1",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostname  string
		wantMatch bool
	}{
		{"example.com", true},
		{"Example.COM", true},
		{"EXAMPLE.COM", true},
		{"Example.Com", true},
		{"example.com.", true},   // trailing dot (FQDN)
		{"Example.COM.", true},   // mixed case + trailing dot
		{"  example.com  ", true}, // whitespace
		{"other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			result := engine.EvaluateDnsRedirect(tt.hostname)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateDnsRedirect(%q) matched = %v, want %v", tt.hostname, result.Matched, tt.wantMatch)
			}
		})
	}
}

func TestEvaluateConnectRedirect_CaseNormalization(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []ConnectRedirectRule{
			{
				Name:       "example",
				Match:      `^example\.com:443$`,
				RedirectTo: "proxy.internal:443",
			},
		},
	}

	engine, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		hostPort  string
		wantMatch bool
	}{
		{"example.com:443", true},
		{"Example.COM:443", true},
		{"EXAMPLE.COM:443", true},
		{"Example.Com:443", true},
		{"example.com.:443", true},   // trailing dot
		{"Example.COM.:443", true},   // mixed case + trailing dot
		{"  example.com:443  ", true}, // whitespace
		{"other.com:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostPort, func(t *testing.T) {
			result := engine.EvaluateConnectRedirect(tt.hostPort)
			if result.Matched != tt.wantMatch {
				t.Errorf("EvaluateConnectRedirect(%q) matched = %v, want %v", tt.hostPort, result.Matched, tt.wantMatch)
			}
		})
	}
}
