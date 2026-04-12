package policy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHTTPServiceYAMLUnmarshal(t *testing.T) {
	src := []byte(`
http_services:
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    default: deny
    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
        decision: allow
`)

	var p Policy
	if err := yaml.Unmarshal(src, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.HTTPServices) != 1 {
		t.Fatalf("expected 1 http_service, got %d", len(p.HTTPServices))
	}
	svc := p.HTTPServices[0]
	if svc.Name != "github" {
		t.Errorf("Name = %q, want github", svc.Name)
	}
	if svc.Upstream != "https://api.github.com" {
		t.Errorf("Upstream = %q, want https://api.github.com", svc.Upstream)
	}
	if svc.ExposeAs != "GITHUB_API_URL" {
		t.Errorf("ExposeAs = %q, want GITHUB_API_URL", svc.ExposeAs)
	}
	if svc.Default != "deny" {
		t.Errorf("Default = %q, want deny", svc.Default)
	}
	if len(svc.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(svc.Rules))
	}
	r := svc.Rules[0]
	if r.Name != "read-issues" || r.Decision != "allow" {
		t.Errorf("rule = %+v, want name=read-issues decision=allow", r)
	}
	if len(r.Methods) != 1 || r.Methods[0] != "GET" {
		t.Errorf("Methods = %v, want [GET]", r.Methods)
	}
	if len(r.Paths) != 1 || r.Paths[0] != "/repos/*/*/issues" {
		t.Errorf("Paths = %v, want [/repos/*/*/issues]", r.Paths)
	}
}

// TestHTTPServicesValidatedDuringLoad verifies that the policy loader rejects
// a policy file whose http_services entries fail validation (e.g. missing name).
func TestHTTPServicesValidatedDuringLoad(t *testing.T) {
	src := []byte(`
version: 1
name: test-policy
http_services:
  - name: ""
    upstream: https://api.github.com
`)
	_, err := LoadFromBytes(src)
	if err == nil {
		t.Fatal("expected http_services validation error, got nil")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("error = %v, want mention of \"name is required\"", err)
	}
}

func TestValidateHTTPServices(t *testing.T) {
	validRule := HTTPServiceRule{
		Name:     "read-repos",
		Methods:  []string{"GET"},
		Paths:    []string{"/repos/**"},
		Decision: "allow",
	}

	tests := []struct {
		name    string
		svcs    []HTTPService
		wantErr string // substring match; empty means no error
	}{
		{
			name: "valid single service",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Default:  "deny",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "empty name rejected",
			svcs: []HTTPService{
				{
					Name:     "",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "name is required",
		},
		{
			name: "whitespace-only name rejected",
			svcs: []HTTPService{
				{
					Name:     "   ",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "name is required",
		},
		{
			name: "name with slash rejected",
			svcs: []HTTPService{
				{
					Name:     "foo/bar",
					Upstream: "https://api.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "URL-safe segment",
		},
		{
			name: "name with question mark rejected",
			svcs: []HTTPService{
				{
					Name:     "foo?bar",
					Upstream: "https://api.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "URL-safe segment",
		},
		{
			name: "name with hash rejected",
			svcs: []HTTPService{
				{
					Name:     "foo#bar",
					Upstream: "https://api.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "URL-safe segment",
		},
		{
			name: "name with space rejected",
			svcs: []HTTPService{
				{
					Name:     "foo bar",
					Upstream: "https://api.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "URL-safe segment",
		},
		{
			name: "name with valid chars accepted",
			svcs: []HTTPService{
				{
					Name:     "foo.bar-baz_123",
					Upstream: "https://api.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "duplicate name rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github",
					Upstream: "https://api2.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate http_service name",
		},
		{
			name: "duplicate name rejected case-insensitive",
			svcs: []HTTPService{
				{
					Name:     "GitHub",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github",
					Upstream: "https://api2.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate http_service name",
		},
		{
			name: "non-https upstream rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "http://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "upstream must be https",
		},
		{
			name: "unparseable upstream rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "://bad-url",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid upstream URL",
		},
		{
			name: "upstream with no host rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid upstream URL",
		},
		{
			name: "duplicate upstream host rejected across services",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias collides with another service upstream host",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api2.github.com",
					Aliases:  []string{"api.github.com"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias with trailing dot collides with upstream",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api2.github.com",
					Aliases:  []string{"api.github.com."},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias with port collides with upstream",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api2.github.com",
					Aliases:  []string{"api.github.com:443"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias with mixed case collides with upstream",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api2.github.com",
					Aliases:  []string{"API.GitHub.COM"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "upstream with trailing dot collides with plain upstream",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "github2",
					Upstream: "https://api.github.com./",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias that becomes empty after port strip rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{":443"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "invalid default value",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Default:  "redirect",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid default",
		},
		{
			name: "invalid rule decision",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "bad-rule",
							Paths:    []string{"/repos/**"},
							Decision: "redirect",
						},
					},
				},
			},
			wantErr: "invalid rule decision",
		},
		{
			name: "invalid path glob",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "bad-glob",
							Paths:    []string{"[unterminated"},
							Decision: "allow",
						},
					},
				},
			},
			wantErr: "invalid path glob",
		},
		{
			name: "empty paths list",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "no-paths",
							Paths:    []string{},
							Decision: "allow",
						},
					},
				},
			},
			wantErr: "rule must have at least one path",
		},
		{
			name: "blank path entry rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "blank-path",
							Paths:    []string{""},
							Decision: "allow",
						},
					},
				},
			},
			wantErr: "empty path",
		},
		{
			name: "whitespace-only path entry rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "whitespace-path",
							Paths:    []string{"   "},
							Decision: "allow",
						},
					},
				},
			},
			wantErr: "empty path",
		},
		{
			name: "mixed valid and blank path entries rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "mixed-paths",
							Paths:    []string{"/api/*", ""},
							Decision: "allow",
						},
					},
				},
			},
			wantErr: "empty path",
		},
		{
			name: "invalid expose_as",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					ExposeAs: "1_INVALID",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid expose_as",
		},
		{
			name: "derived env var name invalid due to hyphen in service name",
			svcs: []HTTPService{
				{
					Name:     "my-svc",
					Upstream: "https://api.example.com",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "derived env var name",
		},
		{
			name: "valid service with explicit expose_as overrides bad derived name",
			svcs: []HTTPService{
				{
					Name:     "my-svc",
					Upstream: "https://api.example.com",
					ExposeAs: "MY_SVC_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "valid service with allow default and audit rule",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Default:  "allow",
					Rules: []HTTPServiceRule{
						{
							Name:     "audit-writes",
							Methods:  []string{"POST", "PUT", "DELETE"},
							Paths:    []string{"/repos/**"},
							Decision: "audit",
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid service with approve rule",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules: []HTTPServiceRule{
						{
							Name:     "approve-deletes",
							Methods:  []string{"DELETE"},
							Paths:    []string{"/repos/**"},
							Decision: "approve",
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "IPv6 upstream collides with bracketed alias on another service",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[::1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "IPv6 upstream with port collides with bracketed alias with port on another service",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]:8443",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[::1]:443"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "IPv6 upstream collides with mixed-case bracketed alias on another service",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[fe80::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[FE80::1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "bare IPv6 alias rejected",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"::1"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "IPv6 literals must be bracketed",
		},
		{
			name: "bare IPv6 alias with different address rejected",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"fe80::1"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "IPv6 literals must be bracketed",
		},
		{
			name: "bracketed IPv6 alias accepted when no upstream conflict",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://api.github.com",
					ExposeAs: "SVC1_API_URL",
					Aliases:  []string{"[::1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "distinct IPv6 upstreams both accepted",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://[::2]",
					ExposeAs: "SVC2_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "unterminated bracket alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[::1"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "IPv6 literals must be bracketed",
		},
		{
			name: "empty brackets alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "IPv6 literals must be bracketed",
		},
		{
			name: "bracketed dot alias canonicalizes to empty and is rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[.]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed double-dot alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[..]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed hostname alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[example.com]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed IPv4 alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[192.168.1.1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed IPv4-in-IPv6 alias accepted",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[::ffff:192.168.1.1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "duplicate bracketed IPv4-in-IPv6 alias across services rejected",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://api1.example.com",
					ExposeAs: "SVC1_API_URL",
					Aliases:  []string{"[::ffff:192.168.1.1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[::ffff:192.168.1.1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "bracketed invalid hex IPv6 alias rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[gggg::1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed IPv6 with trailing space inside brackets rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Aliases:  []string{"[::1 ]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "invalid alias",
		},
		{
			name: "bracketed IPv6 leading-zero alias treated as distinct textual form",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[::0001]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "bracketed IPv6 expanded form alias treated as distinct textual form",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "SVC2_API_URL",
					Aliases:  []string{"[0:0:0:0:0:0:0:1]"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "bracketed IPv6 with various spellings all accepted when distinct",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://[fe80::1]",
					ExposeAs: "SVC1_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://[::2]",
					ExposeAs: "SVC2_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "duplicate ExposeAs rejected",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://api1.example.com",
					ExposeAs: "MY_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "MY_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate env var name",
		},
		{
			name: "duplicate derived name rejected",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "other",
					Upstream: "https://api.other.example.com",
					ExposeAs: "GITHUB_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate env var name",
		},
		{
			name: "reserved ANTHROPIC_BASE_URL rejected",
			svcs: []HTTPService{
				{
					Name:     "svc",
					Upstream: "https://api.example.com",
					ExposeAs: "ANTHROPIC_BASE_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "reserved env var name",
		},
		{
			name: "reserved OPENAI_BASE_URL rejected",
			svcs: []HTTPService{
				{
					Name:     "svc",
					Upstream: "https://api.example.com",
					ExposeAs: "OPENAI_BASE_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "reserved env var name",
		},
		{
			name: "reserved AGENTSH_SESSION_ID rejected",
			svcs: []HTTPService{
				{
					Name:     "svc",
					Upstream: "https://api.example.com",
					ExposeAs: "AGENTSH_SESSION_ID",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "reserved env var name",
		},
		{
			name: "reserved ANTHROPIC_BASE_URL case-insensitive",
			svcs: []HTTPService{
				{
					Name:     "svc",
					Upstream: "https://api.example.com",
					ExposeAs: "anthropic_base_url",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "reserved env var name",
		},
		{
			name: "reserved OPENAI_BASE_URL mixed case",
			svcs: []HTTPService{
				{
					Name:     "svc",
					Upstream: "https://api.example.com",
					ExposeAs: "Openai_Base_Url",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "reserved env var name",
		},
		{
			name: "duplicate ExposeAs case-insensitive",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://api1.example.com",
					ExposeAs: "MY_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "my_api_url",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate env var name",
		},
		{
			name: "duplicate ExposeAs mixed case",
			svcs: []HTTPService{
				{
					Name:     "svc1",
					Upstream: "https://api1.example.com",
					ExposeAs: "Foo_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "svc2",
					Upstream: "https://api2.example.com",
					ExposeAs: "FOO_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate env var name",
		},
		{
			name: "non-colliding multiple services accepted",
			svcs: []HTTPService{
				{
					Name:     "github",
					Upstream: "https://api.github.com",
					Rules:    []HTTPServiceRule{validRule},
				},
				{
					Name:     "other",
					Upstream: "https://api.other.example.com",
					ExposeAs: "OTHER_API_URL",
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "",
		},
		{
			name: "empty http_services list is valid",
			svcs: []HTTPService{},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHTTPServices(tc.svcs)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestCompileHTTPServices_Smoke(t *testing.T) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{{
			Name: "read", Methods: []string{"GET"},
			Paths: []string{"/repos/*/*/issues"}, Decision: "allow",
		}},
	}}
	if err := ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	byName, byHost, err := compileHTTPServices(svcs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cs, ok := byName["github"]
	if !ok {
		t.Fatal("github not in byName map")
	}
	if cs.envVar != "GITHUB_API_URL" {
		t.Errorf("envVar = %q, want GITHUB_API_URL", cs.envVar)
	}
	if cs.upstreamHost != "api.github.com" {
		t.Errorf("upstreamHost = %q", cs.upstreamHost)
	}
	if cs.defaultDecision != "deny" {
		t.Errorf("defaultDecision = %q", cs.defaultDecision)
	}
	if len(cs.rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(cs.rules))
	}
	if _, ok := cs.rules[0].methods["GET"]; !ok {
		t.Errorf("method GET not compiled")
	}
	if len(cs.rules[0].paths) != 1 {
		t.Errorf("paths not compiled")
	}
	if _, ok := byHost["api.github.com"]; !ok {
		t.Error("api.github.com not in byHost map")
	}
}

func TestCompileHTTPServices_AliasesIndexedByCanonicalHost(t *testing.T) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Aliases: []string{"UPLOADS.GitHub.COM", "raw.githubusercontent.com", "[::1]:443"},
		Default: "deny",
		Rules: []HTTPServiceRule{{
			Name: "any", Paths: []string{"/**"}, Decision: "allow",
		}},
	}}
	if err := ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, byHost, err := compileHTTPServices(svcs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, want := range []string{
		"api.github.com",            // upstream host
		"uploads.github.com",        // mixed-case alias canonicalizes to lowercase
		"raw.githubusercontent.com", // plain alias
		"::1",                       // bracketed IPv6 alias canonicalizes without brackets
	} {
		if _, ok := byHost[want]; !ok {
			t.Errorf("byHost missing %q (keys: %v)", want, keysOf(byHost))
		}
	}
}

func keysOf(m map[string]*compiledHTTPService) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCompileHTTPServices_RejectsDuplicateName(t *testing.T) {
	svcs := []HTTPService{
		{
			Name: "svc", Upstream: "https://api.example.com",
			Rules: []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
		{
			Name: "svc", Upstream: "https://api.other.example.com",
			Rules: []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
	}
	if _, _, err := compileHTTPServices(svcs); err == nil || !strings.Contains(err.Error(), "duplicate service name") {
		t.Fatalf("want duplicate service name error, got %v", err)
	}
}

func TestCompileHTTPServices_RejectsDuplicateUpstreamHost(t *testing.T) {
	svcs := []HTTPService{
		{
			Name: "a", Upstream: "https://api.example.com",
			Rules: []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
		{
			Name: "b", Upstream: "https://api.example.com",
			Rules: []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
	}
	if _, _, err := compileHTTPServices(svcs); err == nil || !strings.Contains(err.Error(), "duplicate upstream host") {
		t.Fatalf("want duplicate upstream host error, got %v", err)
	}
}

func TestCompileHTTPServices_RejectsDuplicateAliasHost(t *testing.T) {
	svcs := []HTTPService{
		{
			Name: "a", Upstream: "https://api.a.example.com",
			Aliases: []string{"shared.example.com"},
			Rules:   []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
		{
			Name: "b", Upstream: "https://api.b.example.com",
			Aliases: []string{"shared.example.com"},
			Rules:   []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
	}
	if _, _, err := compileHTTPServices(svcs); err == nil || !strings.Contains(err.Error(), "via alias") {
		t.Fatalf("want alias collision error, got %v", err)
	}
}

func TestHTTPServiceYAMLUnmarshal_WithSecret(t *testing.T) {
	input := `
http_services:
  - name: github
    upstream: https://api.github.com
    default: deny
    secret:
      ref: "vault://kv/data/github#token"
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
    scrub_response: true
    rules:
      - name: read-issues
        methods: [GET]
        paths: ["/repos/*/*/issues"]
        decision: allow
`
	var p struct {
		HTTPServices []HTTPService `yaml:"http_services"`
	}
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.HTTPServices) != 1 {
		t.Fatalf("want 1 service, got %d", len(p.HTTPServices))
	}
	s := p.HTTPServices[0]
	if s.Secret == nil {
		t.Fatal("secret is nil")
	}
	if s.Secret.Ref != "vault://kv/data/github#token" {
		t.Errorf("secret.ref = %q", s.Secret.Ref)
	}
	if s.Secret.Format != "ghp_{rand:36}" {
		t.Errorf("secret.format = %q", s.Secret.Format)
	}
	if s.Inject == nil || s.Inject.Header == nil {
		t.Fatal("inject.header is nil")
	}
	if s.Inject.Header.Name != "Authorization" {
		t.Errorf("inject.header.name = %q", s.Inject.Header.Name)
	}
	if s.Inject.Header.Template != "Bearer {{secret}}" {
		t.Errorf("inject.header.template = %q", s.Inject.Header.Template)
	}
	if s.ScrubResponse == nil || !*s.ScrubResponse {
		t.Error("scrub_response should be true")
	}
}

func TestHTTPServiceYAMLUnmarshal_WithoutSecret(t *testing.T) {
	input := `
http_services:
  - name: stripe
    upstream: https://api.stripe.com
    default: deny
    rules:
      - name: read
        methods: [GET]
        paths: ["/v1/customers"]
        decision: allow
`
	var p struct {
		HTTPServices []HTTPService `yaml:"http_services"`
	}
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s := p.HTTPServices[0]
	if s.Secret != nil {
		t.Error("secret should be nil for filtering-only service")
	}
	if s.Inject != nil {
		t.Error("inject should be nil for filtering-only service")
	}
	if s.ScrubResponse != nil {
		t.Error("scrub_response should be nil when not set")
	}
}

func TestHTTPServices_DeepCopyPointerFields(t *testing.T) {
	scrub := true
	p := &Policy{
		Version: 1,
		Name:    "test",
		HTTPServices: []HTTPService{{
			Name: "github", Upstream: "https://api.github.com",
			Secret: &HTTPServiceSecret{
				Ref:    "vault://kv/data/github#token",
				Format: "ghp_{rand:36}",
			},
			Inject: &HTTPServiceInject{
				Header: &HTTPServiceInjectHeader{
					Name:     "Authorization",
					Template: "Bearer {{secret}}",
				},
			},
			ScrubResponse: &scrub,
			Rules: []HTTPServiceRule{{
				Name: "read", Paths: []string{"/repos/**"}, Decision: "allow",
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	e, err := NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// First call — grab the returned copy and mutate every pointer field.
	got := e.HTTPServices()
	if len(got) != 1 {
		t.Fatalf("expected 1 service, got %d", len(got))
	}
	got[0].Secret.Ref = "MUTATED"
	got[0].Inject.Header.Name = "MUTATED"
	*got[0].ScrubResponse = false

	// Second call — values must be the originals, not the mutations.
	got2 := e.HTTPServices()
	if got2[0].Secret.Ref != "vault://kv/data/github#token" {
		t.Errorf("Secret.Ref = %q, want original (shallow-copy leak)", got2[0].Secret.Ref)
	}
	if got2[0].Inject.Header.Name != "Authorization" {
		t.Errorf("Inject.Header.Name = %q, want original (shallow-copy leak)", got2[0].Inject.Header.Name)
	}
	if got2[0].ScrubResponse == nil || !*got2[0].ScrubResponse {
		t.Errorf("ScrubResponse = %v, want true (shallow-copy leak)", got2[0].ScrubResponse)
	}
}

func TestNewEngine_PopulatesHTTPServiceMaps(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		HTTPServices: []HTTPService{{
			Name: "github", Upstream: "https://api.github.com",
			Rules: []HTTPServiceRule{{
				Name: "read", Paths: []string{"/repos/**"}, Decision: "allow",
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	e, err := NewEngine(p, false, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, ok := e.httpServices["github"]; !ok {
		t.Error("e.httpServices missing github")
	}
	if _, ok := e.httpServiceHosts["api.github.com"]; !ok {
		t.Error("e.httpServiceHosts missing api.github.com")
	}
}
