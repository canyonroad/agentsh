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
			wantErr: "empty alias",
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
			name: "IPv6 upstream collides with bare alias on another service",
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
			name: "IPv6 upstream collides with mixed-case bare alias on another service",
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
					Aliases:  []string{"FE80::1"},
					Rules:    []HTTPServiceRule{validRule},
				},
			},
			wantErr: "duplicate upstream host",
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
