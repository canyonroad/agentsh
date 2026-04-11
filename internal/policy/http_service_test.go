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

func TestHTTPServicesRejectedDuringLoad(t *testing.T) {
	src := []byte(`
version: 1
name: test-policy
http_services:
  - name: github
    upstream: https://api.github.com
`)
	_, err := LoadFromBytes(src)
	if err == nil {
		t.Fatal("expected http_services to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "http_services") {
		t.Errorf("error = %v, want mention of http_services", err)
	}
}
