package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

func TestSkillsSh_NoOriginNoSignal(t *testing.T) {
	p := NewSkillsShProvider(SkillsShConfig{BaseURL: "http://unused.example", Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req := loadFixture(t, "minimal")
	req.Skill.Origin = nil
	resp, err := p.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("no findings expected when origin nil, got %+v", resp.Findings)
	}
}

func TestSkillsSh_RegisteredEmitsProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		if r.URL.Path != "/example/skills/minimal" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewSkillsShProvider(SkillsShConfig{BaseURL: srv.URL, Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req := loadFixture(t, "minimal")
	req.Skill.Name = "minimal"
	req.Skill.Origin = &skillcheck.GitOrigin{URL: "https://github.com/example/skills"}

	resp, err := p.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", resp.Findings)
	}
	if resp.Findings[0].Type != skillcheck.FindingProvenance {
		t.Errorf("type=%s want provenance", resp.Findings[0].Type)
	}
	if resp.Findings[0].Severity != skillcheck.SeverityInfo {
		t.Errorf("severity=%s want info", resp.Findings[0].Severity)
	}
}

func TestSkillsSh_404IsNeutral(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := NewSkillsShProvider(SkillsShConfig{BaseURL: srv.URL, Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req := loadFixture(t, "minimal")
	req.Skill.Name = "minimal"
	req.Skill.Origin = &skillcheck.GitOrigin{URL: "https://github.com/example/skills"}
	resp, err := p.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("404 should produce no findings, got %+v", resp.Findings)
	}
}
