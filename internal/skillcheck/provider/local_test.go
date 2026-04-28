package provider

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

func loadFixture(t *testing.T, name string) skillcheck.ScanRequest {
	t.Helper()
	ref, files, err := skillcheck.LoadSkill(filepath.Join("..", "testdata", "skills", name), skillcheck.DefaultLoaderLimits())
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return skillcheck.ScanRequest{Skill: *ref, Files: files}
}

func scanWithLocal(t *testing.T, name string) []skillcheck.Finding {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := NewLocalProvider().Scan(ctx, loadFixture(t, name))
	if err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return resp.Findings
}

func TestLocal_HiddenUnicode(t *testing.T) {
	findings := scanWithLocal(t, "hidden-unicode")
	if !hasType(findings, skillcheck.FindingHiddenUnicode) {
		t.Errorf("expected hidden_unicode finding, got %+v", findings)
	}
}

func TestLocal_EvalEnv(t *testing.T) {
	findings := scanWithLocal(t, "eval-env")
	if !hasType(findings, skillcheck.FindingExfiltration) && !hasType(findings, skillcheck.FindingPolicyViolation) {
		t.Errorf("expected exfil/policy finding for eval $env, got %+v", findings)
	}
}

func TestLocal_ScopeMismatch(t *testing.T) {
	findings := scanWithLocal(t, "scope-mismatch")
	if !hasType(findings, skillcheck.FindingPolicyViolation) {
		t.Errorf("expected policy_violation, got %+v", findings)
	}
}

func TestLocal_PromptInjection(t *testing.T) {
	findings := scanWithLocal(t, "prompt-injection")
	if !hasType(findings, skillcheck.FindingPromptInjection) {
		t.Errorf("expected prompt_injection, got %+v", findings)
	}
}

func TestLocal_MinimalSkillIsClean(t *testing.T) {
	findings := scanWithLocal(t, "minimal")
	if len(findings) > 0 {
		t.Errorf("minimal skill should produce no findings, got %+v", findings)
	}
}

func hasType(fs []skillcheck.Finding, t skillcheck.FindingType) bool {
	for _, f := range fs {
		if f.Type == t {
			return true
		}
	}
	return false
}
