package server

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestBuildSkillcheckProviders_UnknownNameRejected(t *testing.T) {
	_, err := buildSkillcheckProviders(map[string]config.SkillcheckProviderConfig{
		"locla": {Enabled: true},
	})
	if err == nil {
		t.Fatalf("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "locla") || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention typo and 'unknown'; got: %v", err)
	}
}

func TestBuildSkillcheckProviders_DisabledIgnored(t *testing.T) {
	out, err := buildSkillcheckProviders(map[string]config.SkillcheckProviderConfig{
		"local": {Enabled: false},
		"snyk":  {Enabled: false},
	})
	if err != nil {
		t.Fatalf("disabled-only should not error; got %v", err)
	}
	if len(out) != 0 {
		t.Errorf("disabled providers should not appear; got %v", out)
	}
}

func TestBuildSkillcheckProviders_ValidLocal(t *testing.T) {
	out, err := buildSkillcheckProviders(map[string]config.SkillcheckProviderConfig{
		"local": {Enabled: true},
	})
	if err != nil {
		t.Fatalf("local should be valid; got %v", err)
	}
	if _, ok := out["local"]; !ok {
		t.Errorf("local provider missing from result")
	}
}
