package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProxyConfigDefaults(t *testing.T) {
	cfg := DefaultProxyConfig()
	if cfg.Mode != "embedded" {
		t.Errorf("expected mode 'embedded', got %q", cfg.Mode)
	}
	if cfg.Port != 0 {
		t.Errorf("expected port 0 (random), got %d", cfg.Port)
	}
}

func TestDLPConfigParse(t *testing.T) {
	yamlData := `
dlp:
  mode: redact
  patterns:
    email: true
    phone: false
  custom_patterns:
    - name: customer_id
      display: identifier
      regex: "CUST-[0-9]{8}"
`
	var cfg struct {
		DLP DLPConfig `yaml:"dlp"`
	}
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DLP.Mode != "redact" {
		t.Errorf("expected mode 'redact', got %q", cfg.DLP.Mode)
	}
	if len(cfg.DLP.CustomPatterns) != 1 {
		t.Fatalf("expected 1 custom pattern, got %d", len(cfg.DLP.CustomPatterns))
	}
	if cfg.DLP.CustomPatterns[0].Display != "identifier" {
		t.Errorf("expected display 'identifier', got %q", cfg.DLP.CustomPatterns[0].Display)
	}
}
