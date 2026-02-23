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

func TestProxyConfig_IsMCPOnly(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{"mcp-only mode", "mcp-only", true},
		{"embedded mode", "embedded", false},
		{"disabled mode", "disabled", false},
		{"empty mode", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ProxyConfig{Mode: tt.mode}
			if got := cfg.IsMCPOnly(); got != tt.want {
				t.Errorf("ProxyConfig{Mode: %q}.IsMCPOnly() = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestProxyConfig_IsMCPOnly_YAMLParse(t *testing.T) {
	yamlData := `
proxy:
  mode: mcp-only
  port: 8080
`
	var cfg struct {
		Proxy ProxyConfig `yaml:"proxy"`
	}
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.Proxy.IsMCPOnly() {
		t.Errorf("expected IsMCPOnly() = true for mode %q", cfg.Proxy.Mode)
	}
	if cfg.Proxy.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Proxy.Port)
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
