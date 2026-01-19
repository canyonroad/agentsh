package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSecurityConfig_Unmarshal(t *testing.T) {
	yamlData := `
security:
  mode: auto
  strict: false
  minimum_mode: landlock-only
  warn_degraded: true

landlock:
  enabled: true
  allow_execute:
    - /usr/bin
    - /bin
  allow_read:
    - /etc/ssl/certs
  deny_paths:
    - /var/run/docker.sock
  network:
    allow_connect_tcp: true
    allow_bind_tcp: false

capabilities:
  allow:
    - CAP_NET_RAW
`

	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify security config
	if cfg.Security.Mode != "auto" {
		t.Errorf("expected mode 'auto', got %q", cfg.Security.Mode)
	}
	if cfg.Security.MinimumMode != "landlock-only" {
		t.Errorf("expected minimum_mode 'landlock-only', got %q", cfg.Security.MinimumMode)
	}

	// Verify landlock config
	if !cfg.Landlock.Enabled {
		t.Error("expected landlock.enabled = true")
	}
	if len(cfg.Landlock.AllowExecute) != 2 {
		t.Errorf("expected 2 allow_execute paths, got %d", len(cfg.Landlock.AllowExecute))
	}
	if len(cfg.Landlock.DenyPaths) != 1 {
		t.Errorf("expected 1 deny_paths, got %d", len(cfg.Landlock.DenyPaths))
	}

	// Verify capabilities config
	if len(cfg.LinuxCapabilities.Allow) != 1 || cfg.LinuxCapabilities.Allow[0] != "CAP_NET_RAW" {
		t.Errorf("expected [CAP_NET_RAW], got %v", cfg.LinuxCapabilities.Allow)
	}
}

func TestSecurityConfig_Defaults(t *testing.T) {
	yamlData := `
server:
  http:
    addr: ":8080"
`

	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Security defaults should be reasonable
	// Mode should default to "auto" after applying defaults
	applyDefaults(&cfg)

	if cfg.Security.Mode != "auto" {
		t.Errorf("expected default mode 'auto', got %q", cfg.Security.Mode)
	}
	if !cfg.Security.WarnDegraded {
		t.Error("expected warn_degraded to default to true")
	}
}

func TestSecurityConfig_ModeValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid mode auto",
			yaml: `
security:
  mode: auto
`,
			wantErr: false,
		},
		{
			name: "valid mode full",
			yaml: `
security:
  mode: full
`,
			wantErr: false,
		},
		{
			name: "valid mode landlock",
			yaml: `
security:
  mode: landlock
`,
			wantErr: false,
		},
		{
			name: "valid mode minimal",
			yaml: `
security:
  mode: minimal
`,
			wantErr: false,
		},
		{
			name: "invalid mode",
			yaml: `
security:
  mode: invalid_mode
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			applyDefaults(&cfg)
			err = validateConfig(&cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
