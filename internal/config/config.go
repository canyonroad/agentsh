package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Auth        AuthConfig        `yaml:"auth"`
	Logging     LoggingConfig     `yaml:"logging"`
	Audit       AuditConfig       `yaml:"audit"`
	Sessions    SessionsConfig    `yaml:"sessions"`
	Sandbox     SandboxConfig     `yaml:"sandbox"`
	Policies    PoliciesConfig    `yaml:"policies"`
	Approvals   ApprovalsConfig   `yaml:"approvals"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Health      HealthConfig      `yaml:"health"`
	Development DevelopmentConfig `yaml:"development"`
}

type ServerConfig struct {
	HTTP ServerHTTPConfig `yaml:"http"`
	GRPC ServerGRPCConfig `yaml:"grpc"`
}

type ServerHTTPConfig struct {
	Addr string `yaml:"addr"`
}

type ServerGRPCConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type AuthConfig struct {
	Type   string           `yaml:"type"`
	APIKey AuthAPIKeyConfig `yaml:"api_key"`
}

type AuthAPIKeyConfig struct {
	KeysFile   string `yaml:"keys_file"`
	HeaderName string `yaml:"header_name"`
}

type LoggingConfig struct {
	Level    string         `yaml:"level"`
	Format   string         `yaml:"format"`
	Output   string         `yaml:"output"`
	Rotation RotationConfig `yaml:"rotation"`
}

type AuditConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Output   string         `yaml:"output"`
	Rotation RotationConfig `yaml:"rotation"`

	// Storage is agentsh-specific (not in spec config yet): local DB path.
	Storage AuditStorageConfig `yaml:"storage"`
}

type AuditStorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type RotationConfig struct {
	MaxSizeMB  int  `yaml:"max_size_mb"`
	MaxAgeDays int  `yaml:"max_age_days"`
	MaxBackups int  `yaml:"max_backups"`
	Compress   bool `yaml:"compress"`
}

type SessionsConfig struct {
	BaseDir string `yaml:"base_dir"`
}

type SandboxConfig struct {
	FUSE SandboxFUSEConfig `yaml:"fuse"`
	Network SandboxNetworkConfig `yaml:"network"`
}

type SandboxFUSEConfig struct {
	Enabled bool `yaml:"enabled"`
	// Optional base dir for mounts; defaults to sessions.base_dir.
	MountBaseDir string `yaml:"mount_base_dir"`
}

type SandboxNetworkConfig struct {
	Enabled bool `yaml:"enabled"`
	ProxyListenAddr string `yaml:"proxy_listen_addr"`
}

type PoliciesConfig struct {
	Dir     string `yaml:"dir"`
	Default string `yaml:"default"`
}

type ApprovalsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`    // "local_tty" or "api"
	Timeout string `yaml:"timeout"` // duration string, e.g. "5m"
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type HealthConfig struct {
	Path          string `yaml:"path"`
	ReadinessPath string `yaml:"readiness_path"`
}

type DevelopmentConfig struct {
	Debug        bool `yaml:"debug"`
	DisableAuth  bool `yaml:"disable_auth"`
	DisablePolicy bool `yaml:"disable_policy"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.HTTP.Addr == "" {
		cfg.Server.HTTP.Addr = "0.0.0.0:8080"
	}
	if cfg.Auth.Type == "" {
		cfg.Auth.Type = "none"
	}
	if cfg.Auth.APIKey.HeaderName == "" {
		cfg.Auth.APIKey.HeaderName = "X-API-Key"
	}
	if cfg.Sessions.BaseDir == "" {
		cfg.Sessions.BaseDir = "/var/lib/agentsh/sessions"
	}
	if cfg.Sandbox.FUSE.MountBaseDir == "" {
		cfg.Sandbox.FUSE.MountBaseDir = cfg.Sessions.BaseDir
	}
	if cfg.Sandbox.Network.ProxyListenAddr == "" {
		cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"
	}
	if cfg.Policies.Default == "" {
		cfg.Policies.Default = "default"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Health.Path == "" {
		cfg.Health.Path = "/health"
	}
	if cfg.Health.ReadinessPath == "" {
		cfg.Health.ReadinessPath = "/ready"
	}
	if cfg.Audit.Storage.SQLitePath == "" {
		// Default DB path adjacent to sessions base dir (e.g., /var/lib/agentsh/events.db).
		cfg.Audit.Storage.SQLitePath = "/var/lib/agentsh/events.db"
	}
	if cfg.Audit.Rotation.MaxSizeMB == 0 {
		cfg.Audit.Rotation.MaxSizeMB = 500
	}
	if cfg.Audit.Rotation.MaxBackups == 0 {
		cfg.Audit.Rotation.MaxBackups = 10
	}
	if cfg.Approvals.Timeout == "" {
		cfg.Approvals.Timeout = "5m"
	}
	if cfg.Approvals.Mode == "" {
		cfg.Approvals.Mode = "local_tty"
	}
}
