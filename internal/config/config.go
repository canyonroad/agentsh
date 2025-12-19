package config

import (
	"fmt"
	"os"
	"path/filepath"

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
	HTTP       ServerHTTPConfig       `yaml:"http"`
	GRPC       ServerGRPCConfig       `yaml:"grpc"`
	UnixSocket ServerUnixSocketConfig `yaml:"unix_socket"`
	TLS        ServerTLSConfig        `yaml:"tls"`
}

type ServerHTTPConfig struct {
	Addr string `yaml:"addr"`

	ReadTimeout    string `yaml:"read_timeout"`
	WriteTimeout   string `yaml:"write_timeout"`
	MaxRequestSize string `yaml:"max_request_size"`
}

type ServerGRPCConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type ServerUnixSocketConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"` // e.g. "0660"
}

type ServerTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
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

	// Optional: ship events to an HTTP webhook.
	Webhook AuditWebhookConfig `yaml:"webhook"`
}

type AuditStorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type AuditWebhookConfig struct {
	URL           string            `yaml:"url"`
	BatchSize     int               `yaml:"batch_size"`
	FlushInterval string            `yaml:"flush_interval"`
	Timeout       string            `yaml:"timeout"`
	Headers       map[string]string `yaml:"headers"`
}

type RotationConfig struct {
	MaxSizeMB  int  `yaml:"max_size_mb"`
	MaxAgeDays int  `yaml:"max_age_days"`
	MaxBackups int  `yaml:"max_backups"`
	Compress   bool `yaml:"compress"`
}

type SessionsConfig struct {
	BaseDir     string `yaml:"base_dir"`
	MaxSessions int    `yaml:"max_sessions"`

	// Optional defaults (duration strings). If set, these act as additional caps on top of policy resource_limits.
	DefaultTimeout     string `yaml:"default_timeout"`
	DefaultIdleTimeout string `yaml:"default_idle_timeout"`
	CleanupInterval    string `yaml:"cleanup_interval"`
}

type SandboxConfig struct {
	FUSE    SandboxFUSEConfig    `yaml:"fuse"`
	Network SandboxNetworkConfig `yaml:"network"`
	Cgroups SandboxCgroupsConfig `yaml:"cgroups"`
}

type SandboxFUSEConfig struct {
	Enabled bool `yaml:"enabled"`
	// Optional base dir for mounts; defaults to sessions.base_dir.
	MountBaseDir string `yaml:"mount_base_dir"`
}

type SandboxNetworkConfig struct {
	Enabled         bool                            `yaml:"enabled"`
	ProxyListenAddr string                          `yaml:"proxy_listen_addr"`
	Transparent     SandboxTransparentNetworkConfig `yaml:"transparent"`
	EBPF            SandboxEBPFConfig               `yaml:"ebpf"`
}

type SandboxTransparentNetworkConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SubnetBase string `yaml:"subnet_base"` // e.g. "10.250.0.0/16"
}

type SandboxEBPFConfig struct {
	Enabled     bool `yaml:"enabled"`
	Required    bool `yaml:"required"`
	ResolveRDNS bool `yaml:"resolve_rdns"` // optional reverse DNS on ebpf net events
}

type SandboxCgroupsConfig struct {
	Enabled bool `yaml:"enabled"`
	// BasePath is a cgroupfs directory under which per-command cgroups will be created.
	// If empty, agentsh will default to the current process cgroup.
	// Note: this should be a path under /sys/fs/cgroup (or relative to the current process cgroup dir).
	BasePath string `yaml:"base_path"`
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
	Debug         bool `yaml:"debug"`
	DisableAuth   bool `yaml:"disable_auth"`
	DisablePolicy bool `yaml:"disable_policy"`

	PProf DevelopmentPProfConfig `yaml:"pprof"`
}

type DevelopmentPProfConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
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
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.HTTP.Addr == "" {
		cfg.Server.HTTP.Addr = "0.0.0.0:8080"
	}
	if cfg.Server.GRPC.Addr == "" {
		cfg.Server.GRPC.Addr = "127.0.0.1:9090"
	}
	if cfg.Server.HTTP.ReadTimeout == "" {
		cfg.Server.HTTP.ReadTimeout = "30s"
	}
	if cfg.Server.HTTP.WriteTimeout == "" {
		cfg.Server.HTTP.WriteTimeout = "5m"
	}
	if cfg.Server.HTTP.MaxRequestSize == "" {
		cfg.Server.HTTP.MaxRequestSize = "10MB"
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
	if cfg.Sessions.MaxSessions <= 0 {
		cfg.Sessions.MaxSessions = 100
	}
	if cfg.Sessions.CleanupInterval == "" {
		cfg.Sessions.CleanupInterval = "1m"
	}
	if cfg.Sandbox.FUSE.MountBaseDir == "" {
		cfg.Sandbox.FUSE.MountBaseDir = cfg.Sessions.BaseDir
	}
	if cfg.Sandbox.Network.ProxyListenAddr == "" {
		cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"
	}
	if cfg.Sandbox.Network.Transparent.SubnetBase == "" {
		cfg.Sandbox.Network.Transparent.SubnetBase = "10.250.0.0/16"
	}
	// eBPF tracing defaults to disabled unless explicitly enabled.
	if cfg.Sandbox.Network.EBPF.Required && !cfg.Sandbox.Network.EBPF.Enabled {
		// If a user set required=true but forgot enabled, force enable to avoid silent misconfig.
		// This coupling is also documented in config.yml.
		cfg.Sandbox.Network.EBPF.Enabled = true
	}
	// Reverse DNS is off by default to avoid latency; no defaults needed otherwise.
	// cgroups defaults to disabled unless explicitly enabled.
	if cfg.Sandbox.Cgroups.BasePath == "" {
		cfg.Sandbox.Cgroups.BasePath = ""
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
	if cfg.Audit.Webhook.BatchSize == 0 {
		cfg.Audit.Webhook.BatchSize = 100
	}
	if cfg.Audit.Webhook.FlushInterval == "" {
		cfg.Audit.Webhook.FlushInterval = "10s"
	}
	if cfg.Audit.Webhook.Timeout == "" {
		cfg.Audit.Webhook.Timeout = "5s"
	}
	if cfg.Approvals.Timeout == "" {
		cfg.Approvals.Timeout = "5m"
	}
	if cfg.Approvals.Mode == "" {
		cfg.Approvals.Mode = "local_tty"
	}
	if cfg.Development.PProf.Addr == "" {
		cfg.Development.PProf.Addr = "localhost:6060"
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AGENTSH_HTTP_ADDR"); v != "" {
		cfg.Server.HTTP.Addr = v
	}
	if v := os.Getenv("AGENTSH_GRPC_ADDR"); v != "" {
		cfg.Server.GRPC.Addr = v
	}
	if v := os.Getenv("AGENTSH_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("AGENTSH_DATA_DIR"); v != "" {
		cfg.Sessions.BaseDir = filepath.Join(v, "sessions")
		cfg.Audit.Storage.SQLitePath = filepath.Join(v, "events.db")
	}
}
