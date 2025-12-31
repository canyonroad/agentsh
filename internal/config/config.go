package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform      PlatformConfig             `yaml:"platform"`
	Server        ServerConfig               `yaml:"server"`
	Auth          AuthConfig                 `yaml:"auth"`
	Logging       LoggingConfig              `yaml:"logging"`
	Audit         AuditConfig                `yaml:"audit"`
	Sessions      SessionsConfig             `yaml:"sessions"`
	Sandbox       SandboxConfig              `yaml:"sandbox"`
	Policies      PoliciesConfig             `yaml:"policies"`
	MountProfiles map[string]MountProfile    `yaml:"mount_profiles"`
	Approvals     ApprovalsConfig            `yaml:"approvals"`
	Metrics       MetricsConfig              `yaml:"metrics"`
	Health        HealthConfig               `yaml:"health"`
	Development   DevelopmentConfig          `yaml:"development"`
}

// PlatformConfig configures cross-platform selection and fallback behavior.
type PlatformConfig struct {
	// Mode selects the platform: auto, linux, darwin, darwin-lima, windows, windows-wsl2
	Mode string `yaml:"mode"`

	// Fallback configures fallback behavior when preferred mode is unavailable
	Fallback PlatformFallbackConfig `yaml:"fallback"`

	// MountPoints configures platform-specific mount points
	MountPoints PlatformMountPointsConfig `yaml:"mount_points"`
}

// PlatformFallbackConfig configures platform fallback behavior.
type PlatformFallbackConfig struct {
	// Enabled allows falling back to alternative platforms
	Enabled bool `yaml:"enabled"`

	// Order specifies fallback priority (first available is used)
	Order []string `yaml:"order"`
}

// PlatformMountPointsConfig specifies platform-specific mount points.
type PlatformMountPointsConfig struct {
	Linux       string `yaml:"linux"`
	Darwin      string `yaml:"darwin"`
	Windows     string `yaml:"windows"`
	WindowsWSL2 string `yaml:"windows_wsl2"`
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
	// Enabled enables the sandbox subsystem
	Enabled bool `yaml:"enabled"`

	// AllowDegraded permits running with reduced isolation if full isolation unavailable
	AllowDegraded bool `yaml:"allow_degraded"`

	// Limits configures resource limits for sandboxed processes
	Limits SandboxLimitsConfig `yaml:"limits"`

	FUSE        SandboxFUSEConfig        `yaml:"fuse"`
	Network     SandboxNetworkConfig     `yaml:"network"`
	Cgroups     SandboxCgroupsConfig     `yaml:"cgroups"`
	UnixSockets SandboxUnixSocketsConfig `yaml:"unix_sockets"`
}

// SandboxLimitsConfig configures resource limits.
type SandboxLimitsConfig struct {
	MaxMemoryMB    int `yaml:"max_memory_mb"`
	MaxCPUPercent  int `yaml:"max_cpu_percent"`
	MaxProcesses   int `yaml:"max_processes"`
	MaxDiskIOMbps  int `yaml:"max_disk_io_mbps"`
	MaxNetworkMbps int `yaml:"max_network_mbps"`
}

type SandboxFUSEConfig struct {
	Enabled bool            `yaml:"enabled"`
	Audit   FUSEAuditConfig `yaml:"audit"`
	// Optional base dir for mounts; defaults to sessions.base_dir.
	MountBaseDir string `yaml:"mount_base_dir"`
}

type FUSEAuditConfig struct {
	Enabled              *bool  `yaml:"enabled"`
	Mode                 string `yaml:"mode"` // monitor, soft_block, soft_delete, strict
	TrashPath            string `yaml:"trash_path"`
	TTL                  string `yaml:"ttl"`
	Quota                string `yaml:"quota"`
	StrictOnAuditFailure bool   `yaml:"strict_on_audit_failure"`
	MaxEventQueue        int    `yaml:"max_event_queue"`
	HashSmallFilesUnder  string `yaml:"hash_small_files_under"`
}

type SandboxNetworkConfig struct {
	Enabled         bool                            `yaml:"enabled"`
	ProxyPort       int                             `yaml:"proxy_port"`
	DNSPort         int                             `yaml:"dns_port"`
	InterceptMode   string                          `yaml:"intercept_mode"` // all, tcp_only, monitor
	ProxyListenAddr string                          `yaml:"proxy_listen_addr"`
	TLSInspection   TLSInspectionConfig             `yaml:"tls_inspection"`
	Transparent     SandboxTransparentNetworkConfig `yaml:"transparent"`
	EBPF            SandboxEBPFConfig               `yaml:"ebpf"`
}

// TLSInspectionConfig configures TLS interception (requires CA cert).
type TLSInspectionConfig struct {
	Enabled bool   `yaml:"enabled"`
	CACert  string `yaml:"ca_cert"`
	CAKey   string `yaml:"ca_key"`
}

type SandboxTransparentNetworkConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SubnetBase string `yaml:"subnet_base"` // e.g. "10.250.0.0/16"
}

type SandboxEBPFConfig struct {
	Enabled           bool `yaml:"enabled"`
	Required          bool `yaml:"required"`
	ResolveRDNS       bool `yaml:"resolve_rdns"`         // optional reverse DNS on ebpf net events
	Enforce           bool `yaml:"enforce"`              // deny in BPF if not allowed
	EnforceWithoutDNS bool `yaml:"enforce_without_dns"`  // when true, default deny even if DNS resolution failed
	MapAllowEntries   int  `yaml:"map_allow_entries"`    // optional override for allowlist map size
	MapDenyEntries    int  `yaml:"map_deny_entries"`     // optional override for denylist map size
	MapLPMEntries     int  `yaml:"map_lpm_entries"`      // optional override for LPM map size
	MapLPMDenyEntries int  `yaml:"map_lpm_deny_entries"` // optional override for deny LPM map size
	MapDefaultEntries int  `yaml:"map_default_entries"`  // optional override for default_deny map size
	DNSRefreshSeconds int  `yaml:"dns_refresh_seconds"`  // interval to refresh DNS-derived allowlist (0 disables)
	DNSMaxTTLSeconds  int  `yaml:"dns_max_ttl_seconds"`  // cap TTL used for caching/refresh (0 uses default 60s)
}

type SandboxCgroupsConfig struct {
	Enabled bool `yaml:"enabled"`
	// BasePath is a cgroupfs directory under which per-command cgroups will be created.
	// If empty, agentsh will default to the current process cgroup.
	// Note: this should be a path under /sys/fs/cgroup (or relative to the current process cgroup dir).
	BasePath string `yaml:"base_path"`
}

type SandboxUnixSocketsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WrapperBin string `yaml:"wrapper_bin"` // optional override; defaults to "agentsh-unixwrap" in PATH
}

type PoliciesConfig struct {
	Dir          string          `yaml:"dir"`
	Default      string          `yaml:"default"`
	Allowed      []string        `yaml:"allowed"`
	ManifestPath string          `yaml:"manifest_path"`
	EnvPolicy    EnvPolicyConfig `yaml:"env_policy"`
	EnvShimPath  string          `yaml:"env_shim_path"`
}

// MountProfile defines a collection of mounts with policies.
type MountProfile struct {
	BasePolicy string      `yaml:"base_policy"`
	Mounts     []MountSpec `yaml:"mounts"`
}

// MountSpec defines a single mount point with its policy.
type MountSpec struct {
	Path   string `yaml:"path"`
	Policy string `yaml:"policy"`
}

type EnvPolicyConfig struct {
	Allow          []string `yaml:"allow"`
	Deny           []string `yaml:"deny"`
	MaxBytes       int      `yaml:"max_bytes"`
	MaxKeys        int      `yaml:"max_keys"`
	BlockIteration bool     `yaml:"block_iteration"`
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
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadFromBytes loads configuration from bytes without applying environment
// overrides. This is intended for testing where env vars should not interfere.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	// Platform defaults
	if cfg.Platform.Mode == "" {
		cfg.Platform.Mode = "auto"
	}
	if cfg.Platform.MountPoints.Linux == "" {
		cfg.Platform.MountPoints.Linux = "/tmp/agentsh/workspace"
	}
	if cfg.Platform.MountPoints.Darwin == "" {
		cfg.Platform.MountPoints.Darwin = "/tmp/agentsh/workspace"
	}
	if cfg.Platform.MountPoints.Windows == "" {
		cfg.Platform.MountPoints.Windows = "X:"
	}
	if cfg.Platform.MountPoints.WindowsWSL2 == "" {
		cfg.Platform.MountPoints.WindowsWSL2 = "/tmp/agentsh/workspace"
	}

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
	if cfg.Sandbox.FUSE.Audit.Mode == "" {
		cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	}
	if cfg.Sandbox.FUSE.Audit.TrashPath == "" {
		cfg.Sandbox.FUSE.Audit.TrashPath = ".agentsh_trash"
	}
	if cfg.Sandbox.FUSE.Audit.TTL == "" {
		cfg.Sandbox.FUSE.Audit.TTL = "7d"
	}
	if cfg.Sandbox.FUSE.Audit.Quota == "" {
		cfg.Sandbox.FUSE.Audit.Quota = "5GB"
	}
	if cfg.Sandbox.FUSE.Audit.MaxEventQueue <= 0 {
		cfg.Sandbox.FUSE.Audit.MaxEventQueue = 1024
	}
	if cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder == "" {
		cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder = "1MB"
	}
	// default audit enabled unless explicitly disabled
	if cfg.Sandbox.FUSE.Audit.Enabled == nil {
		t := true
		cfg.Sandbox.FUSE.Audit.Enabled = &t
	}
	if cfg.Sandbox.Network.ProxyPort == 0 {
		cfg.Sandbox.Network.ProxyPort = 9080
	}
	if cfg.Sandbox.Network.DNSPort == 0 {
		cfg.Sandbox.Network.DNSPort = 9053
	}
	if cfg.Sandbox.Network.InterceptMode == "" {
		cfg.Sandbox.Network.InterceptMode = "all"
	}
	if cfg.Sandbox.Network.ProxyListenAddr == "" {
		cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"
	}
	// Resource limits defaults
	if cfg.Sandbox.Limits.MaxMemoryMB == 0 {
		cfg.Sandbox.Limits.MaxMemoryMB = 2048
	}
	if cfg.Sandbox.Limits.MaxCPUPercent == 0 {
		cfg.Sandbox.Limits.MaxCPUPercent = 50
	}
	if cfg.Sandbox.Limits.MaxProcesses == 0 {
		cfg.Sandbox.Limits.MaxProcesses = 100
	}
	if cfg.Sandbox.Limits.MaxDiskIOMbps == 0 {
		cfg.Sandbox.Limits.MaxDiskIOMbps = 100
	}
	if cfg.Sandbox.Limits.MaxNetworkMbps == 0 {
		cfg.Sandbox.Limits.MaxNetworkMbps = 50
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
	// If enforce is set, ebpf must be enabled.
	if cfg.Sandbox.Network.EBPF.Enforce && !cfg.Sandbox.Network.EBPF.Enabled {
		cfg.Sandbox.Network.EBPF.Enabled = true
	}
	if cfg.Sandbox.Network.EBPF.DNSRefreshSeconds < 0 {
		cfg.Sandbox.Network.EBPF.DNSRefreshSeconds = 0
	}
	if cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds <= 0 {
		cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds = 60
	}
	if cfg.Sandbox.Network.EBPF.MapDenyEntries < 0 {
		cfg.Sandbox.Network.EBPF.MapDenyEntries = 0
	}
	if cfg.Sandbox.Network.EBPF.MapLPMDenyEntries < 0 {
		cfg.Sandbox.Network.EBPF.MapLPMDenyEntries = 0
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
	if v := os.Getenv("AGENTSH_PLATFORM_MODE"); v != "" {
		cfg.Platform.Mode = v
	}
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

func validateConfig(cfg *Config) error {
	switch cfg.Sandbox.FUSE.Audit.Mode {
	case "monitor", "soft_block", "soft_delete", "strict":
	default:
		return fmt.Errorf("invalid sandbox.fuse.audit.mode %q", cfg.Sandbox.FUSE.Audit.Mode)
	}
	if cfg.Sandbox.FUSE.Audit.MaxEventQueue < 0 {
		return fmt.Errorf("sandbox.fuse.audit.max_event_queue must be >= 0")
	}
	switch cfg.Sandbox.Network.InterceptMode {
	case "", "all", "tcp_only", "monitor":
	default:
		return fmt.Errorf("invalid sandbox.network.intercept_mode %q", cfg.Sandbox.Network.InterceptMode)
	}
	// Validate platform mode
	switch cfg.Platform.Mode {
	case "", "auto", "linux", "darwin", "darwin-lima", "windows", "windows-wsl2":
	default:
		return fmt.Errorf("invalid platform.mode %q", cfg.Platform.Mode)
	}
	return nil
}
