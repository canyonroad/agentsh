package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Platform          PlatformConfig          `yaml:"platform"`
	Server            ServerConfig            `yaml:"server"`
	Auth              AuthConfig              `yaml:"auth"`
	Logging           LoggingConfig           `yaml:"logging"`
	Audit             AuditConfig             `yaml:"audit"`
	Sessions          SessionsConfig          `yaml:"sessions"`
	Sandbox           SandboxConfig           `yaml:"sandbox"`
	Policies          PoliciesConfig          `yaml:"policies"`
	MountProfiles     map[string]MountProfile `yaml:"mount_profiles"`
	Approvals         ApprovalsConfig         `yaml:"approvals"`
	Metrics           MetricsConfig           `yaml:"metrics"`
	Health            HealthConfig            `yaml:"health"`
	Development       DevelopmentConfig       `yaml:"development"`
	Proxy             ProxyConfig             `yaml:"proxy"`
	DLP               DLPConfig               `yaml:"dlp"`
	LLMStorage        LLMStorageConfig        `yaml:"llm_storage"`
	Security          SecurityConfig          `yaml:"security"`
	Landlock          LandlockConfig          `yaml:"landlock"`
	LinuxCapabilities CapabilitiesConfig      `yaml:"capabilities"`
	ThreatFeeds       ThreatFeedsConfig       `yaml:"threat_feeds"`
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
	Type   string           `yaml:"type"` // "api_key", "oidc", "hybrid"
	APIKey AuthAPIKeyConfig `yaml:"api_key"`
	OIDC   OIDCConfig       `yaml:"oidc"`
}

type AuthAPIKeyConfig struct {
	KeysFile   string `yaml:"keys_file"`
	HeaderName string `yaml:"header_name"`
}

// OIDCConfig configures OpenID Connect authentication.
type OIDCConfig struct {
	Issuer           string            `yaml:"issuer"`            // e.g., "https://corp.okta.com"
	ClientID         string            `yaml:"client_id"`         // e.g., "agentsh-server"
	Audience         string            `yaml:"audience"`          // Expected audience claim
	JWKSCacheTTL     string            `yaml:"jwks_cache_ttl"`    // e.g., "1h"
	DiscoveryTimeout string            `yaml:"discovery_timeout"` // Timeout for OIDC discovery (default: "5s")
	ClaimMappings    OIDCClaimMappings `yaml:"claim_mappings"`
	AllowedGroups    []string          `yaml:"allowed_groups"`    // Groups allowed to access
	GroupPolicyMap   map[string]string `yaml:"group_policy_map"`  // group -> policy name
	GroupRoleMap     map[string]string `yaml:"group_role_map"`    // group -> role (admin, approver, agent)
}

// OIDCClaimMappings maps OIDC claims to agentsh fields.
type OIDCClaimMappings struct {
	OperatorID string `yaml:"operator_id"` // Claim for operator ID (default: "sub")
	Groups     string `yaml:"groups"`      // Claim for groups (default: "groups")
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

	// Integrity configures tamper-proof audit logging with HMAC chains.
	Integrity AuditIntegrityConfig `yaml:"integrity"`

	// Encryption configures AES-256-GCM encryption at rest.
	Encryption AuditEncryptionConfig `yaml:"encryption"`

	// OTEL configures OpenTelemetry event export.
	OTEL AuditOTELConfig `yaml:"otel"`
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

// AuditIntegrityConfig configures tamper-proof audit logging.
type AuditIntegrityConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"` // hmac-sha256 (default), hmac-sha512

	// Key source (mutually exclusive options)
	KeySource string `yaml:"key_source"` // file, env, aws_kms, azure_keyvault, hashicorp_vault, gcp_kms

	// File/Env source (legacy, still supported)
	KeyFile string `yaml:"key_file"` // Path to HMAC key file
	KeyEnv  string `yaml:"key_env"`  // Or env var name containing key

	// AWS KMS configuration
	AWSKMS AWSKMSConfig `yaml:"aws_kms"`

	// Azure Key Vault configuration
	AzureKeyVault AzureKeyVaultConfig `yaml:"azure_keyvault"`

	// HashiCorp Vault configuration
	HashiCorpVault HashiCorpVaultConfig `yaml:"hashicorp_vault"`

	// GCP Cloud KMS configuration
	GCPKMS GCPKMSConfig `yaml:"gcp_kms"`
}

// AWSKMSConfig configures AWS KMS integration.
type AWSKMSConfig struct {
	KeyID            string `yaml:"key_id"`             // KMS key ARN or alias
	Region           string `yaml:"region"`             // AWS region
	EncryptedDEKFile string `yaml:"encrypted_dek_file"` // Optional path to cache encrypted DEK
}

// AzureKeyVaultConfig configures Azure Key Vault integration.
type AzureKeyVaultConfig struct {
	VaultURL   string `yaml:"vault_url"`   // Vault URL (e.g., https://myvault.vault.azure.net)
	KeyName    string `yaml:"key_name"`    // Secret name in vault
	KeyVersion string `yaml:"key_version"` // Optional version (empty = latest)
}

// HashiCorpVaultConfig configures HashiCorp Vault integration.
type HashiCorpVaultConfig struct {
	Address    string `yaml:"address"`     // Vault address
	AuthMethod string `yaml:"auth_method"` // token, kubernetes, approle
	TokenFile  string `yaml:"token_file"`  // Path to token file (for token auth)
	K8sRole    string `yaml:"kubernetes_role"` // Role name (for kubernetes auth)
	AppRoleID  string `yaml:"approle_id"`  // Role ID (for approle auth)
	SecretID   string `yaml:"secret_id"`   // Secret ID (for approle auth, or use VAULT_SECRET_ID env)
	SecretPath string `yaml:"secret_path"` // Path to secret (e.g., secret/data/agentsh/audit-key)
	KeyField   string `yaml:"key_field"`   // Field name within secret (default: "key")
}

// GCPKMSConfig configures GCP Cloud KMS integration.
type GCPKMSConfig struct {
	KeyName          string `yaml:"key_name"`           // Full key resource name
	EncryptedDEKFile string `yaml:"encrypted_dek_file"` // Optional path to cache encrypted DEK
}

// AuditEncryptionConfig configures encryption at rest.
type AuditEncryptionConfig struct {
	Enabled   bool   `yaml:"enabled"`
	KeySource string `yaml:"key_source"` // file, env
	KeyFile   string `yaml:"key_file"`
	KeyEnv    string `yaml:"key_env"`
}

// AuditOTELConfig configures OpenTelemetry event export.
type AuditOTELConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Endpoint string            `yaml:"endpoint"`
	Protocol string            `yaml:"protocol"` // "grpc" or "http"
	TLS      OTELTLSConfig     `yaml:"tls"`
	Headers  map[string]string `yaml:"headers"`
	Timeout  string            `yaml:"timeout"`
	Signals  OTELSignalsConfig `yaml:"signals"`
	Batch    OTELBatchConfig   `yaml:"batch"`
	Filter   OTELFilterConfig  `yaml:"filter"`
	Resource OTELResourceConfig `yaml:"resource"`
}

// OTELTLSConfig configures TLS for the OTEL exporter.
type OTELTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	Insecure bool   `yaml:"insecure"`
}

// OTELSignalsConfig selects which OTEL signal types to export.
type OTELSignalsConfig struct {
	Logs  bool `yaml:"logs"`
	Spans bool `yaml:"spans"`
}

// OTELBatchConfig configures OTEL export batching.
type OTELBatchConfig struct {
	MaxSize int    `yaml:"max_size"`
	Timeout string `yaml:"timeout"`
}

// OTELFilterConfig controls which events are exported via OTEL.
type OTELFilterConfig struct {
	IncludeTypes      []string `yaml:"include_types"`
	ExcludeTypes      []string `yaml:"exclude_types"`
	IncludeCategories []string `yaml:"include_categories"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	MinRiskLevel      string   `yaml:"min_risk_level"`
}

// OTELResourceConfig configures the OTEL resource attributes.
type OTELResourceConfig struct {
	ServiceName     string            `yaml:"service_name"`
	ExtraAttributes map[string]string `yaml:"extra_attributes"`
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

	// Checkpoints configures workspace checkpoint/rollback functionality.
	Checkpoints CheckpointConfig `yaml:"checkpoints"`
}

// CheckpointConfig configures workspace checkpoint and rollback.
type CheckpointConfig struct {
	Enabled       bool                    `yaml:"enabled"`
	StorageDir    string                  `yaml:"storage_dir"`    // Directory for checkpoint storage
	MaxPerSession int                     `yaml:"max_per_session"` // Max checkpoints per session (0 = unlimited)
	MaxSizeMB     int                     `yaml:"max_size_mb"`     // Max total size per session (0 = unlimited)
	AutoCheckpoint AutoCheckpointConfig   `yaml:"auto_checkpoint"`
	Retention     CheckpointRetentionConfig `yaml:"retention"`
}

// AutoCheckpointConfig configures automatic checkpointing before risky commands.
type AutoCheckpointConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Triggers []string `yaml:"triggers"` // Commands that trigger auto-checkpoint (e.g., "rm", "mv")
}

// CheckpointRetentionConfig configures checkpoint cleanup.
type CheckpointRetentionConfig struct {
	MaxAge          string `yaml:"max_age"`          // Duration string, e.g., "24h"
	CleanupInterval string `yaml:"cleanup_interval"` // How often to run cleanup
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
	Seccomp     SandboxSeccompConfig     `yaml:"seccomp"`
	XPC         SandboxXPCConfig         `yaml:"xpc"`
	MCP         SandboxMCPConfig         `yaml:"mcp"`

	// EnvInject specifies environment variables to inject into every command execution.
	// These bypass policy filtering as they are operator-configured (trusted).
	EnvInject map[string]string `yaml:"env_inject"`
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
	Enabled  bool            `yaml:"enabled"`
	Deferred bool            `yaml:"deferred"`
	Audit    FUSEAuditConfig `yaml:"audit"`
	// Optional base dir for mounts; defaults to sessions.base_dir.
	MountBaseDir string `yaml:"mount_base_dir"`
	// DeferredMarkerFile is a file whose existence gates the enable command.
	// If set, the enable command only runs when this file exists.
	DeferredMarkerFile string `yaml:"deferred_marker_file"`
	// DeferredEnableCommand is run when FUSE is unavailable in deferred mode
	// to make /dev/fuse accessible (e.g., ["sudo", "/bin/chmod", "666", "/dev/fuse"]).
	DeferredEnableCommand []string `yaml:"deferred_enable_command"`
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
	RateLimits      NetworkRateLimitsConfig         `yaml:"rate_limits"`
}

// NetworkRateLimitsConfig configures network rate limiting.
type NetworkRateLimitsConfig struct {
	Enabled     bool                       `yaml:"enabled"`
	GlobalRPM   int                        `yaml:"global_rpm"`
	GlobalBurst int                        `yaml:"global_burst"`
	PerDomain   map[string]DomainRateLimit `yaml:"per_domain"`
}

// DomainRateLimit defines rate limits for a domain.
type DomainRateLimit struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
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
	Enabled    *bool  `yaml:"enabled"`     // defaults to true for seccomp enforcement
	WrapperBin string `yaml:"wrapper_bin"` // optional override; defaults to "agentsh-unixwrap" in PATH
}

// SandboxSeccompConfig configures seccomp-bpf filtering.
type SandboxSeccompConfig struct {
	Enabled    bool                        `yaml:"enabled"`
	Mode       string                      `yaml:"mode"` // enforce, audit, disabled
	UnixSocket SandboxSeccompUnixConfig    `yaml:"unix_socket"`
	Syscalls   SandboxSeccompSyscallConfig `yaml:"syscalls"`
	Execve      ExecveConfig                    `yaml:"execve"`
	FileMonitor SandboxSeccompFileMonitorConfig `yaml:"file_monitor"`
}

// SandboxSeccompUnixConfig configures unix socket monitoring via seccomp.
type SandboxSeccompUnixConfig struct {
	Enabled bool   `yaml:"enabled"`
	Action  string `yaml:"action"` // enforce, audit
}

// SandboxSeccompSyscallConfig configures syscall blocking.
type SandboxSeccompSyscallConfig struct {
	DefaultAction string   `yaml:"default_action"` // allow, block
	Block         []string `yaml:"block"`
	Allow         []string `yaml:"allow"`
	OnBlock       string   `yaml:"on_block"` // kill, log_and_kill
}

// SandboxSeccompFileMonitorConfig configures file I/O interception via seccomp.
type SandboxSeccompFileMonitorConfig struct {
	Enabled            bool `yaml:"enabled"`
	EnforceWithoutFUSE bool `yaml:"enforce_without_fuse"`
}

// SandboxXPCConfig configures macOS XPC/Mach IPC control.
type SandboxXPCConfig struct {
	Enabled       bool                 `yaml:"enabled"`
	Mode          string               `yaml:"mode"` // enforce, audit, disabled
	WrapperBin    string               `yaml:"wrapper_bin"`
	MachServices  SandboxXPCMachConfig `yaml:"mach_services"`
	ESFMonitoring SandboxXPCESFConfig  `yaml:"esf_monitoring"`
}

// SandboxXPCMachConfig configures mach-lookup restrictions.
type SandboxXPCMachConfig struct {
	DefaultAction string   `yaml:"default_action"` // allow, deny
	Allow         []string `yaml:"allow"`
	Block         []string `yaml:"block"`
	AllowPrefixes []string `yaml:"allow_prefixes"`
	BlockPrefixes []string `yaml:"block_prefixes"`
}

// SandboxXPCESFConfig configures ESF-based XPC monitoring.
type SandboxXPCESFConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SandboxMCPConfig configures MCP security policies.
type SandboxMCPConfig struct {
	EnforcePolicy  bool                    `yaml:"enforce_policy"`
	FailClosed     bool                    `yaml:"fail_closed"` // Block unknown tools if true
	Servers        []MCPServerDeclaration  `yaml:"servers"`
	ServerPolicy   string                  `yaml:"server_policy"` // allowlist, denylist, none
	AllowedServers []MCPServerRule         `yaml:"allowed_servers"`
	DeniedServers  []MCPServerRule         `yaml:"denied_servers"`
	ToolPolicy     string                  `yaml:"tool_policy"` // allowlist, denylist, none
	AllowedTools   []MCPToolRule           `yaml:"allowed_tools"`
	DeniedTools    []MCPToolRule           `yaml:"denied_tools"`
	VersionPinning MCPVersionPinningConfig `yaml:"version_pinning"`
	RateLimits     MCPRateLimitsConfig     `yaml:"rate_limits"`
	CrossServer    CrossServerConfig       `yaml:"cross_server"`
}

// MCPServerDeclaration defines an MCP server and how to connect to it.
type MCPServerDeclaration struct {
	ID             string   `yaml:"id"`
	Type           string   `yaml:"type"`            // "stdio" | "http" | "sse"
	Command        string   `yaml:"command"`          // For stdio servers
	Args           []string `yaml:"args"`             // For stdio servers
	URL            string   `yaml:"url"`              // For http/sse servers
	TLSFingerprint string   `yaml:"tls_fingerprint"`  // Optional TLS cert pin
}

// MCPServerRule matches servers by ID (supports "*" wildcard).
type MCPServerRule struct {
	ID string `yaml:"id"`
}

// MCPToolRule defines a tool matching rule.
type MCPToolRule struct {
	Server      string `yaml:"server"`       // Server ID or "*" for any
	Tool        string `yaml:"tool"`         // Tool name or "*" for any
	ContentHash string `yaml:"content_hash"` // Optional SHA-256 hash
}

// MCPVersionPinningConfig configures version pinning behavior.
type MCPVersionPinningConfig struct {
	Enabled        bool   `yaml:"enabled"`
	OnChange       string `yaml:"on_change"`        // block, alert, allow
	AutoTrustFirst bool   `yaml:"auto_trust_first"` // Pin on first use
}

// MCPRateLimitsConfig configures MCP rate limiting.
type MCPRateLimitsConfig struct {
	Enabled      bool                    `yaml:"enabled"`
	DefaultRPM   int                     `yaml:"default_rpm"`   // Default calls per minute
	DefaultBurst int                     `yaml:"default_burst"`
	PerServer    map[string]MCPRateLimit `yaml:"per_server"`
}

// MCPRateLimit defines rate limit for a server.
type MCPRateLimit struct {
	CallsPerMinute int `yaml:"calls_per_minute"`
	Burst          int `yaml:"burst"`
}

// CrossServerConfig configures cross-server pattern detection.
// These patterns detect potentially malicious multi-server tool call sequences
// (e.g., reading secrets from one server then sending them via another).
type CrossServerConfig struct {
	Enabled         bool                  `yaml:"enabled"`
	ReadThenSend    ReadThenSendConfig    `yaml:"read_then_send"`
	Burst           BurstConfig           `yaml:"burst"`
	CrossServerFlow CrossServerFlowConfig `yaml:"cross_server_flow"`
	ShadowTool      ShadowToolConfig      `yaml:"shadow_tool"`
}

// ReadThenSendConfig detects read-from-one-server-then-send-via-another patterns.
type ReadThenSendConfig struct {
	Enabled bool          `yaml:"enabled"`
	Window  time.Duration `yaml:"window"` // default: 30s
}

// BurstConfig detects rapid-fire tool calls that may indicate exfiltration.
type BurstConfig struct {
	Enabled  bool          `yaml:"enabled"`
	MaxCalls int           `yaml:"max_calls"` // default: 10
	Window   time.Duration `yaml:"window"`    // default: 5s
}

// CrossServerFlowConfig detects tool calls that flow across different servers.
type CrossServerFlowConfig struct {
	Enabled      bool          `yaml:"enabled"`
	SameTurnOnly *bool         `yaml:"same_turn_only"` // default: true
	Window       time.Duration `yaml:"window"`          // default: 30s
}

// ShadowToolConfig detects tool names that shadow/mimic tools from other servers.
type ShadowToolConfig struct {
	Enabled *bool `yaml:"enabled"` // default: true
}

// SecurityConfig controls security mode selection and strictness.
type SecurityConfig struct {
	Mode         string `yaml:"mode"`          // auto, full, landlock, landlock-only, minimal
	Strict       bool   `yaml:"strict"`        // Fail if mode requirements not met
	MinimumMode  string `yaml:"minimum_mode"`  // Fail if auto-detect picks worse
	WarnDegraded bool   `yaml:"warn_degraded"` // Log warnings in degraded mode
}

// LandlockConfig controls Landlock sandbox settings.
type LandlockConfig struct {
	Enabled      bool                  `yaml:"enabled"`
	AllowExecute []string              `yaml:"allow_execute"` // Paths where execute is allowed
	AllowRead    []string              `yaml:"allow_read"`    // Paths where read is allowed
	AllowWrite   []string              `yaml:"allow_write"`   // Paths where write is allowed
	DenyPaths    []string              `yaml:"deny_paths"`    // Paths to deny (by omission)
	Network      LandlockNetworkConfig `yaml:"network"`
}

// LandlockNetworkConfig controls Landlock network restrictions (kernel 6.7+).
type LandlockNetworkConfig struct {
	AllowConnectTCP bool  `yaml:"allow_connect_tcp"` // Allow outbound TCP
	AllowBindTCP    bool  `yaml:"allow_bind_tcp"`    // Allow listening
	BindPorts       []int `yaml:"bind_ports"`        // Specific ports if bind allowed
}

// CapabilitiesConfig controls Linux capability dropping.
type CapabilitiesConfig struct {
	Allow []string `yaml:"allow"` // Capabilities to keep (empty = drop all droppable)
}

// PoliciesConfig configures policy loading.
type PoliciesConfig struct {
	Dir               string          `yaml:"dir"`
	Default           string          `yaml:"default"`
	Allowed           []string        `yaml:"allowed"`
	ManifestPath      string          `yaml:"manifest_path"`
	EnvPolicy         EnvPolicyConfig `yaml:"env_policy"`
	EnvShimPath       string          `yaml:"env_shim_path"`
	ReloadInterval    string          `yaml:"reload_interval"`
	DetectProjectRoot *bool           `yaml:"detect_project_root"` // nil means true (default enabled)
	ProjectMarkers    []string        `yaml:"project_markers"`     // Override default markers
}

// ShouldDetectProjectRoot returns whether project root detection is enabled.
// Returns true by default if DetectProjectRoot is nil.
func (c *PoliciesConfig) ShouldDetectProjectRoot() bool {
	if c.DetectProjectRoot == nil {
		return true // Default enabled
	}
	return *c.DetectProjectRoot
}

// GetProjectMarkers returns custom project markers if configured, or nil to use defaults.
func (c *PoliciesConfig) GetProjectMarkers() []string {
	if len(c.ProjectMarkers) > 0 {
		return c.ProjectMarkers
	}
	return nil // Use defaults from policy package
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

// WebAuthnConfig configures WebAuthn/FIDO2 authentication.
type WebAuthnConfig struct {
	RPID             string   `yaml:"rp_id"`             // e.g., "agentsh.local"
	RPName           string   `yaml:"rp_name"`           // e.g., "agentsh"
	RPOrigins        []string `yaml:"rp_origins"`        // e.g., ["http://localhost:18080"]
	UserVerification string   `yaml:"user_verification"` // preferred, required, discouraged
}

type ApprovalsConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Mode     string         `yaml:"mode"`    // "local_tty", "api", "totp", or "webauthn"
	Timeout  string         `yaml:"timeout"` // duration string, e.g. "5m"
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
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

	// Expand environment variables in config content (e.g., $HOME, ${HOME})
	expanded := os.ExpandEnv(string(b))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	applyEnvOverrides(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadWithSource loads config from path and returns the config along with its source.
// The source parameter indicates where this config path came from.
func LoadWithSource(path string, source ConfigSource) (*Config, ConfigSource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, source, fmt.Errorf("read config: %w", err)
	}

	// Expand environment variables in config content (e.g., $HOME, ${HOME})
	expanded := os.ExpandEnv(string(b))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, source, fmt.Errorf("parse config: %w", err)
	}

	applyDefaultsWithSource(&cfg, source, path)
	applyEnvOverrides(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, source, err
	}
	return &cfg, source, nil
}

// getDefaultDataDir returns the appropriate data directory based on config source.
func getDefaultDataDir(source ConfigSource, configPath string) string {
	switch source {
	case ConfigSourceEnv:
		// Use the directory containing the config file
		if configPath != "" {
			return filepath.Dir(configPath)
		}
		return GetUserDataDir()
	case ConfigSourceUser:
		return GetUserDataDir()
	case ConfigSourceSystem:
		return GetDataDir()
	default:
		return GetDataDir()
	}
}

// getDefaultPoliciesDir returns the appropriate policies directory based on config source.
func getDefaultPoliciesDir(source ConfigSource, configPath string) string {
	switch source {
	case ConfigSourceEnv:
		// Use policies subdir of config file location
		if configPath != "" {
			return filepath.Join(filepath.Dir(configPath), "policies")
		}
		return filepath.Join(GetUserConfigDir(), "policies")
	case ConfigSourceUser:
		return filepath.Join(GetUserConfigDir(), "policies")
	case ConfigSourceSystem:
		return GetPoliciesDir()
	default:
		return GetPoliciesDir()
	}
}

// applyDefaultsWithSource applies default values based on the config source.
// This enables source-aware default path resolution:
// - User config: defaults use ~/.local/share/agentsh/ and ~/.config/agentsh/
// - System config: defaults use /var/lib/agentsh/ and /etc/agentsh/
// - Env config: defaults use the directory containing the config file
func applyDefaultsWithSource(cfg *Config, source ConfigSource, configPath string) {
	dataDir := getDefaultDataDir(source, configPath)
	policiesDir := getDefaultPoliciesDir(source, configPath)

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
		cfg.Server.HTTP.Addr = "0.0.0.0:18080"
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

	// Use source-aware data directory for sessions
	if cfg.Sessions.BaseDir == "" {
		cfg.Sessions.BaseDir = filepath.Join(dataDir, "sessions")
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

	// Unix sockets wrapper defaults to enabled for seccomp enforcement in shim mode.
	// This wraps commands with agentsh-unixwrap which applies seccomp-bpf filters.
	if cfg.Sandbox.UnixSockets.Enabled == nil {
		t := true
		cfg.Sandbox.UnixSockets.Enabled = &t
	}

	// Seccomp defaults
	if cfg.Sandbox.Seccomp.Mode == "" {
		cfg.Sandbox.Seccomp.Mode = "enforce"
	}
	if cfg.Sandbox.Seccomp.Enabled && !cfg.Sandbox.Seccomp.UnixSocket.Enabled {
		// Enable unix socket monitoring by default if seccomp is enabled
		cfg.Sandbox.Seccomp.UnixSocket.Enabled = true
	}
	if cfg.Sandbox.Seccomp.UnixSocket.Action == "" {
		cfg.Sandbox.Seccomp.UnixSocket.Action = "enforce"
	}
	if cfg.Sandbox.Seccomp.Syscalls.DefaultAction == "" {
		cfg.Sandbox.Seccomp.Syscalls.DefaultAction = "allow"
	}
	if cfg.Sandbox.Seccomp.Syscalls.OnBlock == "" {
		cfg.Sandbox.Seccomp.Syscalls.OnBlock = "kill"
	}
	// Default blocked syscalls (dangerous operations)
	if len(cfg.Sandbox.Seccomp.Syscalls.Block) == 0 && cfg.Sandbox.Seccomp.Enabled {
		cfg.Sandbox.Seccomp.Syscalls.Block = []string{
			"ptrace",
			"process_vm_readv",
			"process_vm_writev",
			"personality",
			"mount",
			"umount2",
			"pivot_root",
			"reboot",
			"kexec_load",
			"init_module",
			"finit_module",
			"delete_module",
		}
	}

	// Execve interception defaults - apply when enabled but not fully configured
	if cfg.Sandbox.Seccomp.Execve.Enabled {
		defaults := DefaultExecveConfig()
		if cfg.Sandbox.Seccomp.Execve.MaxArgc == 0 {
			cfg.Sandbox.Seccomp.Execve.MaxArgc = defaults.MaxArgc
		}
		if cfg.Sandbox.Seccomp.Execve.MaxArgvBytes == 0 {
			cfg.Sandbox.Seccomp.Execve.MaxArgvBytes = defaults.MaxArgvBytes
		}
		if cfg.Sandbox.Seccomp.Execve.OnTruncated == "" {
			cfg.Sandbox.Seccomp.Execve.OnTruncated = defaults.OnTruncated
		}
		if cfg.Sandbox.Seccomp.Execve.ApprovalTimeout == 0 {
			cfg.Sandbox.Seccomp.Execve.ApprovalTimeout = defaults.ApprovalTimeout
		}
		if cfg.Sandbox.Seccomp.Execve.ApprovalTimeoutAction == "" {
			cfg.Sandbox.Seccomp.Execve.ApprovalTimeoutAction = defaults.ApprovalTimeoutAction
		}
		if len(cfg.Sandbox.Seccomp.Execve.InternalBypass) == 0 {
			cfg.Sandbox.Seccomp.Execve.InternalBypass = defaults.InternalBypass
		}
	}

	// Cross-server pattern detection defaults
	if cfg.Sandbox.MCP.CrossServer.ReadThenSend.Window == 0 {
		cfg.Sandbox.MCP.CrossServer.ReadThenSend.Window = 30 * time.Second
	}
	if cfg.Sandbox.MCP.CrossServer.Burst.MaxCalls == 0 {
		cfg.Sandbox.MCP.CrossServer.Burst.MaxCalls = 10
	} else if cfg.Sandbox.MCP.CrossServer.Burst.MaxCalls < 0 {
		cfg.Sandbox.MCP.CrossServer.Burst.MaxCalls = 10
	}
	if cfg.Sandbox.MCP.CrossServer.Burst.Window == 0 {
		cfg.Sandbox.MCP.CrossServer.Burst.Window = 5 * time.Second
	}
	if cfg.Sandbox.MCP.CrossServer.CrossServerFlow.Window == 0 {
		cfg.Sandbox.MCP.CrossServer.CrossServerFlow.Window = 30 * time.Second
	}
	// SameTurnOnly defaults to true when not explicitly set.
	if cfg.Sandbox.MCP.CrossServer.CrossServerFlow.SameTurnOnly == nil {
		t := true
		cfg.Sandbox.MCP.CrossServer.CrossServerFlow.SameTurnOnly = &t
	}
	// ShadowTool defaults to enabled when not explicitly set.
	if cfg.Sandbox.MCP.CrossServer.ShadowTool.Enabled == nil {
		t := true
		cfg.Sandbox.MCP.CrossServer.ShadowTool.Enabled = &t
	}

	// macOS XPC defaults
	if cfg.Sandbox.XPC.Mode == "" {
		cfg.Sandbox.XPC.Mode = "enforce"
	}
	if cfg.Sandbox.XPC.MachServices.DefaultAction == "" {
		cfg.Sandbox.XPC.MachServices.DefaultAction = "deny"
	}

	// Use source-aware policies directory
	if cfg.Policies.Dir == "" {
		cfg.Policies.Dir = policiesDir
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

	// Use source-aware data directory for SQLite
	if cfg.Audit.Storage.SQLitePath == "" {
		cfg.Audit.Storage.SQLitePath = filepath.Join(dataDir, "events.db")
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
	// OTEL defaults
	if cfg.Audit.OTEL.Endpoint == "" {
		cfg.Audit.OTEL.Endpoint = "localhost:4317"
	}
	if cfg.Audit.OTEL.Protocol == "" {
		cfg.Audit.OTEL.Protocol = "grpc"
	}
	if cfg.Audit.OTEL.Timeout == "" {
		cfg.Audit.OTEL.Timeout = "10s"
	}
	if !cfg.Audit.OTEL.Signals.Logs && !cfg.Audit.OTEL.Signals.Spans {
		cfg.Audit.OTEL.Signals.Logs = true
		cfg.Audit.OTEL.Signals.Spans = true
	}
	if cfg.Audit.OTEL.Batch.MaxSize == 0 {
		cfg.Audit.OTEL.Batch.MaxSize = 512
	}
	if cfg.Audit.OTEL.Batch.Timeout == "" {
		cfg.Audit.OTEL.Batch.Timeout = "5s"
	}
	if cfg.Audit.OTEL.Resource.ServiceName == "" {
		cfg.Audit.OTEL.Resource.ServiceName = "agentsh"
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

	// Apply proxy defaults field by field
	if cfg.Proxy.Mode == "" {
		cfg.Proxy.Mode = "embedded"
	}
	if cfg.Proxy.Providers.Anthropic == "" {
		cfg.Proxy.Providers.Anthropic = "https://api.anthropic.com"
	}
	if cfg.Proxy.Providers.OpenAI == "" {
		cfg.Proxy.Providers.OpenAI = "https://api.openai.com"
	}
	// Port 0 is valid (means random), so don't override it

	// Apply DLP defaults field by field
	if cfg.DLP.Mode == "" {
		cfg.DLP.Mode = "redact"
	}
	// Note: For DLPPatternsConfig booleans, we can't distinguish between
	// "not set" and "explicitly set to false", so we should only apply
	// defaults if the entire patterns section appears empty
	if !cfg.DLP.Patterns.Email && !cfg.DLP.Patterns.Phone &&
		!cfg.DLP.Patterns.CreditCard && !cfg.DLP.Patterns.SSN &&
		!cfg.DLP.Patterns.APIKeys {
		defaults := DefaultDLPConfig()
		cfg.DLP.Patterns = defaults.Patterns
	}

	// Apply LLM storage defaults field by field
	if cfg.LLMStorage.Retention.MaxAgeDays == 0 {
		cfg.LLMStorage.Retention.MaxAgeDays = 30
	}
	if cfg.LLMStorage.Retention.MaxSizeMB == 0 {
		cfg.LLMStorage.Retention.MaxSizeMB = 500
	}
	if cfg.LLMStorage.Retention.Eviction == "" {
		cfg.LLMStorage.Retention.Eviction = "oldest_first"
	}
	// StoreBodies default is false, which is the zero value, so no need to set

	// Security defaults
	if cfg.Security.Mode == "" {
		cfg.Security.Mode = "auto"
	}
	// Default to warning when running in degraded mode
	if !cfg.Security.WarnDegraded {
		// Only set default if not explicitly set
		// Since we can't distinguish false from unset, default to true for new configs
		cfg.Security.WarnDegraded = true
	}

	// Threat feeds defaults
	if cfg.ThreatFeeds.Action == "" {
		cfg.ThreatFeeds.Action = "deny"
	}
	if cfg.ThreatFeeds.SyncInterval == 0 {
		cfg.ThreatFeeds.SyncInterval = 6 * time.Hour
	}
	if cfg.ThreatFeeds.Realtime.Timeout == 0 {
		cfg.ThreatFeeds.Realtime.Timeout = 500 * time.Millisecond
	}
	if cfg.ThreatFeeds.Realtime.CacheTTL == 0 {
		cfg.ThreatFeeds.Realtime.CacheTTL = 1 * time.Hour
	}
	if cfg.ThreatFeeds.Realtime.OnTimeout == "" {
		cfg.ThreatFeeds.Realtime.OnTimeout = "local-only"
	}
}

// applyDefaults wraps applyDefaultsWithSource for backward compatibility.
func applyDefaults(cfg *Config) {
	applyDefaultsWithSource(cfg, ConfigSourceSystem, "")
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
	// Proxy-specific overrides
	if v := os.Getenv("AGENTSH_PROXY_MODE"); v != "" {
		cfg.Proxy.Mode = v
	}
	if v := os.Getenv("AGENTSH_DLP_MODE"); v != "" {
		cfg.DLP.Mode = v
	}
	if v := os.Getenv("AGENTSH_PROXY_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.Port = port
		}
	}
	// OTEL overrides
	if v := os.Getenv("AGENTSH_OTEL_ENDPOINT"); v != "" {
		cfg.Audit.OTEL.Endpoint = v
	} else if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		cfg.Audit.OTEL.Endpoint = v
	}
	if v := os.Getenv("AGENTSH_OTEL_PROTOCOL"); v != "" {
		cfg.Audit.OTEL.Protocol = v
	}
}

// isSafeFeedName checks that a feed name contains only safe characters.
func isSafeFeedName(name string) bool {
	for _, c := range name {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
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
	// Validate XPC mode
	switch cfg.Sandbox.XPC.Mode {
	case "", "enforce", "audit", "disabled":
	default:
		return fmt.Errorf("invalid sandbox.xpc.mode %q", cfg.Sandbox.XPC.Mode)
	}
	// Validate XPC default_action
	switch cfg.Sandbox.XPC.MachServices.DefaultAction {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("invalid sandbox.xpc.mach_services.default_action %q", cfg.Sandbox.XPC.MachServices.DefaultAction)
	}
	// Validate security mode
	switch cfg.Security.Mode {
	case "", "auto", "full", "landlock", "landlock-only", "minimal":
	default:
		return fmt.Errorf("invalid security.mode %q", cfg.Security.Mode)
	}
	// Validate minimum_mode if specified
	if cfg.Security.MinimumMode != "" {
		switch cfg.Security.MinimumMode {
		case "full", "landlock", "landlock-only", "minimal":
		default:
			return fmt.Errorf("invalid security.minimum_mode %q", cfg.Security.MinimumMode)
		}
	}
	// Validate OTEL config
	if cfg.Audit.OTEL.Enabled {
		switch cfg.Audit.OTEL.Protocol {
		case "grpc", "http":
		default:
			return fmt.Errorf("invalid audit.otel.protocol %q (must be \"grpc\" or \"http\")", cfg.Audit.OTEL.Protocol)
		}
		if cfg.Audit.OTEL.Endpoint == "" {
			return fmt.Errorf("audit.otel.endpoint is required when otel is enabled")
		}
		switch cfg.Audit.OTEL.Filter.MinRiskLevel {
		case "", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid audit.otel.filter.min_risk_level %q", cfg.Audit.OTEL.Filter.MinRiskLevel)
		}
	}
	// Validate threat_feeds config
	if cfg.ThreatFeeds.Action != "" {
		switch cfg.ThreatFeeds.Action {
		case "deny", "audit":
		default:
			return fmt.Errorf("invalid threat_feeds.action %q (must be \"deny\" or \"audit\")", cfg.ThreatFeeds.Action)
		}
	}
	for i, f := range cfg.ThreatFeeds.Feeds {
		if f.Name == "" {
			return fmt.Errorf("threat_feeds.feeds[%d].name must not be empty", i)
		}
		if !isSafeFeedName(f.Name) {
			return fmt.Errorf("invalid threat_feeds.feeds[%d].name %q (must match [A-Za-z0-9._-]+)", i, f.Name)
		}
		if f.URL == "" {
			return fmt.Errorf("threat_feeds.feeds[%d].url must not be empty", i)
		}
		u, err := url.Parse(f.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid threat_feeds.feeds[%d].url %q (must be http or https with a valid host)", i, f.URL)
		}
		switch f.Format {
		case "hostfile", "domain-list":
		case "":
			return fmt.Errorf("threat_feeds.feeds[%d].format must not be empty (use \"hostfile\" or \"domain-list\")", i)
		default:
			return fmt.Errorf("invalid threat_feeds.feeds[%d].format %q (must be \"hostfile\" or \"domain-list\")", i, f.Format)
		}
	}
	feedNames := make(map[string]struct{}, len(cfg.ThreatFeeds.Feeds))
	for i, f := range cfg.ThreatFeeds.Feeds {
		if _, dup := feedNames[f.Name]; dup {
			return fmt.Errorf("duplicate threat_feeds.feeds name %q at index %d", f.Name, i)
		}
		feedNames[f.Name] = struct{}{}
	}
	if cfg.ThreatFeeds.Realtime.OnTimeout != "" {
		switch cfg.ThreatFeeds.Realtime.OnTimeout {
		case "local-only", "allow", "deny":
		default:
			return fmt.Errorf("invalid threat_feeds.realtime.on_timeout %q (must be \"local-only\", \"allow\", or \"deny\")", cfg.ThreatFeeds.Realtime.OnTimeout)
		}
	}
	return nil
}
