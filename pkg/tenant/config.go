package tenant

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrTenantExists       = errors.New("tenant already exists")
	ErrInvalidTenantID    = errors.New("invalid tenant ID")
	ErrQuotaExceeded      = errors.New("tenant quota exceeded")
	ErrTenantDisabled     = errors.New("tenant is disabled")
	ErrInvalidUIDRange    = errors.New("invalid UID range")
	ErrInvalidStorageSize = errors.New("invalid storage size")
)

// tenantIDRe validates tenant IDs
var tenantIDRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

// TenantConfig defines configuration for a tenant/organization.
type TenantConfig struct {
	// TenantID is the unique identifier for this tenant.
	TenantID string `yaml:"tenant_id" json:"tenant_id"`

	// Name is a human-readable name for the tenant.
	Name string `yaml:"name" json:"name"`

	// Enabled indicates if the tenant is currently active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Isolation contains filesystem, network, and process isolation settings.
	Isolation IsolationConfig `yaml:"isolation" json:"isolation"`

	// Quotas contains resource limits for the tenant.
	Quotas TenantQuotas `yaml:"quotas" json:"quotas"`

	// PolicyOverrides contains policy settings that override defaults.
	PolicyOverrides map[string]any `yaml:"policy_overrides,omitempty" json:"policy_overrides,omitempty"`

	// DefaultTrustLevel is the default trust level for agents in this tenant.
	DefaultTrustLevel string `yaml:"default_trust_level,omitempty" json:"default_trust_level,omitempty"`

	// AllowedAuthMethods restricts which auth methods can be used.
	AllowedAuthMethods []string `yaml:"allowed_auth_methods,omitempty" json:"allowed_auth_methods,omitempty"`

	// Metadata contains additional key-value pairs.
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// CreatedAt is when the tenant was created.
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`

	// UpdatedAt is when the tenant was last updated.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`
}

// IsolationConfig defines isolation settings for a tenant.
type IsolationConfig struct {
	// WorkspaceRoot is the base directory for tenant workspaces.
	// Supports template variables: {tenant_id}, {agent_id}, {session_id}
	WorkspaceRoot string `yaml:"workspace_root" json:"workspace_root"`

	// SharedReadOnly contains paths that are readable by all tenants.
	SharedReadOnly []string `yaml:"shared_readonly,omitempty" json:"shared_readonly,omitempty"`

	// NetworkNamespace indicates whether to use separate network namespaces.
	NetworkNamespace bool `yaml:"network_namespace" json:"network_namespace"`

	// AllowedEgress contains hosts/CIDRs allowed for outbound connections.
	AllowedEgress []string `yaml:"allowed_egress,omitempty" json:"allowed_egress,omitempty"`

	// DeniedEgress contains hosts/CIDRs explicitly denied for outbound connections.
	DeniedEgress []string `yaml:"denied_egress,omitempty" json:"denied_egress,omitempty"`

	// UIDRange defines the UID range for tenant processes [start, end].
	UIDRange [2]int `yaml:"uid_range,omitempty" json:"uid_range,omitempty"`

	// GIDRange defines the GID range for tenant processes [start, end].
	GIDRange [2]int `yaml:"gid_range,omitempty" json:"gid_range,omitempty"`

	// MaxProcesses limits the number of concurrent processes per session.
	MaxProcesses int `yaml:"max_processes" json:"max_processes"`

	// Seccomp enables seccomp filtering for tenant processes.
	Seccomp bool `yaml:"seccomp" json:"seccomp"`

	// SeccompProfile is the path to a custom seccomp profile.
	SeccompProfile string `yaml:"seccomp_profile,omitempty" json:"seccomp_profile,omitempty"`
}

// TenantQuotas defines resource limits for a tenant.
type TenantQuotas struct {
	// MaxConcurrentSessions limits concurrent sessions for the tenant.
	MaxConcurrentSessions int `yaml:"max_concurrent_sessions" json:"max_concurrent_sessions"`

	// MaxConcurrentAgents limits concurrent agents for the tenant.
	MaxConcurrentAgents int `yaml:"max_concurrent_agents" json:"max_concurrent_agents"`

	// MaxSessionDuration limits how long a session can run.
	MaxSessionDuration time.Duration `yaml:"max_session_duration" json:"max_session_duration"`

	// MaxStorageBytes limits total storage usage for the tenant.
	MaxStorageBytes int64 `yaml:"max_storage_bytes" json:"max_storage_bytes"`

	// MaxNetworkBytesPerDay limits daily network transfer.
	MaxNetworkBytesPerDay int64 `yaml:"max_network_bytes_per_day" json:"max_network_bytes_per_day"`

	// MaxAPICallsPerHour limits API calls per hour.
	MaxAPICallsPerHour int `yaml:"max_api_calls_per_hour" json:"max_api_calls_per_hour"`

	// MaxCPUPercent limits CPU usage as a percentage (0-100).
	MaxCPUPercent int `yaml:"max_cpu_percent" json:"max_cpu_percent"`

	// MaxMemoryBytes limits memory usage per session.
	MaxMemoryBytes int64 `yaml:"max_memory_bytes" json:"max_memory_bytes"`

	// MaxFileDescriptors limits open file descriptors per session.
	MaxFileDescriptors int `yaml:"max_file_descriptors" json:"max_file_descriptors"`
}

// NewTenantConfig creates a new tenant configuration with defaults.
func NewTenantConfig(tenantID, name string) (*TenantConfig, error) {
	if !tenantIDRe.MatchString(tenantID) {
		return nil, ErrInvalidTenantID
	}

	now := time.Now().UTC()
	return &TenantConfig{
		TenantID:  tenantID,
		Name:      name,
		Enabled:   true,
		Isolation: DefaultIsolationConfig(tenantID),
		Quotas:    DefaultQuotas(),
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// DefaultIsolationConfig returns sensible default isolation settings.
func DefaultIsolationConfig(tenantID string) IsolationConfig {
	return IsolationConfig{
		WorkspaceRoot:    filepath.Join("/var/agentsh/tenants", tenantID),
		SharedReadOnly:   []string{"/usr/share", "/etc/ssl/certs"},
		NetworkNamespace: true,
		AllowedEgress:    []string{}, // Empty means use default policy
		MaxProcesses:     100,
		Seccomp:          true,
	}
}

// DefaultQuotas returns sensible default quotas.
func DefaultQuotas() TenantQuotas {
	return TenantQuotas{
		MaxConcurrentSessions: 10,
		MaxConcurrentAgents:   5,
		MaxSessionDuration:    24 * time.Hour,
		MaxStorageBytes:       10 * 1024 * 1024 * 1024, // 10 GB
		MaxNetworkBytesPerDay: 1 * 1024 * 1024 * 1024,  // 1 GB
		MaxAPICallsPerHour:    10000,
		MaxCPUPercent:         80,
		MaxMemoryBytes:        4 * 1024 * 1024 * 1024, // 4 GB
		MaxFileDescriptors:    1024,
	}
}

// Validate checks if the tenant configuration is valid.
func (c *TenantConfig) Validate() error {
	if !tenantIDRe.MatchString(c.TenantID) {
		return ErrInvalidTenantID
	}

	if err := c.Isolation.Validate(); err != nil {
		return err
	}

	if err := c.Quotas.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate checks if the isolation config is valid.
func (i *IsolationConfig) Validate() error {
	// Validate UID range if set
	if i.UIDRange[0] != 0 || i.UIDRange[1] != 0 {
		if i.UIDRange[0] < 1000 || i.UIDRange[1] < i.UIDRange[0] {
			return ErrInvalidUIDRange
		}
	}

	// Validate GID range if set
	if i.GIDRange[0] != 0 || i.GIDRange[1] != 0 {
		if i.GIDRange[0] < 1000 || i.GIDRange[1] < i.GIDRange[0] {
			return ErrInvalidUIDRange
		}
	}

	return nil
}

// Validate checks if the quotas are valid.
func (q *TenantQuotas) Validate() error {
	if q.MaxStorageBytes < 0 {
		return ErrInvalidStorageSize
	}
	if q.MaxMemoryBytes < 0 {
		return ErrInvalidStorageSize
	}
	return nil
}

// WorkspacePath returns the workspace path for a specific session.
func (c *TenantConfig) WorkspacePath(agentID, sessionID string) string {
	path := c.Isolation.WorkspaceRoot
	path = strings.ReplaceAll(path, "{tenant_id}", c.TenantID)
	path = strings.ReplaceAll(path, "{agent_id}", agentID)
	path = strings.ReplaceAll(path, "{session_id}", sessionID)
	return path
}

// IsEgressAllowed checks if egress to the given host is allowed.
func (c *TenantConfig) IsEgressAllowed(host string) bool {
	// Check denied list first
	for _, denied := range c.Isolation.DeniedEgress {
		if matchHost(host, denied) {
			return false
		}
	}

	// If allowed list is empty, use default policy (allow)
	if len(c.Isolation.AllowedEgress) == 0 {
		return true
	}

	// Check allowed list
	for _, allowed := range c.Isolation.AllowedEgress {
		if matchHost(host, allowed) {
			return true
		}
	}

	return false
}

// matchHost checks if a host matches a pattern (supports wildcards).
func matchHost(host, pattern string) bool {
	// Simple wildcard matching
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return host == pattern
}

// TenantUsage tracks current resource usage for a tenant.
type TenantUsage struct {
	TenantID string `json:"tenant_id"`

	// Current counts
	ActiveSessions int   `json:"active_sessions"`
	ActiveAgents   int   `json:"active_agents"`
	StorageBytes   int64 `json:"storage_bytes"`

	// Daily counters (reset at midnight UTC)
	NetworkBytesToday int64     `json:"network_bytes_today"`
	APICallsThisHour  int       `json:"api_calls_this_hour"`
	LastResetDate     time.Time `json:"last_reset_date"`
	LastResetHour     int       `json:"last_reset_hour"`
}

// NewTenantUsage creates a new usage tracker for a tenant.
func NewTenantUsage(tenantID string) *TenantUsage {
	now := time.Now().UTC()
	return &TenantUsage{
		TenantID:      tenantID,
		LastResetDate: now.Truncate(24 * time.Hour),
		LastResetHour: now.Hour(),
	}
}

// CheckAndResetCounters resets daily/hourly counters if needed.
func (u *TenantUsage) CheckAndResetCounters() {
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)

	// Reset daily counter
	if today.After(u.LastResetDate) {
		u.NetworkBytesToday = 0
		u.LastResetDate = today
	}

	// Reset hourly counter
	if now.Hour() != u.LastResetHour {
		u.APICallsThisHour = 0
		u.LastResetHour = now.Hour()
	}
}

// CanStartSession checks if starting a new session is allowed within quotas.
func (u *TenantUsage) CanStartSession(quotas TenantQuotas) error {
	u.CheckAndResetCounters()

	if quotas.MaxConcurrentSessions > 0 && u.ActiveSessions >= quotas.MaxConcurrentSessions {
		return ErrQuotaExceeded
	}
	return nil
}

// CanRegisterAgent checks if registering a new agent is allowed within quotas.
func (u *TenantUsage) CanRegisterAgent(quotas TenantQuotas) error {
	if quotas.MaxConcurrentAgents > 0 && u.ActiveAgents >= quotas.MaxConcurrentAgents {
		return ErrQuotaExceeded
	}
	return nil
}

// CanMakeAPICall checks if making an API call is allowed within quotas.
func (u *TenantUsage) CanMakeAPICall(quotas TenantQuotas) error {
	u.CheckAndResetCounters()

	if quotas.MaxAPICallsPerHour > 0 && u.APICallsThisHour >= quotas.MaxAPICallsPerHour {
		return ErrQuotaExceeded
	}
	return nil
}

// RecordAPICall increments the API call counter.
func (u *TenantUsage) RecordAPICall() {
	u.CheckAndResetCounters()
	u.APICallsThisHour++
}

// RecordNetworkBytes adds to the network bytes counter.
func (u *TenantUsage) RecordNetworkBytes(bytes int64) {
	u.CheckAndResetCounters()
	u.NetworkBytesToday += bytes
}
