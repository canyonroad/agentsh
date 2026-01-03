// Package platform provides cross-platform abstractions for filesystem,
// network, sandbox, and resource management. Each platform (Linux, macOS,
// Windows) implements these interfaces using native primitives.
package platform

import (
	"context"
	"time"
)

// Platform is the main interface for platform-specific implementations.
// Use New() to get the appropriate implementation for the current OS.
type Platform interface {
	// Name returns the platform identifier (e.g., "linux", "darwin", "windows")
	Name() string

	// Capabilities returns what this platform supports
	Capabilities() Capabilities

	// Core components - may return nil if not available on this platform
	Filesystem() FilesystemInterceptor
	Network() NetworkInterceptor
	Sandbox() SandboxManager
	Resources() ResourceLimiter

	// Lifecycle
	Initialize(ctx context.Context, config Config) error
	Shutdown(ctx context.Context) error
}

// FilesystemInterceptor handles FUSE-based (or equivalent) file monitoring and interception.
type FilesystemInterceptor interface {
	// Mount creates a new intercepted filesystem mount
	Mount(config FSConfig) (FSMount, error)

	// Unmount removes a filesystem mount
	Unmount(mount FSMount) error

	// Available returns whether filesystem interception is available
	Available() bool

	// Implementation returns the underlying technology (e.g., "fuse3", "fuse-t", "winfsp")
	Implementation() string
}

// FSMount represents an active filesystem mount with interception enabled.
type FSMount interface {
	// Path returns the mount point path
	Path() string

	// SourcePath returns the underlying real filesystem path
	SourcePath() string

	// Stats returns current mount statistics
	Stats() FSStats

	// Close unmounts and cleans up resources
	Close() error
}

// FSConfig configures a filesystem mount.
type FSConfig struct {
	// SourcePath is the real filesystem path to intercept
	SourcePath string

	// MountPoint is where to mount the intercepted filesystem
	MountPoint string

	// SessionID identifies the session this mount belongs to
	SessionID string

	// CommandIDFunc returns the current command ID (called per-operation)
	CommandIDFunc func() string

	// PolicyEngine evaluates access decisions
	PolicyEngine PolicyEngine

	// EventChannel receives filesystem events
	EventChannel chan<- IOEvent

	// Interceptor handles synchronous interception (hold/redirect/approve)
	Interceptor InterceptionManager

	// TrashConfig configures soft-delete behavior (optional)
	TrashConfig *TrashConfig

	// NotifySoftDelete is called when a file is soft-deleted (optional)
	NotifySoftDelete func(path, token string)

	// Options contains platform-specific mount options
	Options map[string]string
}

// FSStats contains filesystem mount statistics.
type FSStats struct {
	MountedAt     time.Time
	TotalOps      int64
	AllowedOps    int64
	DeniedOps     int64
	RedirectedOps int64
	PendingOps    int64
	BytesRead     int64
	BytesWritten  int64
}

// TrashConfig configures soft-delete behavior.
type TrashConfig struct {
	// Enabled turns on soft-delete (move to trash instead of delete)
	Enabled bool

	// TrashDir is where deleted files are moved
	TrashDir string

	// HashFiles enables computing hashes for trashed files
	HashFiles bool

	// HashAlgorithm specifies hash algorithm ("sha256", "blake3")
	HashAlgorithm string

	// HashLimitBytes is max file size to hash (0 = unlimited)
	HashLimitBytes int64
}

// NetworkInterceptor handles network traffic interception.
type NetworkInterceptor interface {
	// Setup configures network interception
	Setup(config NetConfig) error

	// Teardown removes network interception
	Teardown() error

	// Available returns whether network interception is available
	Available() bool

	// Implementation returns the underlying technology (e.g., "iptables", "pf", "windivert")
	Implementation() string
}

// NetConfig configures network interception.
type NetConfig struct {
	// ProxyPort is the local port for TCP proxy
	ProxyPort int

	// DNSPort is the local port for DNS proxy
	DNSPort int

	// PolicyEngine evaluates access decisions
	PolicyEngine PolicyEngine

	// EventChannel receives network events
	EventChannel chan<- IOEvent

	// Interceptor handles synchronous interception
	Interceptor InterceptionManager

	// InterceptMode controls what traffic to intercept
	InterceptMode InterceptMode
}

// InterceptMode controls network interception behavior.
type InterceptMode int

const (
	// InterceptAll intercepts all network traffic
	InterceptAll InterceptMode = iota

	// InterceptTCPOnly intercepts TCP only (UDP except DNS passes through)
	InterceptTCPOnly

	// InterceptMonitor monitors traffic without redirecting
	InterceptMonitor
)

// SandboxManager handles process isolation.
type SandboxManager interface {
	// Create creates a new sandbox
	Create(config SandboxConfig) (Sandbox, error)

	// Available returns whether sandboxing is available
	Available() bool

	// IsolationLevel returns the isolation capability
	IsolationLevel() IsolationLevel
}

// SandboxConfig configures a sandbox.
type SandboxConfig struct {
	// Name identifies this sandbox
	Name string

	// WorkspacePath is the primary working directory
	WorkspacePath string

	// AllowedPaths are additional paths accessible in the sandbox
	AllowedPaths []string

	// Capabilities are allowed Linux capabilities (or equivalent)
	Capabilities []string

	// Environment variables for the sandbox
	Environment map[string]string

	// WindowsOptions contains Windows-specific options (ignored on other platforms)
	WindowsOptions *WindowsSandboxOptions
}

// NetworkAccessLevel controls network capabilities for Windows AppContainer.
type NetworkAccessLevel int

const (
	// NetworkNone disables all network access
	NetworkNone NetworkAccessLevel = iota
	// NetworkOutbound allows internet client connections only
	NetworkOutbound
	// NetworkLocal allows private network only
	NetworkLocal
	// NetworkFull allows all network access
	NetworkFull
)

// WindowsSandboxOptions contains Windows-specific sandbox configuration.
// These options are ignored on other platforms.
type WindowsSandboxOptions struct {
	// UseAppContainer enables AppContainer isolation (default: true)
	UseAppContainer bool

	// UseMinifilter enables minifilter driver policy enforcement (default: true)
	UseMinifilter bool

	// NetworkAccess controls network capabilities when UseAppContainer is true
	NetworkAccess NetworkAccessLevel

	// FailOnAppContainerError fails hard if AppContainer setup fails (default: true)
	// When false, falls back to restricted token execution
	FailOnAppContainerError bool
}

// DefaultWindowsSandboxOptions returns secure default options.
func DefaultWindowsSandboxOptions() *WindowsSandboxOptions {
	return &WindowsSandboxOptions{
		UseAppContainer:         true,
		UseMinifilter:           true,
		NetworkAccess:           NetworkNone,
		FailOnAppContainerError: true,
	}
}

// Sandbox represents an isolated execution environment.
type Sandbox interface {
	// ID returns the sandbox identifier
	ID() string

	// Execute runs a command in the sandbox
	Execute(ctx context.Context, cmd string, args ...string) (*ExecResult, error)

	// Close destroys the sandbox
	Close() error
}

// ExecResult contains command execution results.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// ResourceLimiter handles resource constraints.
type ResourceLimiter interface {
	// Apply applies resource limits to a process or cgroup
	Apply(config ResourceConfig) (ResourceHandle, error)

	// Available returns whether resource limiting is available
	Available() bool

	// SupportedLimits returns which resource types can be limited
	SupportedLimits() []ResourceType
}

// ResourceConfig configures resource limits.
type ResourceConfig struct {
	// Name identifies this resource limit group
	Name string

	// MaxMemoryMB limits memory usage
	MaxMemoryMB uint64

	// MaxCPUPercent limits CPU usage (100 = 1 core)
	MaxCPUPercent uint32

	// MaxProcesses limits number of processes
	MaxProcesses uint32

	// MaxDiskReadMBps limits disk read bandwidth
	MaxDiskReadMBps uint32

	// MaxDiskWriteMBps limits disk write bandwidth
	MaxDiskWriteMBps uint32

	// MaxNetworkMbps limits network bandwidth
	MaxNetworkMbps uint32

	// CPUAffinity pins to specific CPUs
	CPUAffinity []int
}

// ResourceHandle represents applied resource limits.
type ResourceHandle interface {
	// AssignProcess adds a process to this resource group
	AssignProcess(pid int) error

	// Stats returns current resource usage
	Stats() ResourceStats

	// Release removes the resource limits
	Release() error
}

// ResourceStats contains resource usage information.
type ResourceStats struct {
	MemoryMB     uint64
	CPUPercent   float64
	ProcessCount int
	DiskReadMB   int64
	DiskWriteMB  int64
	NetworkMB    int64
}

// ResourceType identifies a type of resource limit.
type ResourceType int

const (
	ResourceCPU ResourceType = 1 << iota
	ResourceMemory
	ResourceProcessCount
	ResourceDiskIO
	ResourceNetworkBW
	ResourceCPUAffinity
)

// InterceptionManager handles synchronous operation interception.
// Operations can be held pending a policy decision, and may be
// allowed, denied, redirected, or require manual approval.
type InterceptionManager interface {
	// Intercept evaluates an operation and returns a decision.
	// This may block if the operation requires approval.
	Intercept(ctx context.Context, op *InterceptedOperation) DecisionResponse

	// Approve handles an approval decision for a pending operation.
	Approve(opID string, approved bool, redirect *RedirectTarget, approvedBy string) error

	// Pending returns currently pending operations awaiting approval.
	Pending() []*InterceptedOperation
}

// PolicyEngine evaluates policy rules. This interface is implemented
// by the policy package and passed to platform components.
type PolicyEngine interface {
	// CheckFile evaluates file access
	CheckFile(path string, op FileOperation) Decision

	// CheckNetwork evaluates network access
	CheckNetwork(addr string, port int, protocol string) Decision

	// CheckEnv evaluates environment variable access
	CheckEnv(name string, op EnvOperation) Decision

	// CheckCommand evaluates command execution
	CheckCommand(cmd string, args []string) Decision

	// CheckRegistry evaluates Windows registry access (Windows-only)
	CheckRegistry(path string, op string) Decision
}

// Config holds platform initialization configuration.
type Config struct {
	// WorkspacePath is the primary workspace directory
	WorkspacePath string

	// PolicyEngine for access decisions
	PolicyEngine PolicyEngine

	// EventChannel for all platform events
	EventChannel chan<- IOEvent

	// Logger for platform logging (optional, uses default if nil)
	Logger Logger

	// PlatformOptions contains platform-specific options
	PlatformOptions map[string]any
}

// Logger interface for platform logging.
type Logger interface {
	Debug(msg string, fields ...any)
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}
