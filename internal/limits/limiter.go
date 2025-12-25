package limits

import (
	"time"
)

// ResourceLimits defines constraints for a session/command.
type ResourceLimits struct {
	// Memory
	MaxMemoryMB int64 `yaml:"max_memory_mb"`
	MaxSwapMB   int64 `yaml:"max_swap_mb"`

	// CPU
	CPUQuotaPercent int   `yaml:"cpu_quota_percent"` // % of one CPU
	CPUPeriodUS     int64 `yaml:"cpu_period_us"`     // Period in microseconds
	CPUShares       int64 `yaml:"cpu_shares"`        // Relative weight

	// Process
	MaxProcesses int `yaml:"max_processes"` // pids.max
	MaxThreads   int `yaml:"max_threads"`

	// I/O
	MaxDiskReadMBps  int64 `yaml:"max_disk_read_mbps"`
	MaxDiskWriteMBps int64 `yaml:"max_disk_write_mbps"`
	MaxDiskMB        int64 `yaml:"max_disk_mb"` // Total disk quota

	// Network
	MaxNetSendMBps int64 `yaml:"max_net_send_mbps"`
	MaxNetRecvMBps int64 `yaml:"max_net_recv_mbps"`
	MaxNetMB       int64 `yaml:"max_net_mb"` // Total transfer quota

	// Time
	CommandTimeout time.Duration `yaml:"command_timeout"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
}

// ResourceUsage represents current resource consumption.
type ResourceUsage struct {
	MemoryMB      int64
	CPUPercent    float64
	DiskReadMB    int64
	DiskWriteMB   int64
	NetSentMB     int64
	NetReceivedMB int64
	ProcessCount  int
	ThreadCount   int
}

// LimitViolation describes a resource limit that was exceeded.
type LimitViolation struct {
	Resource string // "memory", "cpu", "pids", etc.
	Limit    int64
	Current  int64
	Action   string // "warn", "throttle", "kill"
}

// ResourceLimiter applies and monitors resource limits for processes.
type ResourceLimiter interface {
	// Apply limits to a process/session.
	Apply(pid int, limits ResourceLimits) error

	// Usage returns current resource usage for a process.
	Usage(pid int) (*ResourceUsage, error)

	// CheckLimits checks if any limits are exceeded.
	CheckLimits(pid int) (*LimitViolation, error)

	// Cleanup releases resources associated with a process.
	Cleanup(pid int) error

	// Capabilities returns which limits are supported on this platform.
	Capabilities() LimiterCapabilities
}

// LimiterCapabilities describes what limits are supported.
type LimiterCapabilities struct {
	MemoryHard    bool // Hard memory limit
	MemorySoft    bool // Soft memory limit (warning)
	Swap          bool // Swap limit
	CPUQuota      bool // CPU quota (hard cap)
	CPUShares     bool // CPU shares (relative weight)
	ProcessCount  bool // Process/PID limit
	CPUTime       bool // CPU time limit
	DiskIORate    bool // Disk I/O rate limiting
	DiskQuota     bool // Disk space quota
	NetworkRate   bool // Network rate limiting
	ChildTracking bool // Automatic child process tracking
}
