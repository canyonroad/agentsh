//go:build windows

package windows

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Job Object limit flags (from Windows SDK)
const (
	JOB_OBJECT_LIMIT_ACTIVE_PROCESS        = 0x00000008
	JOB_OBJECT_LIMIT_AFFINITY              = 0x00000010
	JOB_OBJECT_LIMIT_JOB_MEMORY            = 0x00000200
	JOB_OBJECT_LIMIT_PROCESS_MEMORY        = 0x00000100
	JOB_OBJECT_LIMIT_JOB_TIME              = 0x00000004
	JOB_OBJECT_LIMIT_PROCESS_TIME          = 0x00000002
	JOB_OBJECT_LIMIT_BREAKAWAY_OK          = 0x00000800
	JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK   = 0x00001000
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE     = 0x00002000
	JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
)

// CPU rate control flags (Windows 8+)
const (
	JOB_OBJECT_CPU_RATE_CONTROL_ENABLE   = 0x1
	JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
)

// ResourceLimiter implements platform.ResourceLimiter for Windows.
// Uses Job Objects for process resource limits.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
	handles         map[string]*ResourceHandle
	mu              sync.Mutex
}

// NewResourceLimiter creates a new Windows resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available: true, // Job Objects always available on modern Windows
		handles:   make(map[string]*ResourceHandle),
	}
	r.supportedLimits = r.detectSupportedLimits()
	return r
}

// detectSupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) detectSupportedLimits() []platform.ResourceType {
	// Job Objects support CPU, memory, and process count limits
	return []platform.ResourceType{
		platform.ResourceCPU,
		platform.ResourceMemory,
		platform.ResourceProcessCount,
		platform.ResourceCPUAffinity,
	}
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits using Job Objects.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	if !r.available {
		return nil, fmt.Errorf("resource limiting not available")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	if _, exists := r.handles[config.Name]; exists {
		return nil, fmt.Errorf("resource handle with name %q already exists", config.Name)
	}

	// Create the handle
	handle := &ResourceHandle{
		name:   config.Name,
		config: config,
	}

	// Calculate limit flags and values
	handle.limitFlags = r.calculateLimitFlags(config)
	handle.cpuRate = r.calculateCPURate(config)
	handle.memoryLimit = r.calculateMemoryLimit(config)
	handle.processLimit = r.calculateProcessLimit(config)
	handle.affinityMask = r.calculateAffinityMask(config)

	// Note: Real implementation would:
	// 1. Call windows.CreateJobObject(nil, nil)
	// 2. Set up JOBOBJECT_EXTENDED_LIMIT_INFORMATION with calculated values
	// 3. Call SetInformationJobObject
	// 4. For CPU rate control on Windows 8+, set JOBOBJECT_CPU_RATE_CONTROL_INFORMATION

	r.handles[config.Name] = handle
	return handle, nil
}

// calculateLimitFlags determines which Job Object limits to apply.
func (r *ResourceLimiter) calculateLimitFlags(config platform.ResourceConfig) uint32 {
	var flags uint32

	if config.MaxMemoryMB > 0 {
		flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
	}
	if config.MaxProcesses > 0 {
		flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	}
	if len(config.CPUAffinity) > 0 {
		flags |= JOB_OBJECT_LIMIT_AFFINITY
	}
	// Always kill child processes when job is closed
	flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	return flags
}

// calculateCPURate returns CPU rate limit in 100ths of a percent.
func (r *ResourceLimiter) calculateCPURate(config platform.ResourceConfig) uint32 {
	if config.MaxCPUPercent <= 0 {
		return 0
	}
	// CPU rate is expressed in 100ths of a percent (0-10000)
	rate := config.MaxCPUPercent * 100
	if rate > 10000 {
		rate = 10000
	}
	return rate
}

// calculateMemoryLimit returns memory limit in bytes.
func (r *ResourceLimiter) calculateMemoryLimit(config platform.ResourceConfig) uint64 {
	if config.MaxMemoryMB <= 0 {
		return 0
	}
	return config.MaxMemoryMB * 1024 * 1024
}

// calculateProcessLimit returns the maximum number of processes.
func (r *ResourceLimiter) calculateProcessLimit(config platform.ResourceConfig) uint32 {
	if config.MaxProcesses <= 0 {
		return 0
	}
	return config.MaxProcesses
}

// calculateAffinityMask returns the CPU affinity mask.
func (r *ResourceLimiter) calculateAffinityMask(config platform.ResourceConfig) uint64 {
	if len(config.CPUAffinity) == 0 {
		return 0
	}
	var mask uint64
	for _, cpu := range config.CPUAffinity {
		if cpu >= 0 && cpu < 64 {
			mask |= 1 << cpu
		}
	}
	return mask
}

// GetHandle returns an existing resource handle by name.
func (r *ResourceLimiter) GetHandle(name string) (platform.ResourceHandle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.handles[name]
	return h, ok
}

// Release removes a resource handle.
func (r *ResourceLimiter) Release(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.handles[name]
	if !ok {
		return fmt.Errorf("handle %q not found", name)
	}

	if err := h.Release(); err != nil {
		return err
	}

	delete(r.handles, name)
	return nil
}

// ResourceHandle represents applied resource limits via Job Objects.
type ResourceHandle struct {
	name         string
	config       platform.ResourceConfig
	limitFlags   uint32
	cpuRate      uint32
	memoryLimit  uint64
	processLimit uint32
	affinityMask uint64
	closed       bool
	mu           sync.Mutex
	// Note: Real implementation would store windows.Handle for the Job Object
}

// Name returns the handle name.
func (h *ResourceHandle) Name() string {
	return h.name
}

// AssignProcess adds a process to this Job Object.
func (h *ResourceHandle) AssignProcess(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return fmt.Errorf("job object is closed")
	}

	// Note: Real implementation would:
	// 1. OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE, false, pid)
	// 2. AssignProcessToJobObject(h.handle, procHandle)
	// 3. CloseHandle(procHandle)

	return nil
}

// Stats returns current resource usage from the Job Object.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return platform.ResourceStats{}
	}

	// Note: Real implementation would:
	// 1. QueryInformationJobObject with JobObjectBasicAndIoAccountingInformation
	// 2. Parse JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
	// 3. Return populated ResourceStats

	return platform.ResourceStats{
		MemoryMB:     0,
		CPUPercent:   0,
		ProcessCount: 0,
		DiskReadMB:   0,
		DiskWriteMB:  0,
		NetworkMB:    0,
	}
}

// LimitFlags returns the configured limit flags.
func (h *ResourceHandle) LimitFlags() uint32 {
	return h.limitFlags
}

// CPURate returns the configured CPU rate limit.
func (h *ResourceHandle) CPURate() uint32 {
	return h.cpuRate
}

// MemoryLimit returns the configured memory limit in bytes.
func (h *ResourceHandle) MemoryLimit() uint64 {
	return h.memoryLimit
}

// ProcessLimit returns the configured process limit.
func (h *ResourceHandle) ProcessLimit() uint32 {
	return h.processLimit
}

// AffinityMask returns the configured CPU affinity mask.
func (h *ResourceHandle) AffinityMask() uint64 {
	return h.affinityMask
}

// Release removes the resource limits by closing the Job Object.
func (h *ResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	// Note: Real implementation would CloseHandle(h.handle)
	// Due to KILL_ON_JOB_CLOSE, this terminates all processes in the job

	h.closed = true
	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
