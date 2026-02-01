//go:build windows

package windows

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/agentsh/agentsh/internal/platform"
	"golang.org/x/sys/windows"
)

// Job Object limit flags (from Windows SDK)
const (
	JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008
	JOB_OBJECT_LIMIT_AFFINITY                   = 0x00000010
	JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200
	JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100
	JOB_OBJECT_LIMIT_JOB_TIME                   = 0x00000004
	JOB_OBJECT_LIMIT_PROCESS_TIME               = 0x00000002
	JOB_OBJECT_LIMIT_BREAKAWAY_OK               = 0x00000800
	JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        = 0x00001000
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000
	JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
)

// CPU rate control flags (Windows 8+)
const (
	JOB_OBJECT_CPU_RATE_CONTROL_ENABLE   = 0x1
	JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4
)

// JobObjectInfoClass values for QueryInformationJobObject/SetInformationJobObject
const (
	jobObjectBasicAndIoAccountingInformation = 8
	jobObjectExtendedLimitInformation        = 9
	jobObjectCpuRateControlInformation       = 15
)

// jobobjectBasicAccountingInformation matches JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
type jobobjectBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// jobobjectBasicAndIoAccountingInformation matches JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
type jobobjectBasicAndIoAccountingInformation struct {
	BasicInfo jobobjectBasicAccountingInformation
	IoInfo    windows.IO_COUNTERS
}

// jobobjectCpuRateControlInformation matches JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
type jobobjectCpuRateControlInformation struct {
	ControlFlags uint32
	CpuRate      uint32
}

// processMemoryCounters matches PROCESS_MEMORY_COUNTERS
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")
)

func getProcessMemoryInfo(process windows.Handle, memCounters *processMemoryCounters, cb uint32) error {
	ret, _, err := procGetProcessMemoryInfo.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(memCounters)),
		uintptr(cb),
	)
	if ret == 0 {
		return err
	}
	return nil
}

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

	// Create a Job Object
	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}

	// Create the handle
	handle := &ResourceHandle{
		name:      config.Name,
		config:    config,
		jobHandle: jobHandle,
	}

	// Calculate limit flags and values
	handle.limitFlags = r.calculateLimitFlags(config)
	handle.cpuRate = r.calculateCPURate(config)
	handle.memoryLimit = r.calculateMemoryLimit(config)
	handle.processLimit = r.calculateProcessLimit(config)
	handle.affinityMask = r.calculateAffinityMask(config)

	// Set up JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var extendedInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	extendedInfo.BasicLimitInformation.LimitFlags = handle.limitFlags

	// Memory limit (job-wide and per-process)
	if handle.memoryLimit > 0 {
		extendedInfo.JobMemoryLimit = uintptr(handle.memoryLimit)
		extendedInfo.ProcessMemoryLimit = uintptr(handle.memoryLimit)
	}

	// Active process limit
	if handle.processLimit > 0 {
		extendedInfo.BasicLimitInformation.ActiveProcessLimit = handle.processLimit
	}

	// CPU affinity
	if handle.affinityMask > 0 {
		extendedInfo.BasicLimitInformation.Affinity = uintptr(handle.affinityMask)
	}

	// Apply extended limits
	_, err = windows.SetInformationJobObject(
		jobHandle,
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&extendedInfo)),
		uint32(unsafe.Sizeof(extendedInfo)),
	)
	if err != nil {
		windows.CloseHandle(jobHandle)
		return nil, fmt.Errorf("SetInformationJobObject (extended limits): %w", err)
	}

	// Apply CPU rate control (Windows 8+)
	if handle.cpuRate > 0 {
		cpuRateInfo := jobobjectCpuRateControlInformation{
			ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
			CpuRate:      handle.cpuRate,
		}
		// CPU rate control may fail on older Windows - ignore error
		_, _ = windows.SetInformationJobObject(
			jobHandle,
			jobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpuRateInfo)),
			uint32(unsafe.Sizeof(cpuRateInfo)),
		)
	}

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
	// Only set affinity flag if we have valid CPUs that produce a non-zero mask
	if len(config.CPUAffinity) > 0 {
		mask := r.calculateAffinityMask(config)
		if mask != 0 {
			flags |= JOB_OBJECT_LIMIT_AFFINITY
		}
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
	jobHandle    windows.Handle
	limitFlags   uint32
	cpuRate      uint32
	memoryLimit  uint64
	processLimit uint32
	affinityMask uint64
	pids         []int // Track assigned process IDs for Stats()
	closed       bool
	mu           sync.Mutex
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

	if h.jobHandle == 0 {
		return fmt.Errorf("job object handle is invalid")
	}

	// Open the process with required access rights
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(process)

	// Assign the process to this job object
	if err := windows.AssignProcessToJobObject(h.jobHandle, process); err != nil {
		return fmt.Errorf("AssignProcessToJobObject(%d): %w", pid, err)
	}

	// Track the PID for Stats()
	h.pids = append(h.pids, pid)

	return nil
}

// Stats returns current resource usage from the Job Object.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed || h.jobHandle == 0 {
		return platform.ResourceStats{}
	}

	stats := platform.ResourceStats{}

	// Query job object accounting information
	var info jobobjectBasicAndIoAccountingInformation
	var retLen uint32
	err := windows.QueryInformationJobObject(
		h.jobHandle,
		jobObjectBasicAndIoAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&retLen,
	)
	if err == nil {
		stats.ProcessCount = int(info.BasicInfo.ActiveProcesses)
		// CPU time in 100ns units, convert to approximate percentage
		// This is cumulative time, not instantaneous percentage
		totalTime := info.BasicInfo.TotalUserTime + info.BasicInfo.TotalKernelTime
		stats.CPUPercent = float64(totalTime) / 10000000.0 // Convert 100ns to seconds
		stats.DiskReadMB = int64(info.IoInfo.ReadTransferCount) / 1024 / 1024
		stats.DiskWriteMB = int64(info.IoInfo.WriteTransferCount) / 1024 / 1024
	}

	// Get memory usage from the first tracked PID
	if len(h.pids) > 0 {
		for _, pid := range h.pids {
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
			if err != nil {
				continue
			}
			var memCounters processMemoryCounters
			memCounters.CB = uint32(unsafe.Sizeof(memCounters))
			if err := getProcessMemoryInfo(process, &memCounters, memCounters.CB); err == nil {
				stats.MemoryMB += uint64(memCounters.WorkingSetSize) / 1024 / 1024
			}
			windows.CloseHandle(process)
		}
	}

	return stats
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

// JobHandle returns the Windows Job Object handle for testing.
func (h *ResourceHandle) JobHandle() windows.Handle {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.jobHandle
}

// IsActive returns true if the job object has active processes.
func (h *ResourceHandle) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed || h.jobHandle == 0 {
		return false
	}

	var info jobobjectBasicAndIoAccountingInformation
	var retLen uint32
	err := windows.QueryInformationJobObject(
		h.jobHandle,
		jobObjectBasicAndIoAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&retLen,
	)
	if err != nil {
		return false
	}

	return info.BasicInfo.ActiveProcesses > 0
}

// Release removes the resource limits by closing the Job Object.
// Due to JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, this terminates all processes in the job.
func (h *ResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	if h.jobHandle != 0 {
		// Closing the handle terminates all processes due to KILL_ON_JOB_CLOSE flag
		if err := windows.CloseHandle(h.jobHandle); err != nil {
			return fmt.Errorf("CloseHandle: %w", err)
		}
		h.jobHandle = 0
	}

	// Mark closed only after successful cleanup
	h.closed = true
	h.pids = nil
	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
