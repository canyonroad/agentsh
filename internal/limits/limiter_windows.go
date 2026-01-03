//go:build windows

package limits

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsLimiter implements ResourceLimiter using Windows Job Objects.
type WindowsLimiter struct {
	jobs map[int]windows.Handle
	mu   sync.Mutex
}

// Job Object constants not in x/sys/windows
const (
	jobObjectCpuRateControlInformation         = 15
	jobObjectBasicAndIoAccountingInformation   = 8
	jobObjectExtendedLimitInformation          = 9
	jobObjectCpuRateControlEnable              = 0x1
	jobObjectCpuRateControlHardCap             = 0x4
	jobObjectLimitJobMemory                    = 0x00000200
	jobObjectLimitProcessMemory                = 0x00000100
	jobObjectLimitProcessTime                  = 0x00000002
	jobObjectLimitActiveProcess                = 0x00000008
)

type jobObjectCpuRateControlInformationStruct struct {
	ControlFlags uint32
	CpuRate      uint32
}

// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION is not in x/sys/windows
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

type jobObjectBasicAndIoAccountingInformationStruct struct {
	BasicInfo jobobjectBasicAccountingInformation
	IoInfo    windows.IO_COUNTERS
}

// PROCESS_MEMORY_COUNTERS is not in x/sys/windows
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
	modpsapi                = windows.NewLazySystemDLL("psapi.dll")
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

// getProcessThreadCount returns the number of threads for a process using Toolhelp32.
func getProcessThreadCount(pid int) int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	count := 0
	err = windows.Thread32First(snapshot, &te)
	for err == nil {
		if te.OwnerProcessID == uint32(pid) {
			count++
		}
		err = windows.Thread32Next(snapshot, &te)
	}
	return count
}

// NewWindowsLimiter creates a new Windows resource limiter.
func NewWindowsLimiter() *WindowsLimiter {
	return &WindowsLimiter{
		jobs: make(map[int]windows.Handle),
	}
}

// Apply implements ResourceLimiter.
func (l *WindowsLimiter) Apply(pid int, limits ResourceLimits) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create a Job Object
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err)
	}

	// Set extended limits
	var extendedInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	// Memory limit (job-wide)
	if limits.MaxMemoryMB > 0 {
		extendedInfo.JobMemoryLimit = uintptr(limits.MaxMemoryMB * 1024 * 1024)
		extendedInfo.BasicLimitInformation.LimitFlags |= jobObjectLimitJobMemory

		// Also set per-process memory limit
		extendedInfo.ProcessMemoryLimit = uintptr(limits.MaxMemoryMB * 1024 * 1024)
		extendedInfo.BasicLimitInformation.LimitFlags |= jobObjectLimitProcessMemory
	}

	// CPU time limit (per process, in 100ns units)
	if limits.CommandTimeout > 0 {
		extendedInfo.BasicLimitInformation.PerProcessUserTimeLimit = int64(limits.CommandTimeout.Nanoseconds() / 100)
		extendedInfo.BasicLimitInformation.LimitFlags |= jobObjectLimitProcessTime
	}

	// Active process limit
	if limits.MaxProcesses > 0 {
		extendedInfo.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcesses)
		extendedInfo.BasicLimitInformation.LimitFlags |= jobObjectLimitActiveProcess
	}

	// Set the limits
	_, err = windows.SetInformationJobObject(
		job,
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&extendedInfo)),
		uint32(unsafe.Sizeof(extendedInfo)),
	)
	if err != nil {
		windows.CloseHandle(job)
		return fmt.Errorf("SetInformationJobObject: %w", err)
	}

	// CPU rate limit (Windows 8+)
	if limits.CPUQuotaPercent > 0 {
		var cpuRateInfo jobObjectCpuRateControlInformationStruct
		cpuRateInfo.ControlFlags = jobObjectCpuRateControlEnable | jobObjectCpuRateControlHardCap
		cpuRateInfo.CpuRate = uint32(limits.CPUQuotaPercent * 100) // In hundredths of percent

		_, _ = windows.SetInformationJobObject(
			job,
			jobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpuRateInfo)),
			uint32(unsafe.Sizeof(cpuRateInfo)),
		)
	}

	// Open the process
	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		windows.CloseHandle(job)
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(process)

	// Assign process to job
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		windows.CloseHandle(job)
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}

	l.jobs[pid] = job
	return nil
}

// Usage implements ResourceLimiter.
func (l *WindowsLimiter) Usage(pid int) (*ResourceUsage, error) {
	l.mu.Lock()
	job, ok := l.jobs[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no job for pid %d", pid)
	}

	var info jobObjectBasicAndIoAccountingInformationStruct
	var retLen uint32
	err := windows.QueryInformationJobObject(
		job,
		jobObjectBasicAndIoAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&retLen,
	)
	if err != nil {
		return nil, fmt.Errorf("QueryInformationJobObject: %w", err)
	}

	usage := &ResourceUsage{
		ProcessCount: int(info.BasicInfo.ActiveProcesses),
		// CPU time in 100ns units, convert to percentage estimate
		CPUPercent:  float64(info.BasicInfo.TotalUserTime+info.BasicInfo.TotalKernelTime) / 10000000.0,
		DiskReadMB:  int64(info.IoInfo.ReadTransferCount) / 1024 / 1024,
		DiskWriteMB: int64(info.IoInfo.WriteTransferCount) / 1024 / 1024,
	}

	// Get memory usage via process query
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err == nil {
		defer windows.CloseHandle(process)
		var memCounters processMemoryCounters
		memCounters.CB = uint32(unsafe.Sizeof(memCounters))
		if err := getProcessMemoryInfo(process, &memCounters, memCounters.CB); err == nil {
			usage.MemoryMB = int64(memCounters.WorkingSetSize) / 1024 / 1024
		}
	}

	// Get thread count via Toolhelp32
	usage.ThreadCount = getProcessThreadCount(pid)

	return usage, nil
}

// CheckLimits implements ResourceLimiter.
func (l *WindowsLimiter) CheckLimits(pid int) (*LimitViolation, error) {
	l.mu.Lock()
	job, ok := l.jobs[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no job for pid %d", pid)
	}

	var info jobObjectBasicAndIoAccountingInformationStruct
	var retLen uint32
	err := windows.QueryInformationJobObject(
		job,
		jobObjectBasicAndIoAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&retLen,
	)
	if err != nil {
		return nil, err
	}

	// Check if processes were terminated due to limits
	if info.BasicInfo.TotalTerminatedProcesses > 0 {
		return &LimitViolation{
			Resource: "process",
			Current:  int64(info.BasicInfo.TotalTerminatedProcesses),
			Action:   "kill",
		}, nil
	}

	return nil, nil
}

// Cleanup implements ResourceLimiter.
func (l *WindowsLimiter) Cleanup(pid int) error {
	l.mu.Lock()
	job, ok := l.jobs[pid]
	if ok {
		delete(l.jobs, pid)
	}
	l.mu.Unlock()

	if ok && job != 0 {
		// Terminate all processes in the job
		_ = windows.TerminateJobObject(job, 0)
		windows.CloseHandle(job)
	}
	return nil
}

// Capabilities implements ResourceLimiter.
func (l *WindowsLimiter) Capabilities() LimiterCapabilities {
	return LimiterCapabilities{
		MemoryHard:    true,  // JobMemoryLimit
		MemorySoft:    false,
		Swap:          false,
		CPUQuota:      true,  // CpuRate (Windows 8+)
		CPUShares:     false,
		ProcessCount:  true,  // ActiveProcessLimit
		CPUTime:       true,  // PerProcessUserTimeLimit
		DiskIORate:    false,
		DiskQuota:     false,
		NetworkRate:   false,
		ChildTracking: true,  // Job objects track automatically
	}
}

// Ensure interface compliance
var _ ResourceLimiter = (*WindowsLimiter)(nil)
