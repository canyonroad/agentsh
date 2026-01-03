//go:build darwin

package limits

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/platform/darwin"
	"golang.org/x/sys/unix"
)

// DarwinLimiter implements ResourceLimiter using setrlimit and process control.
type DarwinLimiter struct {
	sessions    map[int]*darwinSession
	machMonitor *darwin.MachMonitor
	mu          sync.Mutex
}

type darwinSession struct {
	pid    int
	limits ResourceLimits
}

// NewDarwinLimiter creates a new macOS resource limiter.
func NewDarwinLimiter() *DarwinLimiter {
	return &DarwinLimiter{
		sessions:    make(map[int]*darwinSession),
		machMonitor: darwin.NewMachMonitor(),
	}
}

// Apply implements ResourceLimiter.
// Note: On macOS, limits can only be set for the current process via setrlimit.
// For external processes, we use renice and other available tools.
func (l *DarwinLimiter) Apply(pid int, limits ResourceLimits) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sessions[pid] = &darwinSession{
		pid:    pid,
		limits: limits,
	}

	// For external processes, we can only apply limited controls
	if pid != 0 && pid != unix.Getpid() {
		return l.applyExternal(pid, limits)
	}

	// For current process, use setrlimit
	return l.applySelf(limits)
}

func (l *DarwinLimiter) applySelf(limits ResourceLimits) error {
	// Memory limit (RLIMIT_AS - address space)
	if limits.MaxMemoryMB > 0 {
		var rLimit unix.Rlimit
		rLimit.Cur = uint64(limits.MaxMemoryMB) * 1024 * 1024
		rLimit.Max = rLimit.Cur
		if err := unix.Setrlimit(unix.RLIMIT_AS, &rLimit); err != nil {
			return fmt.Errorf("setrlimit AS: %w", err)
		}
	}

	// CPU time limit (RLIMIT_CPU) - in seconds
	if limits.CommandTimeout > 0 {
		var rLimit unix.Rlimit
		rLimit.Cur = uint64(limits.CommandTimeout.Seconds())
		rLimit.Max = rLimit.Cur + 60 // Grace period
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &rLimit); err != nil {
			return fmt.Errorf("setrlimit CPU: %w", err)
		}
	}

	// File size limit (RLIMIT_FSIZE)
	if limits.MaxDiskMB > 0 {
		var rLimit unix.Rlimit
		rLimit.Cur = uint64(limits.MaxDiskMB) * 1024 * 1024
		rLimit.Max = rLimit.Cur
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &rLimit); err != nil {
			return fmt.Errorf("setrlimit FSIZE: %w", err)
		}
	}

	// Process limit (RLIMIT_NPROC)
	if limits.MaxProcesses > 0 {
		var rLimit unix.Rlimit
		rLimit.Cur = uint64(limits.MaxProcesses)
		rLimit.Max = rLimit.Cur
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &rLimit); err != nil {
			return fmt.Errorf("setrlimit NPROC: %w", err)
		}
	}

	return nil
}

func (l *DarwinLimiter) applyExternal(pid int, limits ResourceLimits) error {
	// For external processes on macOS, options are limited
	// We can use renice for CPU priority

	if limits.CPUShares > 0 {
		// Lower priority = less CPU (nice 0-20)
		// Convert shares (0-100) to nice value (20-0)
		nice := 20 - int(limits.CPUShares*20/100)
		if nice < 0 {
			nice = 0
		}
		if nice > 20 {
			nice = 20
		}
		_ = exec.Command("renice", strconv.Itoa(nice), "-p", strconv.Itoa(pid)).Run()
	}

	return nil
}

// Usage implements ResourceLimiter.
func (l *DarwinLimiter) Usage(pid int) (*ResourceUsage, error) {
	l.mu.Lock()
	_, ok := l.sessions[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no session for pid %d", pid)
	}

	usage := &ResourceUsage{}

	// Use MachMonitor for process info (faster than spawning ps)
	info, err := l.machMonitor.GetProcessInfo(pid)
	if err != nil {
		// Process may have exited
		return usage, nil
	}

	// Convert bytes to MB
	usage.MemoryMB = int64(info.ResidentSize / (1024 * 1024))
	usage.ThreadCount = info.NumThreads

	// Get CPU percentage (requires two samples over time)
	cpuPct, err := l.machMonitor.GetCPUPercent(pid)
	if err == nil {
		usage.CPUPercent = cpuPct
	}

	// Count child processes (still need pgrep for this)
	childOut, err := exec.Command("pgrep", "-P", strconv.Itoa(pid)).Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(childOut)), "\n")
		if lines[0] != "" {
			usage.ProcessCount = len(lines) + 1 // Include parent
		} else {
			usage.ProcessCount = 1
		}
	} else {
		usage.ProcessCount = 1
	}

	return usage, nil
}

// CheckLimits implements ResourceLimiter.
func (l *DarwinLimiter) CheckLimits(pid int) (*LimitViolation, error) {
	l.mu.Lock()
	session, ok := l.sessions[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no session for pid %d", pid)
	}

	usage, err := l.Usage(pid)
	if err != nil {
		return nil, err
	}

	// Check memory limit
	if session.limits.MaxMemoryMB > 0 && usage.MemoryMB > session.limits.MaxMemoryMB {
		return &LimitViolation{
			Resource: "memory",
			Limit:    session.limits.MaxMemoryMB,
			Current:  usage.MemoryMB,
			Action:   "warn",
		}, nil
	}

	// Check process limit
	if session.limits.MaxProcesses > 0 && usage.ProcessCount > session.limits.MaxProcesses {
		return &LimitViolation{
			Resource: "pids",
			Limit:    int64(session.limits.MaxProcesses),
			Current:  int64(usage.ProcessCount),
			Action:   "warn",
		}, nil
	}

	return nil, nil
}

// Cleanup implements ResourceLimiter.
func (l *DarwinLimiter) Cleanup(pid int) error {
	l.mu.Lock()
	delete(l.sessions, pid)
	l.mu.Unlock()

	// Clean up Mach monitor samples for this process
	l.machMonitor.Cleanup(pid)

	return nil
}

// Capabilities implements ResourceLimiter.
func (l *DarwinLimiter) Capabilities() LimiterCapabilities {
	return LimiterCapabilities{
		MemoryHard:    true,  // RLIMIT_AS (self only)
		MemorySoft:    false,
		Swap:          false,
		CPUQuota:      false,
		CPUShares:     true,  // renice
		ProcessCount:  true,  // RLIMIT_NPROC (self only)
		CPUTime:       true,  // RLIMIT_CPU (self only)
		DiskIORate:    false,
		DiskQuota:     true,  // RLIMIT_FSIZE (self only)
		NetworkRate:   false,
		ChildTracking: false, // Must track manually
	}
}

// Ensure interface compliance
var _ ResourceLimiter = (*DarwinLimiter)(nil)
