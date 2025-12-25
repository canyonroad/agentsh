//go:build linux

package limits

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LinuxLimiter implements ResourceLimiter using cgroups v2.
type LinuxLimiter struct {
	basePath string
	sessions map[int]*CgroupV2
	mu       sync.Mutex
}

// NewLinuxLimiter creates a new Linux resource limiter.
// basePath is the cgroup directory to use (e.g., "agentsh").
func NewLinuxLimiter(basePath string) (*LinuxLimiter, error) {
	if !DetectCgroupV2() {
		return nil, fmt.Errorf("cgroups v2 not available")
	}

	parentDir, err := CurrentCgroupDir()
	if err != nil {
		return nil, fmt.Errorf("get current cgroup: %w", err)
	}

	return &LinuxLimiter{
		basePath: filepath.Join(parentDir, basePath),
		sessions: make(map[int]*CgroupV2),
	}, nil
}

// Apply implements ResourceLimiter.
func (l *LinuxLimiter) Apply(pid int, limits ResourceLimits) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Convert ResourceLimits to CgroupV2Limits
	cgLimits := CgroupV2Limits{
		MaxMemoryBytes: limits.MaxMemoryMB * 1024 * 1024,
		CPUQuotaPct:    limits.CPUQuotaPercent,
		PidsMax:        limits.MaxProcesses,
	}

	name := fmt.Sprintf("session-%d", pid)
	cg, err := ApplyCgroupV2(l.basePath, name, pid, cgLimits)
	if err != nil {
		return err
	}

	l.sessions[pid] = cg

	// Apply swap limit if supported
	if limits.MaxSwapMB >= 0 && cg.Path != "" {
		swapMax := filepath.Join(cg.Path, "memory.swap.max")
		swapBytes := limits.MaxSwapMB * 1024 * 1024
		_ = os.WriteFile(swapMax, []byte(strconv.FormatInt(swapBytes, 10)), 0o644)
	}

	// Apply I/O limits if supported
	if limits.MaxDiskReadMBps > 0 || limits.MaxDiskWriteMBps > 0 {
		l.applyIOLimits(cg.Path, limits)
	}

	return nil
}

func (l *LinuxLimiter) applyIOLimits(cgroupPath string, limits ResourceLimits) {
	device := l.getRootDevice()
	if device == "" {
		return
	}

	ioMax := filepath.Join(cgroupPath, "io.max")
	rbps := limits.MaxDiskReadMBps * 1024 * 1024
	wbps := limits.MaxDiskWriteMBps * 1024 * 1024
	value := fmt.Sprintf("%s rbps=%d wbps=%d", device, rbps, wbps)
	_ = os.WriteFile(ioMax, []byte(value), 0o644)
}

func (l *LinuxLimiter) getRootDevice() string {
	// Parse /proc/self/mountinfo to find root device
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[4] == "/" {
			// fields[2] is major:minor
			return fields[2]
		}
	}
	return ""
}

// Usage implements ResourceLimiter.
func (l *LinuxLimiter) Usage(pid int) (*ResourceUsage, error) {
	l.mu.Lock()
	cg, ok := l.sessions[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no session for pid %d", pid)
	}

	usage := &ResourceUsage{}

	// Memory usage
	memCurrent := filepath.Join(cg.Path, "memory.current")
	if data, err := os.ReadFile(memCurrent); err == nil {
		s := strings.TrimSpace(string(data))
		if bytes, err := strconv.ParseInt(s, 10, 64); err == nil {
			usage.MemoryMB = bytes / 1024 / 1024
		}
	}

	// CPU usage from cpu.stat
	cpuStat := filepath.Join(cg.Path, "cpu.stat")
	if data, err := os.ReadFile(cpuStat); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "usage_usec ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if usec, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						// Convert to percentage (rough estimate)
						usage.CPUPercent = float64(usec) / 1000000.0
					}
				}
			}
		}
	}

	// Process count
	procsFile := filepath.Join(cg.Path, "cgroup.procs")
	if data, err := os.ReadFile(procsFile); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		usage.ProcessCount = len(lines)
		if lines[0] == "" {
			usage.ProcessCount = 0
		}
	}

	// I/O stats from io.stat
	ioStat := filepath.Join(cg.Path, "io.stat")
	if data, err := os.ReadFile(ioStat); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			for _, f := range fields {
				if strings.HasPrefix(f, "rbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "rbytes="), 10, 64); err == nil {
						usage.DiskReadMB += v / 1024 / 1024
					}
				}
				if strings.HasPrefix(f, "wbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "wbytes="), 10, 64); err == nil {
						usage.DiskWriteMB += v / 1024 / 1024
					}
				}
			}
		}
	}

	return usage, nil
}

// CheckLimits implements ResourceLimiter.
func (l *LinuxLimiter) CheckLimits(pid int) (*LimitViolation, error) {
	l.mu.Lock()
	cg, ok := l.sessions[pid]
	l.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("no session for pid %d", pid)
	}

	// Check memory.events for OOM
	memEvents := filepath.Join(cg.Path, "memory.events")
	if data, err := os.ReadFile(memEvents); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "oom_kill ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if count, _ := strconv.Atoi(parts[1]); count > 0 {
						return &LimitViolation{
							Resource: "memory",
							Action:   "kill",
						}, nil
					}
				}
			}
		}
	}

	// Check pids.events
	pidsEvents := filepath.Join(cg.Path, "pids.events")
	if data, err := os.ReadFile(pidsEvents); err == nil {
		if strings.Contains(string(data), "max ") {
			parts := strings.Fields(string(data))
			for i, p := range parts {
				if p == "max" && i+1 < len(parts) {
					if count, _ := strconv.Atoi(parts[i+1]); count > 0 {
						return &LimitViolation{
							Resource: "pids",
							Action:   "throttle",
						}, nil
					}
				}
			}
		}
	}

	return nil, nil
}

// Cleanup implements ResourceLimiter.
func (l *LinuxLimiter) Cleanup(pid int) error {
	l.mu.Lock()
	cg, ok := l.sessions[pid]
	if ok {
		delete(l.sessions, pid)
	}
	l.mu.Unlock()

	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return cg.Close(ctx)
}

// Capabilities implements ResourceLimiter.
func (l *LinuxLimiter) Capabilities() LimiterCapabilities {
	return LimiterCapabilities{
		MemoryHard:    true,
		MemorySoft:    true, // memory.high
		Swap:          true,
		CPUQuota:      true,
		CPUShares:     true,
		ProcessCount:  true,
		CPUTime:       true,
		DiskIORate:    true,
		DiskQuota:     false, // Requires filesystem quotas
		NetworkRate:   false, // Requires tc/netfilter
		ChildTracking: true,  // Cgroups track automatically
	}
}

// Ensure interface compliance
var _ ResourceLimiter = (*LinuxLimiter)(nil)
