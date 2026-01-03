//go:build darwin && !cgo

package darwin

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// getProcessTaskInfo retrieves task information for a process.
// This is the fallback implementation using ps when CGO is disabled.
// It's slower than the CGO version but doesn't require CGO support.
func getProcessTaskInfo(pid int) (*ProcessTaskInfo, error) {
	// Use ps to get process info
	// -o rss=       Resident set size in KB
	// -o vsz=       Virtual size in KB
	// -o time=      CPU time in HH:MM:SS or MM:SS format
	// -o nlwp=      Number of threads (not available on all macOS versions)
	// -o pri=       Priority
	out, err := exec.Command("ps", "-o", "rss=,vsz=,time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, fmt.Errorf("ps failed for pid %d: %w (process may not exist)", pid, err)
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected ps output for pid %d: %q", pid, string(out))
	}

	info := &ProcessTaskInfo{}

	// Parse RSS (in KB, convert to bytes)
	if rss, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
		info.ResidentSize = rss * 1024
	}

	// Parse VSZ (in KB, convert to bytes)
	if vsz, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
		info.VirtualSize = vsz * 1024
	}

	// Parse CPU time (format: HH:MM:SS.ss or MM:SS.ss)
	cpuTimeNs := parseCPUTime(fields[2])
	info.UserTime = cpuTimeNs // ps gives total CPU time, can't distinguish user/system
	info.SystemTime = 0
	info.TotalTime = cpuTimeNs

	// Try to get thread count with a separate ps call
	// macOS ps doesn't have nlwp, so we use different approach
	threadOut, err := exec.Command("ps", "-M", "-p", strconv.Itoa(pid)).Output()
	if err == nil {
		// Count lines (excluding header) to get thread count
		lines := strings.Split(strings.TrimSpace(string(threadOut)), "\n")
		if len(lines) > 1 {
			info.NumThreads = len(lines) - 1 // Subtract header line
		} else {
			info.NumThreads = 1
		}
	} else {
		info.NumThreads = 1 // Default to 1 if we can't determine
	}

	// Priority (not easily available via ps on macOS, default to 0)
	info.Priority = 0

	return info, nil
}

// parseCPUTime parses CPU time from ps output format.
// Format can be: HH:MM:SS.ss, MM:SS.ss, or SS.ss
// Returns nanoseconds.
func parseCPUTime(timeStr string) uint64 {
	// Remove any trailing microseconds/centiseconds after decimal
	parts := strings.Split(timeStr, ".")
	mainPart := parts[0]
	var fractionalNs uint64
	if len(parts) > 1 {
		// Parse fractional seconds (centiseconds)
		if frac, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
			// Assume 2 digits = centiseconds
			fractionalNs = frac * 10_000_000 // centiseconds to nanoseconds
		}
	}

	// Parse main time part (HH:MM:SS or MM:SS or SS)
	timeParts := strings.Split(mainPart, ":")
	var totalSeconds uint64

	switch len(timeParts) {
	case 3: // HH:MM:SS
		if h, err := strconv.ParseUint(timeParts[0], 10, 64); err == nil {
			totalSeconds += h * 3600
		}
		if m, err := strconv.ParseUint(timeParts[1], 10, 64); err == nil {
			totalSeconds += m * 60
		}
		if s, err := strconv.ParseUint(timeParts[2], 10, 64); err == nil {
			totalSeconds += s
		}
	case 2: // MM:SS
		if m, err := strconv.ParseUint(timeParts[0], 10, 64); err == nil {
			totalSeconds += m * 60
		}
		if s, err := strconv.ParseUint(timeParts[1], 10, 64); err == nil {
			totalSeconds += s
		}
	case 1: // SS
		if s, err := strconv.ParseUint(timeParts[0], 10, 64); err == nil {
			totalSeconds += s
		}
	}

	return totalSeconds*1_000_000_000 + fractionalNs
}
