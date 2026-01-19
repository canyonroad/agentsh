//go:build darwin && !cgo

package ancestry

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// captureSnapshotImpl captures process info using ps commands on macOS (nocgo fallback).
//
// LIMITATION: StartTime has only second-level precision.
// This implementation calculates StartTime from `ps -o etime=` (elapsed time),
// which only has second-level precision. This means:
// - Two calls for the same PID could return StartTime values differing by 1 second
//   if they straddle a second boundary
// - ValidateSnapshot() may have rare false positives (< 1 in 86400 per day of uptime)
//
// For more reliable start times, build with cgo enabled to use sysctl directly.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Get process info using ps
	// ps -o comm=,lstart= -p <pid>
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %w", err)
	}
	snapshot.Comm = strings.TrimSpace(string(out))

	// Get executable path using ps
	out, err = exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err == nil {
		cmdline := strings.TrimSpace(string(out))
		if cmdline != "" {
			parts := strings.Fields(cmdline)
			if len(parts) > 0 {
				snapshot.ExePath = parts[0]
				snapshot.Cmdline = parts
			}
		}
	}

	// Get start time using ps -o etime (elapsed time) and convert to approximate start time
	out, err = exec.Command("ps", "-o", "etime=", "-p", strconv.Itoa(pid)).Output()
	if err == nil {
		etime := strings.TrimSpace(string(out))
		// Parse elapsed time and subtract from current time
		// Format: [[DD-]hh:]mm:ss
		snapshot.StartTime = parseEtimeToStartTime(etime)
	}

	return snapshot, nil
}

// parseEtimeToStartTime converts ps etime format to a start time value.
// Format: [[DD-]hh:]mm:ss
// Returns a value that's consistent for the same process (for comparison purposes).
func parseEtimeToStartTime(etime string) uint64 {
	// Parse the elapsed time components
	var days, hours, minutes, seconds int

	// Check for days format: DD-hh:mm:ss
	if strings.Contains(etime, "-") {
		parts := strings.SplitN(etime, "-", 2)
		fmt.Sscanf(parts[0], "%d", &days)
		etime = parts[1]
	}

	// Parse hh:mm:ss or mm:ss
	parts := strings.Split(etime, ":")
	switch len(parts) {
	case 3:
		fmt.Sscanf(parts[0], "%d", &hours)
		fmt.Sscanf(parts[1], "%d", &minutes)
		fmt.Sscanf(parts[2], "%d", &seconds)
	case 2:
		fmt.Sscanf(parts[0], "%d", &minutes)
		fmt.Sscanf(parts[1], "%d", &seconds)
	}

	// Calculate total elapsed seconds
	totalSeconds := days*86400 + hours*3600 + minutes*60 + seconds

	// Get current time and subtract elapsed time
	// This gives approximate start time in Unix epoch seconds
	now := time.Now().Unix()
	return uint64(now - int64(totalSeconds))
}
