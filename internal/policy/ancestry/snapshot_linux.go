//go:build linux

package ancestry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// captureSnapshotImpl captures process info from /proc on Linux.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Read comm (process name, max 15 chars)
	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	if data, err := os.ReadFile(commPath); err == nil {
		snapshot.Comm = strings.TrimSpace(string(data))
	}

	// Read exe (symlink to executable path)
	exePath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	if target, err := os.Readlink(exePath); err == nil {
		snapshot.ExePath = target
	}

	// Read cmdline (null-separated arguments)
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if data, err := os.ReadFile(cmdlinePath); err == nil && len(data) > 0 {
		// Split by null bytes, remove empty strings
		parts := strings.Split(string(data), "\x00")
		snapshot.Cmdline = make([]string, 0, len(parts))
		for _, p := range parts {
			if p != "" {
				snapshot.Cmdline = append(snapshot.Cmdline, p)
			}
		}
	}

	// Read starttime from stat (field 22, 1-indexed after the comm field)
	// Format: pid (comm) state ppid pgrp session tty_nr tpgid flags
	//         minflt cminflt majflt cmajflt utime stime cutime cstime
	//         priority nice num_threads itrealvalue starttime ...
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/%d/stat: %w", pid, err)
	}

	startTime, err := parseStartTimeFromStat(string(data))
	if err != nil {
		return nil, err
	}
	snapshot.StartTime = startTime

	return snapshot, nil
}

// parseStartTimeFromStat extracts the starttime field from /proc/PID/stat.
// The format is: pid (comm) state ppid ... starttime ...
// where starttime is field 22 (1-indexed from the start, after parsing comm).
func parseStartTimeFromStat(stat string) (uint64, error) {
	// Find the closing ) of comm field (comm can contain spaces and parens)
	closeParenIdx := strings.LastIndex(stat, ")")
	if closeParenIdx < 0 || closeParenIdx+2 >= len(stat) {
		return 0, fmt.Errorf("invalid stat format: no closing paren")
	}

	// Fields after comm start at index closeParenIdx+2
	// Field indices (0-based after comm): 0=state, 1=ppid, ..., 19=starttime
	fields := strings.Fields(stat[closeParenIdx+2:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("invalid stat format: not enough fields")
	}

	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse starttime: %w", err)
	}

	return startTime, nil
}
