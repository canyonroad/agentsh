//go:build !linux && !darwin && !windows

package ancestry

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// captureSnapshotImpl is a fallback implementation using ps for unsupported platforms.
//
// LIMITATION: StartTime is unreliable on this platform.
// This implementation uses the current time as an approximation, which means:
// - Multiple calls for the same PID will return different StartTime values
// - ValidateSnapshot() cannot reliably detect PID reuse
// - This may allow false positives in taint validation
//
// For production use, prefer Linux, macOS, or Windows where real start times
// are available from the kernel.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Check if process exists
	if _, err := os.FindProcess(pid); err != nil {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	// Try to get process info using ps (POSIX standard)
	// ps -o comm=,args= -p <pid>
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %w", err)
	}
	snapshot.Comm = strings.TrimSpace(string(out))

	// Get full command line
	out, err = exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
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

	// Use current time as approximation for start time
	// This is a fallback - proper platforms should provide real start time
	snapshot.StartTime = uint64(time.Now().UnixNano())

	return snapshot, nil
}
