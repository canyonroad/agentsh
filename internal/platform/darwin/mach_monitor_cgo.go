//go:build darwin && cgo

package darwin

/*
#include <libproc.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <errno.h>

// Mach time conversion: proc_pidinfo returns CPU times in Mach absolute time units.
// We need to convert to nanoseconds for consistent cross-platform usage.
static mach_timebase_info_data_t timebase_info;
static int timebase_initialized = 0;

static void ensure_timebase_initialized() {
    if (!timebase_initialized) {
        mach_timebase_info(&timebase_info);
        timebase_initialized = 1;
    }
}

// Convert Mach absolute time to nanoseconds
static uint64_t mach_time_to_nanos(uint64_t mach_time) {
    ensure_timebase_initialized();
    return mach_time * timebase_info.numer / timebase_info.denom;
}

// Get process task info via proc_pidinfo (PROC_PIDTASKINFO flavor).
// Returns 0 on success, -1 on error with errno set.
static int get_proc_taskinfo(
    int pid,
    uint64_t *resident_size,
    uint64_t *virtual_size,
    uint64_t *user_time_ns,
    uint64_t *system_time_ns,
    int *num_threads,
    int *priority
) {
    struct proc_taskinfo info;
    int len = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof(info));

    if (len != sizeof(info)) {
        // Error: either process doesn't exist or permission denied
        return -1;
    }

    *resident_size = info.pti_resident_size;
    *virtual_size = info.pti_virtual_size;
    *user_time_ns = mach_time_to_nanos(info.pti_total_user);
    *system_time_ns = mach_time_to_nanos(info.pti_total_system);
    *num_threads = info.pti_threadnum;
    *priority = info.pti_priority;

    return 0;
}
*/
import "C"

import (
	"fmt"
)

// getProcessTaskInfo retrieves task information for a process using Mach APIs.
// This is the CGO implementation using proc_pidinfo().
func getProcessTaskInfo(pid int) (*ProcessTaskInfo, error) {
	var (
		residentSize C.uint64_t
		virtualSize  C.uint64_t
		userTimeNs   C.uint64_t
		systemTimeNs C.uint64_t
		numThreads   C.int
		priority     C.int
	)

	ret := C.get_proc_taskinfo(
		C.int(pid),
		&residentSize,
		&virtualSize,
		&userTimeNs,
		&systemTimeNs,
		&numThreads,
		&priority,
	)

	if ret != 0 {
		return nil, fmt.Errorf("proc_pidinfo failed for pid %d: process may not exist or permission denied", pid)
	}

	userTime := uint64(userTimeNs)
	sysTime := uint64(systemTimeNs)

	return &ProcessTaskInfo{
		ResidentSize: uint64(residentSize),
		VirtualSize:  uint64(virtualSize),
		UserTime:     userTime,
		SystemTime:   sysTime,
		TotalTime:    userTime + sysTime,
		NumThreads:   int(numThreads),
		Priority:     int(priority),
	}, nil
}
