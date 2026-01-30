//go:build darwin && cgo

package darwin

/*
#include <libproc.h>
#include <sys/resource.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ProcRusage contains resource usage information for a process.
type ProcRusage struct {
	UserTime     uint64 // User CPU time in Mach absolute time units
	SystemTime   uint64 // System CPU time in Mach absolute time units
	ResidentSize uint64 // Resident memory size in bytes
}

// getProcRusage retrieves resource usage for a process using proc_pid_rusage.
func getProcRusage(pid int) (*ProcRusage, error) {
	var ri C.struct_rusage_info_v3

	ret := C.proc_pid_rusage(C.int(pid), C.RUSAGE_INFO_V3, (*C.rusage_info_t)(unsafe.Pointer(&ri)))
	if ret != 0 {
		return nil, fmt.Errorf("proc_pid_rusage failed for pid %d: returned %d", pid, ret)
	}

	return &ProcRusage{
		UserTime:     uint64(ri.ri_user_time),
		SystemTime:   uint64(ri.ri_system_time),
		ResidentSize: uint64(ri.ri_resident_size),
	}, nil
}
