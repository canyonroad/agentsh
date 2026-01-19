//go:build darwin && cgo

package ancestry

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

// captureSnapshotImpl captures process info using libproc on macOS.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Get process info using proc_pidinfo
	var info C.struct_proc_bsdinfo
	ret := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0,
		unsafe.Pointer(&info), C.int(unsafe.Sizeof(info)))
	if ret <= 0 {
		return nil, fmt.Errorf("proc_pidinfo failed for pid %d", pid)
	}

	// Extract comm (process name)
	snapshot.Comm = C.GoString(&info.pbi_comm[0])

	// Extract start time (seconds since epoch)
	snapshot.StartTime = uint64(info.pbi_start_tvsec)

	// Get executable path using proc_pidpath
	snapshot.ExePath = getExePath(pid)

	// Get command line arguments using ps (libproc doesn't expose this easily)
	snapshot.Cmdline = getCmdline(pid)

	return snapshot, nil
}

func getExePath(pid int) string {
	buf := make([]byte, 4096)
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return ""
	}
	return string(buf[:ret])
}

func getCmdline(pid int) []string {
	// Use ps to get command line (more reliable than proc_pidinfo for args)
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil
	}
	cmdline := strings.TrimSpace(string(out))
	if cmdline == "" {
		return nil
	}
	return strings.Fields(cmdline)
}
