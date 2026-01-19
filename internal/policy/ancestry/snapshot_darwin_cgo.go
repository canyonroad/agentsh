//go:build darwin && cgo

package ancestry

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/*
#include <sys/sysctl.h>
#include <libproc.h>
*/
import "C"

// captureSnapshotImpl captures process info using sysctl and libproc on macOS.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Get process info using sysctl
	info, err := getProcessInfo(pid)
	if err != nil {
		return nil, err
	}

	snapshot.Comm = info.comm
	snapshot.StartTime = info.startTime

	// Get executable path using proc_pidpath
	snapshot.ExePath = getExePath(pid)

	// Get command line arguments using ps (libproc doesn't expose this easily)
	snapshot.Cmdline = getCmdline(pid)

	return snapshot, nil
}

type darwinProcessInfo struct {
	comm      string
	startTime uint64
}

func getProcessInfo(pid int) (*darwinProcessInfo, error) {
	// Use KERN_PROC_PID to get process info
	mib := []int32{C.CTL_KERN, C.KERN_PROC, C.KERN_PROC_PID, int32(pid)}

	var info C.struct_kinfo_proc
	size := C.size_t(unsafe.Sizeof(info))

	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("sysctl failed: %v", errno)
	}

	// Extract comm (process name)
	comm := C.GoString(&info.kp_proc.p_comm[0])

	// Extract start time (seconds since epoch)
	startTime := uint64(info.kp_proc.p_starttime.tv_sec)

	return &darwinProcessInfo{
		comm:      comm,
		startTime: startTime,
	}, nil
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
