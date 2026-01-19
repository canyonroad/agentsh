//go:build windows

package ancestry

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// captureSnapshotImpl captures process info using Windows APIs.
func captureSnapshotImpl(pid int) (*ProcessSnapshot, error) {
	snapshot := &ProcessSnapshot{}

	// Open process handle
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(handle)

	// Get executable path
	exePath, err := getProcessImageName(handle)
	if err == nil {
		snapshot.ExePath = exePath
	}

	// Get process name from executable path
	if exePath != "" {
		snapshot.Comm = getBaseName(exePath)
	}

	// Get process creation time
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	err = windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime)
	if err != nil {
		return nil, fmt.Errorf("GetProcessTimes failed: %w", err)
	}

	// Convert FILETIME to uint64 (100-nanosecond intervals since 1601)
	snapshot.StartTime = uint64(creationTime.HighDateTime)<<32 | uint64(creationTime.LowDateTime)

	// Get command line (requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
	snapshot.Cmdline = getProcessCmdline(uint32(pid))

	return snapshot, nil
}

func getProcessImageName(handle windows.Handle) (string, error) {
	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))

	err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}

	return syscall.UTF16ToString(buf[:size]), nil
}

func getBaseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func getProcessCmdline(pid uint32) []string {
	// Getting the command line on Windows requires reading from the
	// target process's PEB (Process Environment Block), which requires
	// PROCESS_VM_READ access. This is complex and may fail for elevated
	// processes, so we use a simplified approach via toolhelp snapshot.
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}

	for {
		if entry.ProcessID == pid {
			// ExeFile is just the executable name, not full command line
			exeName := syscall.UTF16ToString(entry.ExeFile[:])
			return []string{exeName}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return nil
}
