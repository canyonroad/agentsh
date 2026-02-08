// internal/platform/windows/ntdll_windows.go
//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                  = windows.NewLazySystemDLL("ntdll.dll")
	procNtResumeProcess    = ntdll.NewProc("NtResumeProcess")
	procNtSuspendProcess   = ntdll.NewProc("NtSuspendProcess")
	procNtTerminateProcess = ntdll.NewProc("NtTerminateProcess")
)

// ResumeProcessByPID resumes all threads in a process using NtResumeProcess.
func ResumeProcessByPID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	r, _, _ := procNtResumeProcess.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("NtResumeProcess: NTSTATUS 0x%08X", r)
	}
	return nil
}

// SuspendProcessByPID suspends all threads in a process using NtSuspendProcess.
func SuspendProcessByPID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	r, _, _ := procNtSuspendProcess.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("NtSuspendProcess: NTSTATUS 0x%08X", r)
	}
	return nil
}

// TerminateProcessByPID terminates a process using NtTerminateProcess.
func TerminateProcessByPID(pid uint32, exitCode uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	r, _, _ := procNtTerminateProcess.Call(uintptr(h), uintptr(exitCode))
	if r != 0 {
		return fmt.Errorf("NtTerminateProcess: NTSTATUS 0x%08X", r)
	}
	return nil
}

// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is the attribute key for specifying
// a parent process when creating a new process.
const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

// CreateProcessAsChild spawns a new process as a child of the specified parent PID
// using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. This preserves the parent-child
// relationship when redirecting a suspended process to a stub.
func CreateProcessAsChild(parentPID uint32, appName, cmdLine string, env []string, workDir string, inheritHandles bool, extraHandles []uintptr) (uint32, error) {
	parentHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, parentPID)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess parent(%d): %w", parentPID, err)
	}
	defer windows.CloseHandle(parentHandle)

	// Initialize proc thread attribute list with one attribute
	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, fmt.Errorf("NewProcThreadAttributeList: %w", err)
	}
	defer attrList.Delete()

	err = attrList.Update(
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		unsafe.Pointer(&parentHandle),
		unsafe.Sizeof(parentHandle),
	)
	if err != nil {
		return 0, fmt.Errorf("UpdateProcThreadAttribute: %w", err)
	}

	var appNamePtr *uint16
	if appName != "" {
		appNamePtr, err = windows.UTF16PtrFromString(appName)
		if err != nil {
			return 0, err
		}
	}
	cmdLinePtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, err
	}

	var workDirPtr *uint16
	if workDir != "" {
		workDirPtr, err = windows.UTF16PtrFromString(workDir)
		if err != nil {
			return 0, err
		}
	}

	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
		},
		ProcThreadAttributeList: attrList.List(),
	}

	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)

	// Build environment block
	var envBlock *uint16
	if len(env) > 0 {
		envBlock = createEnvBlock(env)
	}

	err = windows.CreateProcess(
		appNamePtr,
		cmdLinePtr,
		nil, // process security attributes
		nil, // thread security attributes
		inheritHandles,
		flags,
		envBlock,
		workDirPtr,
		&si.StartupInfo,
		&pi,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateProcess: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	return pi.ProcessId, nil
}

// createEnvBlock creates a null-terminated environment block from string pairs.
func createEnvBlock(env []string) *uint16 {
	var block []uint16
	for _, s := range env {
		u, _ := windows.UTF16FromString(s)
		block = append(block, u...)
	}
	block = append(block, 0) // Double null terminator
	return &block[0]
}
