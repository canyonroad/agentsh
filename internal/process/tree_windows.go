//go:build windows

package process

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JOBOBJECT_BASIC_PROCESS_ID_LIST for querying process IDs in a job.
type jobObjectBasicProcessIDList struct {
	NumberOfAssignedProcesses  uint32
	NumberOfProcessIdsInList   uint32
	ProcessIdList              [1]uintptr // Variable length array
}

const jobObjectBasicProcessIdList = 3 // JobObjectBasicProcessIdList info class

// WindowsProcessTracker implements ProcessTracker using Windows Job Objects.
type WindowsProcessTracker struct {
	rootPID   int
	jobHandle windows.Handle
	known     map[int]bool
	mu        sync.RWMutex
	spawnCb   func(pid, ppid int)
	exitCb    func(pid, exitCode int)
	done      chan struct{}
}

func newPlatformTracker() ProcessTracker {
	return &WindowsProcessTracker{
		known: make(map[int]bool),
		done:  make(chan struct{}),
	}
}

// Track implements ProcessTracker.
func (t *WindowsProcessTracker) Track(pid int) error {
	t.rootPID = pid
	t.known[pid] = true

	// Try to create a Job Object for automatic child tracking
	if err := t.setupJobObject(pid); err != nil {
		// Fall back to polling
		go t.poll()
		return nil
	}

	go t.poll() // Still poll for process info updates
	return nil
}

func (t *WindowsProcessTracker) setupJobObject(pid int) error {
	// Create job object
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	t.jobHandle = job

	// Configure job to kill all processes when job closes
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		windows.CloseHandle(job)
		return err
	}

	// Open the target process
	proc, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(pid),
	)
	if err != nil {
		windows.CloseHandle(job)
		return err
	}
	defer windows.CloseHandle(proc)

	// Assign process to job
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return err
	}

	return nil
}

func (t *WindowsProcessTracker) poll() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.scanProcesses()
		}
	}
}

func (t *WindowsProcessTracker) scanProcesses() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If we have a job object, get processes from it
	if t.jobHandle != 0 {
		pids := t.getJobProcesses()
		currentPids := make(map[int]bool)
		for _, pid := range pids {
			currentPids[pid] = true
			if !t.known[pid] {
				t.known[pid] = true
				ppid := t.getPPID(pid)
				if t.spawnCb != nil {
					t.spawnCb(pid, ppid)
				}
			}
		}

		// Check for exits
		for pid := range t.known {
			if pid == t.rootPID {
				continue
			}
			if !currentPids[pid] {
				delete(t.known, pid)
				if t.exitCb != nil {
					t.exitCb(pid, 0)
				}
			}
		}
		return
	}

	// Fallback: scan for children using CreateToolhelp32Snapshot
	t.scanWithToolhelp()
}

func (t *WindowsProcessTracker) getJobProcesses() []int {
	if t.jobHandle == 0 {
		return nil
	}

	// Query job object for process list
	// Start with buffer for 64 processes
	bufSize := uint32(unsafe.Sizeof(jobObjectBasicProcessIDList{}) + 64*unsafe.Sizeof(uintptr(0)))
	buf := make([]byte, bufSize)

	for {
		err := windows.QueryInformationJobObject(
			t.jobHandle,
			jobObjectBasicProcessIdList,
			uintptr(unsafe.Pointer(&buf[0])),
			bufSize,
			nil,
		)
		if err == nil {
			break
		}
		if err == windows.ERROR_MORE_DATA {
			bufSize *= 2
			buf = make([]byte, bufSize)
			continue
		}
		return nil
	}

	// Parse the result
	list := (*jobObjectBasicProcessIDList)(unsafe.Pointer(&buf[0]))
	pids := make([]int, 0, list.NumberOfProcessIdsInList)

	// The ProcessIdList starts after the header
	pidPtr := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Offsetof(list.ProcessIdList)
	for i := uint32(0); i < list.NumberOfProcessIdsInList; i++ {
		pid := *(*uintptr)(unsafe.Pointer(pidPtr + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		pids = append(pids, int(pid))
	}

	return pids
}

func (t *WindowsProcessTracker) scanWithToolhelp() {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return
	}

	for {
		pid := int(entry.ProcessID)
		ppid := int(entry.ParentProcessID)

		if !t.known[pid] && t.known[ppid] {
			t.known[pid] = true
			if t.spawnCb != nil {
				t.spawnCb(pid, ppid)
			}
		}

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	// Check for exits
	for pid := range t.known {
		if pid == t.rootPID {
			continue
		}
		if !t.processExists(pid) {
			delete(t.known, pid)
			if t.exitCb != nil {
				t.exitCb(pid, 0)
			}
		}
	}
}

func (t *WindowsProcessTracker) getPPID(pid int) int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}

	for {
		if int(entry.ProcessID) == pid {
			return int(entry.ParentProcessID)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return 0
}

func (t *WindowsProcessTracker) processExists(pid int) bool {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(proc)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(proc, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
}

// ListPIDs implements ProcessTracker.
func (t *WindowsProcessTracker) ListPIDs() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	pids := make([]int, 0, len(t.known))
	for pid := range t.known {
		pids = append(pids, pid)
	}
	return pids
}

// Contains implements ProcessTracker.
func (t *WindowsProcessTracker) Contains(pid int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.known[pid]
}

// KillAll implements ProcessTracker.
func (t *WindowsProcessTracker) KillAll(signal os.Signal) error {
	// If we have a job object, terminate it
	if t.jobHandle != 0 {
		return windows.TerminateJobObject(t.jobHandle, 1)
	}

	// Otherwise terminate each process individually
	pids := t.ListPIDs()
	for i := len(pids) - 1; i >= 0; i-- {
		t.terminateProcess(pids[i])
	}
	return nil
}

func (t *WindowsProcessTracker) terminateProcess(pid int) error {
	proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)
	return windows.TerminateProcess(proc, 1)
}

// Wait implements ProcessTracker.
func (t *WindowsProcessTracker) Wait(ctx context.Context) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pids := t.ListPIDs()
			if len(pids) == 0 {
				return nil
			}
			if !t.processExists(t.rootPID) {
				return nil
			}
		}
	}
}

// Info implements ProcessTracker.
func (t *WindowsProcessTracker) Info(pid int) (*ProcessInfo, error) {
	if !t.Contains(pid) {
		return nil, fmt.Errorf("pid %d not tracked", pid)
	}

	info := &ProcessInfo{
		PID:  pid,
		PPID: t.getPPID(pid),
	}

	// Get executable name from toolhelp
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return info, nil
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return info, nil
	}

	for {
		if int(entry.ProcessID) == pid {
			info.Command = windows.UTF16ToString(entry.ExeFile[:])
			break
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return info, nil
}

// OnSpawn implements ProcessTracker.
func (t *WindowsProcessTracker) OnSpawn(cb func(pid, ppid int)) {
	t.spawnCb = cb
}

// OnExit implements ProcessTracker.
func (t *WindowsProcessTracker) OnExit(cb func(pid, exitCode int)) {
	t.exitCb = cb
}

// Stop implements ProcessTracker.
func (t *WindowsProcessTracker) Stop() error {
	close(t.done)

	if t.jobHandle != 0 {
		windows.CloseHandle(t.jobHandle)
		t.jobHandle = 0
	}

	return nil
}

// Capabilities returns tracker capabilities.
func (t *WindowsProcessTracker) Capabilities() TrackerCapabilities {
	return TrackerCapabilities{
		AutoChildTracking: t.jobHandle != 0,
		SpawnNotification: true,
		ExitNotification:  true,
		ExitCodes:         false,
	}
}

var _ ProcessTracker = (*WindowsProcessTracker)(nil)
