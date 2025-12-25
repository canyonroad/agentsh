//go:build linux

package process

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// LinuxProcessTracker implements ProcessTracker using cgroups and /proc.
type LinuxProcessTracker struct {
	rootPID    int
	cgroupPath string
	known      map[int]bool
	mu         sync.RWMutex
	spawnCb    func(pid, ppid int)
	exitCb     func(pid, exitCode int)
	done       chan struct{}
}

func newPlatformTracker() ProcessTracker {
	return &LinuxProcessTracker{
		known: make(map[int]bool),
		done:  make(chan struct{}),
	}
}

// Track implements ProcessTracker.
func (t *LinuxProcessTracker) Track(pid int) error {
	t.rootPID = pid
	t.known[pid] = true

	// Try cgroups first (preferred - automatic child tracking)
	if cgroupPath, err := t.setupCgroup(pid); err == nil {
		t.cgroupPath = cgroupPath
		go t.watchCgroupProcs()
		return nil
	}

	// Fallback to /proc polling
	go t.pollProc()
	return nil
}

func (t *LinuxProcessTracker) setupCgroup(pid int) (string, error) {
	// Try to find the current cgroup
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	// Parse cgroup path (v2 format: "0::/path")
	line := strings.TrimSpace(string(data))
	parts := strings.Split(line, ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected cgroup format")
	}

	basePath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(parts[2], "/"))
	cgroupPath := filepath.Join(basePath, fmt.Sprintf("agentsh-session-%d", pid))

	// Create cgroup directory
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		return "", err
	}

	// Move process to cgroup
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		os.Remove(cgroupPath)
		return "", err
	}

	return cgroupPath, nil
}

func (t *LinuxProcessTracker) watchCgroupProcs() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.updateFromCgroupProcs()
		}
	}
}

func (t *LinuxProcessTracker) updateFromCgroupProcs() {
	procsFile := filepath.Join(t.cgroupPath, "cgroup.procs")
	data, err := os.ReadFile(procsFile)
	if err != nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	currentPids := make(map[int]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
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
}

func (t *LinuxProcessTracker) pollProc() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.scanProc()
		}
	}
}

func (t *LinuxProcessTracker) scanProc() {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check for new children of known processes
	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		if t.known[pid] {
			continue
		}

		ppid := t.getPPID(pid)
		if ppid > 0 && t.known[ppid] {
			t.known[pid] = true
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
		if !t.processExists(pid) {
			delete(t.known, pid)
			if t.exitCb != nil {
				t.exitCb(pid, 0)
			}
		}
	}
}

func (t *LinuxProcessTracker) getPPID(pid int) int {
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	// Parse: pid (comm) state ppid ...
	// Need to find the closing ) of comm first
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}

	fields := strings.Fields(s[idx+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

func (t *LinuxProcessTracker) processExists(pid int) bool {
	return unix.Kill(pid, 0) == nil
}

// ListPIDs implements ProcessTracker.
func (t *LinuxProcessTracker) ListPIDs() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	pids := make([]int, 0, len(t.known))
	for pid := range t.known {
		pids = append(pids, pid)
	}
	return pids
}

// Contains implements ProcessTracker.
func (t *LinuxProcessTracker) Contains(pid int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.known[pid]
}

// KillAll implements ProcessTracker.
func (t *LinuxProcessTracker) KillAll(signal os.Signal) error {
	sig, ok := signal.(unix.Signal)
	if !ok {
		sig = unix.SIGTERM
	}

	// Try cgroup.kill first (Linux 5.14+)
	if t.cgroupPath != "" {
		killFile := filepath.Join(t.cgroupPath, "cgroup.kill")
		if err := os.WriteFile(killFile, []byte("1"), 0o644); err == nil {
			return nil
		}
	}

	// Iterate and kill (children first)
	pids := t.ListPIDs()
	for i := len(pids) - 1; i >= 0; i-- {
		unix.Kill(pids[i], sig)
	}
	return nil
}

// Wait implements ProcessTracker.
func (t *LinuxProcessTracker) Wait(ctx context.Context) error {
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
			// Check if root process has exited
			if !t.processExists(t.rootPID) {
				return nil
			}
		}
	}
}

// Info implements ProcessTracker.
func (t *LinuxProcessTracker) Info(pid int) (*ProcessInfo, error) {
	if !t.Contains(pid) {
		return nil, fmt.Errorf("pid %d not tracked", pid)
	}

	info := &ProcessInfo{
		PID:  pid,
		PPID: t.getPPID(pid),
	}

	// Read command
	cmdPath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if data, err := os.ReadFile(cmdPath); err == nil {
		parts := strings.Split(string(data), "\x00")
		if len(parts) > 0 {
			info.Command = parts[0]
			if len(parts) > 1 {
				info.Args = parts[1 : len(parts)-1] // Last element is empty
			}
		}
	}

	// Fallback to comm if cmdline is empty
	if info.Command == "" {
		commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
		if data, err := os.ReadFile(commPath); err == nil {
			info.Command = strings.TrimSpace(string(data))
		}
	}

	return info, nil
}

// OnSpawn implements ProcessTracker.
func (t *LinuxProcessTracker) OnSpawn(cb func(pid, ppid int)) {
	t.spawnCb = cb
}

// OnExit implements ProcessTracker.
func (t *LinuxProcessTracker) OnExit(cb func(pid, exitCode int)) {
	t.exitCb = cb
}

// Stop implements ProcessTracker.
func (t *LinuxProcessTracker) Stop() error {
	close(t.done)

	// Clean up cgroup
	if t.cgroupPath != "" {
		// Move processes back to parent first
		procsFile := filepath.Join(t.cgroupPath, "cgroup.procs")
		if data, err := os.ReadFile(procsFile); err == nil {
			parentProcs := filepath.Join(filepath.Dir(t.cgroupPath), "cgroup.procs")
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				_ = os.WriteFile(parentProcs, []byte(scanner.Text()), 0o644)
			}
		}
		os.Remove(t.cgroupPath)
	}

	return nil
}

// Capabilities returns tracker capabilities.
func (t *LinuxProcessTracker) Capabilities() TrackerCapabilities {
	return TrackerCapabilities{
		AutoChildTracking: t.cgroupPath != "",
		SpawnNotification: true,
		ExitNotification:  true,
		ExitCodes:         false, // Would need ptrace or wait
	}
}

var _ ProcessTracker = (*LinuxProcessTracker)(nil)
