//go:build darwin

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DarwinProcessTracker implements ProcessTracker using polling and ps/pgrep.
type DarwinProcessTracker struct {
	rootPID int
	known   map[int]bool
	mu      sync.RWMutex
	spawnCb func(pid, ppid int)
	exitCb  func(pid, exitCode int)
	done    chan struct{}
}

func newPlatformTracker() ProcessTracker {
	return &DarwinProcessTracker{
		known: make(map[int]bool),
		done:  make(chan struct{}),
	}
}

// Track implements ProcessTracker.
func (t *DarwinProcessTracker) Track(pid int) error {
	t.rootPID = pid
	t.known[pid] = true

	go t.poll()
	return nil
}

func (t *DarwinProcessTracker) poll() {
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

func (t *DarwinProcessTracker) scanProcesses() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Get all children of known processes using pgrep
	newPids := make(map[int]bool)
	for pid := range t.known {
		children := t.getChildren(pid)
		for _, child := range children {
			newPids[child] = true
			if !t.known[child] {
				t.known[child] = true
				if t.spawnCb != nil {
					t.spawnCb(child, pid)
				}
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

func (t *DarwinProcessTracker) getChildren(ppid int) []int {
	// Use pgrep to find children
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(ppid)).Output()
	if err != nil {
		return nil
	}

	var children []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		if pid, err := strconv.Atoi(line); err == nil {
			children = append(children, pid)
		}
	}
	return children
}

func (t *DarwinProcessTracker) getPPID(pid int) int {
	out, err := exec.Command("ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	ppid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return ppid
}

func (t *DarwinProcessTracker) processExists(pid int) bool {
	return unix.Kill(pid, 0) == nil
}

// ListPIDs implements ProcessTracker.
func (t *DarwinProcessTracker) ListPIDs() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	pids := make([]int, 0, len(t.known))
	for pid := range t.known {
		pids = append(pids, pid)
	}
	return pids
}

// Contains implements ProcessTracker.
func (t *DarwinProcessTracker) Contains(pid int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.known[pid]
}

// KillAll implements ProcessTracker.
func (t *DarwinProcessTracker) KillAll(signal os.Signal) error {
	sig, ok := signal.(unix.Signal)
	if !ok {
		sig = unix.SIGTERM
	}

	// Kill children first (reverse order)
	pids := t.ListPIDs()
	for i := len(pids) - 1; i >= 0; i-- {
		unix.Kill(pids[i], sig)
	}
	return nil
}

// Wait implements ProcessTracker.
func (t *DarwinProcessTracker) Wait(ctx context.Context) error {
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
func (t *DarwinProcessTracker) Info(pid int) (*ProcessInfo, error) {
	if !t.Contains(pid) {
		return nil, fmt.Errorf("pid %d not tracked", pid)
	}

	info := &ProcessInfo{
		PID:  pid,
		PPID: t.getPPID(pid),
	}

	// Get command using ps
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err == nil {
		cmdline := strings.TrimSpace(string(out))
		parts := strings.Fields(cmdline)
		if len(parts) > 0 {
			info.Command = parts[0]
			if len(parts) > 1 {
				info.Args = parts[1:]
			}
		}
	}

	return info, nil
}

// OnSpawn implements ProcessTracker.
func (t *DarwinProcessTracker) OnSpawn(cb func(pid, ppid int)) {
	t.spawnCb = cb
}

// OnExit implements ProcessTracker.
func (t *DarwinProcessTracker) OnExit(cb func(pid, exitCode int)) {
	t.exitCb = cb
}

// Stop implements ProcessTracker.
func (t *DarwinProcessTracker) Stop() error {
	close(t.done)
	return nil
}

// Capabilities returns tracker capabilities.
func (t *DarwinProcessTracker) Capabilities() TrackerCapabilities {
	return TrackerCapabilities{
		AutoChildTracking: false, // Polling-based
		SpawnNotification: true,
		ExitNotification:  true,
		ExitCodes:         false,
	}
}

var _ ProcessTracker = (*DarwinProcessTracker)(nil)
