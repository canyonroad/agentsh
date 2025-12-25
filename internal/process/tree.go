package process

import (
	"context"
	"os"
	"sync"
	"time"
)

// ProcessNode represents a process in the tree.
type ProcessNode struct {
	PID       int
	PPID      int
	Command   string
	Args      []string
	StartTime time.Time
	EndTime   *time.Time
	ExitCode  *int
	Children  []*ProcessNode
}

// ProcessTree tracks a process and all its descendants.
type ProcessTree struct {
	Root    *ProcessNode
	mu      sync.RWMutex
	tracker ProcessTracker
	onSpawn func(*ProcessNode)
	onExit  func(*ProcessNode, int)
}

// ProcessTracker is the platform-specific interface for tracking processes.
type ProcessTracker interface {
	// Track starts tracking a process and its descendants.
	Track(pid int) error

	// ListPIDs returns all PIDs in the tracked tree.
	ListPIDs() []int

	// Contains checks if a PID is in the tracked tree.
	Contains(pid int) bool

	// KillAll sends a signal to all processes in the tree.
	KillAll(signal os.Signal) error

	// Wait waits for all processes to exit.
	Wait(ctx context.Context) error

	// Info returns information about a process.
	Info(pid int) (*ProcessInfo, error)

	// OnSpawn registers a callback for new process spawns.
	OnSpawn(func(pid int, ppid int))

	// OnExit registers a callback for process exits.
	OnExit(func(pid int, exitCode int))

	// Stop stops tracking and cleans up resources.
	Stop() error
}

// ProcessInfo contains information about a process.
type ProcessInfo struct {
	PID     int
	PPID    int
	Command string
	Args    []string
}

// TrackerCapabilities describes what features the tracker supports.
type TrackerCapabilities struct {
	AutoChildTracking bool // Children are automatically tracked
	SpawnNotification bool // Real-time spawn notifications
	ExitNotification  bool // Real-time exit notifications
	ExitCodes         bool // Exit codes are available
}

// NewProcessTree creates a tracker for the given root PID.
func NewProcessTree(rootPID int) (*ProcessTree, error) {
	tracker := newPlatformTracker()

	tree := &ProcessTree{
		Root: &ProcessNode{
			PID:       rootPID,
			StartTime: time.Now(),
		},
		tracker: tracker,
	}

	tracker.OnSpawn(tree.handleSpawn)
	tracker.OnExit(tree.handleExit)

	if err := tracker.Track(rootPID); err != nil {
		return nil, err
	}

	return tree, nil
}

// OnSpawn registers a callback for process spawn events.
func (t *ProcessTree) OnSpawn(cb func(*ProcessNode)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onSpawn = cb
}

// OnExit registers a callback for process exit events.
func (t *ProcessTree) OnExit(cb func(*ProcessNode, int)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onExit = cb
}

// ListPIDs returns all PIDs in the tree.
func (t *ProcessTree) ListPIDs() []int {
	return t.tracker.ListPIDs()
}

// Contains checks if a PID is in the tree.
func (t *ProcessTree) Contains(pid int) bool {
	return t.tracker.Contains(pid)
}

// KillAll sends a signal to all processes in the tree.
func (t *ProcessTree) KillAll(signal os.Signal) error {
	return t.tracker.KillAll(signal)
}

// Wait waits for all processes to exit.
func (t *ProcessTree) Wait(ctx context.Context) error {
	return t.tracker.Wait(ctx)
}

// Stop stops tracking and cleans up resources.
func (t *ProcessTree) Stop() error {
	return t.tracker.Stop()
}

func (t *ProcessTree) handleSpawn(pid, ppid int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parent := t.findNode(t.Root, ppid)
	if parent == nil {
		return
	}

	child := &ProcessNode{
		PID:       pid,
		PPID:      ppid,
		StartTime: time.Now(),
	}
	parent.Children = append(parent.Children, child)

	if t.onSpawn != nil {
		t.onSpawn(child)
	}
}

func (t *ProcessTree) handleExit(pid, exitCode int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.findNode(t.Root, pid)
	if node == nil {
		return
	}

	now := time.Now()
	node.EndTime = &now
	node.ExitCode = &exitCode

	if t.onExit != nil {
		t.onExit(node, exitCode)
	}
}

func (t *ProcessTree) findNode(node *ProcessNode, pid int) *ProcessNode {
	if node == nil {
		return nil
	}
	if node.PID == pid {
		return node
	}
	for _, child := range node.Children {
		if found := t.findNode(child, pid); found != nil {
			return found
		}
	}
	return nil
}

// GetNode returns a copy of the node for the given PID.
func (t *ProcessTree) GetNode(pid int) *ProcessNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.findNode(t.Root, pid)
}

// Walk traverses the tree, calling fn for each node.
func (t *ProcessTree) Walk(fn func(*ProcessNode) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	t.walkNode(t.Root, fn)
}

func (t *ProcessTree) walkNode(node *ProcessNode, fn func(*ProcessNode) bool) bool {
	if node == nil {
		return true
	}
	if !fn(node) {
		return false
	}
	for _, child := range node.Children {
		if !t.walkNode(child, fn) {
			return false
		}
	}
	return true
}
