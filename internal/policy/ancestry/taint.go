// Package ancestry provides process ancestry tracking and taint propagation
// for parent-conditional policy enforcement.
package ancestry

import (
	"sync"
	"time"
)

// ProcessClass categorizes processes for chain analysis.
type ProcessClass int

const (
	ClassUnknown ProcessClass = iota
	ClassShell
	ClassEditor
	ClassAgent
	ClassBuildTool
	ClassLanguageServer
	ClassLanguageRuntime
)

// String returns the string representation of a ProcessClass.
func (c ProcessClass) String() string {
	switch c {
	case ClassShell:
		return "shell"
	case ClassEditor:
		return "editor"
	case ClassAgent:
		return "agent"
	case ClassBuildTool:
		return "build_tool"
	case ClassLanguageServer:
		return "language_server"
	case ClassLanguageRuntime:
		return "language_runtime"
	default:
		return "unknown"
	}
}

// ParseProcessClass parses a string into a ProcessClass.
func ParseProcessClass(s string) ProcessClass {
	switch s {
	case "shell":
		return ClassShell
	case "editor":
		return ClassEditor
	case "agent":
		return ClassAgent
	case "build_tool":
		return ClassBuildTool
	case "language_server":
		return ClassLanguageServer
	case "language_runtime":
		return ClassLanguageRuntime
	default:
		return ClassUnknown
	}
}

// ProcessSnapshot captures process info at creation time for race protection.
type ProcessSnapshot struct {
	Comm      string
	ExePath   string
	Cmdline   []string
	StartTime uint64 // Platform-specific start time (unique with PID)
}

// ProcessTaint tracks ancestry from AI tools through process chains.
type ProcessTaint struct {
	SourcePID      int             // Original AI tool PID
	SourceName     string          // Process name of source (e.g., "cursor")
	ContextName    string          // Name of the matching process_context
	IsAgent        bool            // True if detected as AI agent (not just editor)
	Via            []string        // Intermediate process names from source to current
	ViaClasses     []ProcessClass  // Classifications of intermediate processes
	Depth          int             // Number of hops from source
	InheritedAt    time.Time       // When this process inherited the taint
	SourceSnapshot ProcessSnapshot // Snapshot of source process for validation
}

// Clone creates a deep copy of the ProcessTaint.
func (t *ProcessTaint) Clone() *ProcessTaint {
	if t == nil {
		return nil
	}
	clone := &ProcessTaint{
		SourcePID:      t.SourcePID,
		SourceName:     t.SourceName,
		ContextName:    t.ContextName,
		IsAgent:        t.IsAgent,
		Via:            make([]string, len(t.Via)),
		ViaClasses:     make([]ProcessClass, len(t.ViaClasses)),
		Depth:          t.Depth,
		InheritedAt:    t.InheritedAt,
		SourceSnapshot: t.SourceSnapshot,
	}
	copy(clone.Via, t.Via)
	copy(clone.ViaClasses, t.ViaClasses)
	// Clone cmdline in snapshot
	if t.SourceSnapshot.Cmdline != nil {
		clone.SourceSnapshot.Cmdline = make([]string, len(t.SourceSnapshot.Cmdline))
		copy(clone.SourceSnapshot.Cmdline, t.SourceSnapshot.Cmdline)
	}
	return clone
}

// ProcessInfo contains information needed for taint decisions.
type ProcessInfo struct {
	PID       int
	PPID      int
	Comm      string
	ExePath   string
	Cmdline   []string
	StartTime uint64
}

// TaintCache provides O(1) lookup for process taint information.
// It is safe for concurrent use.
type TaintCache struct {
	mu       sync.RWMutex
	taints   map[int]*ProcessTaint
	ttl      time.Duration
	maxDepth int
	done     chan struct{}

	// Callbacks for taint events (optional)
	onTaintCreated    func(pid int, taint *ProcessTaint)
	onTaintPropagated func(pid int, taint *ProcessTaint)
	onTaintRemoved    func(pid int)

	// Matcher function to detect taint sources (set externally)
	matchesTaintSource func(info *ProcessInfo) (contextName string, ok bool)

	// Classifier function to classify processes (set externally)
	classifyProcess func(comm string) ProcessClass
}

// RaceAction specifies what to do when a race condition is detected.
type RaceAction string

const (
	// RaceActionDeny denies the operation when race detected.
	RaceActionDeny RaceAction = "deny"
	// RaceActionAllow allows the operation despite race detection.
	RaceActionAllow RaceAction = "allow"
	// RaceActionApprove requires explicit user approval.
	RaceActionApprove RaceAction = "approve"
)

// RacePolicy configures how to handle race conditions in taint validation.
type RacePolicy struct {
	OnMissingParent   RaceAction // Parent process exited before we could validate
	OnPIDMismatch     RaceAction // PID was reused (start time mismatch)
	OnValidationError RaceAction // Error during validation (e.g., permission denied)
	LogRaceConditions bool       // Whether to log when race conditions are detected
}

// DefaultRacePolicy returns a conservative default race policy.
func DefaultRacePolicy() RacePolicy {
	return RacePolicy{
		OnMissingParent:   RaceActionAllow, // Trust cached data if parent exited
		OnPIDMismatch:     RaceActionDeny,  // Deny if PID was reused
		OnValidationError: RaceActionDeny,  // Deny on validation errors
		LogRaceConditions: true,
	}
}

// PropagationConfig controls taint propagation behavior.
type PropagationConfig struct {
	MaxDepth   int           // Maximum ancestry depth (0 = unlimited)
	TTL        time.Duration // Taint entry TTL (0 = no expiration)
	RacePolicy RacePolicy    // How to handle race conditions
}

// DefaultPropagationConfig returns sensible defaults for propagation.
func DefaultPropagationConfig() PropagationConfig {
	return PropagationConfig{
		MaxDepth:   100,
		TTL:        time.Hour,
		RacePolicy: DefaultRacePolicy(),
	}
}

// TaintCacheConfig configures the TaintCache.
type TaintCacheConfig struct {
	TTL      time.Duration // Time-to-live for taint entries (0 = no expiration)
	MaxDepth int           // Maximum ancestry depth (0 = unlimited)
}

// TaintCacheConfigFromPropagation creates a TaintCacheConfig from PropagationConfig.
func TaintCacheConfigFromPropagation(pc PropagationConfig) TaintCacheConfig {
	return TaintCacheConfig{
		TTL:      pc.TTL,
		MaxDepth: pc.MaxDepth,
	}
}

// NewTaintCache creates a new TaintCache with the given configuration.
func NewTaintCache(cfg TaintCacheConfig) *TaintCache {
	c := &TaintCache{
		taints:   make(map[int]*ProcessTaint),
		ttl:      cfg.TTL,
		maxDepth: cfg.MaxDepth,
		done:     make(chan struct{}),
	}

	// Start cleanup goroutine if TTL is set
	if cfg.TTL > 0 {
		go c.cleanupLoop()
	}

	return c
}

// SetMatchesTaintSource sets the function used to detect taint sources.
func (c *TaintCache) SetMatchesTaintSource(fn func(info *ProcessInfo) (contextName string, ok bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matchesTaintSource = fn
}

// SetClassifyProcess sets the function used to classify processes.
func (c *TaintCache) SetClassifyProcess(fn func(comm string) ProcessClass) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.classifyProcess = fn
}

// SetOnTaintCreated sets the callback for when a new taint source is detected.
func (c *TaintCache) SetOnTaintCreated(fn func(pid int, taint *ProcessTaint)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onTaintCreated = fn
}

// SetOnTaintPropagated sets the callback for when taint is propagated to a child.
func (c *TaintCache) SetOnTaintPropagated(fn func(pid int, taint *ProcessTaint)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onTaintPropagated = fn
}

// SetOnTaintRemoved sets the callback for when a taint entry is removed.
func (c *TaintCache) SetOnTaintRemoved(fn func(pid int)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onTaintRemoved = fn
}

// IsTainted returns a copy of the taint information for a PID, or nil if not tainted.
// This is an O(1) operation. The returned ProcessTaint is a clone and safe to modify.
func (c *TaintCache) IsTainted(pid int) *ProcessTaint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if taint, ok := c.taints[pid]; ok {
		return taint.Clone()
	}
	return nil
}

// OnSpawn handles a new process spawn event.
// It checks if the parent is tainted and propagates taint to the child,
// or checks if the new process is itself a taint source.
func (c *TaintCache) OnSpawn(pid, ppid int, info *ProcessInfo) {
	var callbackPID int
	var callbackTaint *ProcessTaint
	var callbackType int // 0=none, 1=propagated, 2=created

	c.mu.Lock()
	// Check if parent is tainted - propagate to child
	if parentTaint, ok := c.taints[ppid]; ok {
		// Check depth limit
		if c.maxDepth > 0 && parentTaint.Depth >= c.maxDepth {
			c.mu.Unlock()
			return // Don't propagate beyond max depth
		}

		// Classify the new process
		class := ClassUnknown
		if c.classifyProcess != nil {
			class = c.classifyProcess(info.Comm)
		}

		// Create child taint with propagated info
		childTaint := &ProcessTaint{
			SourcePID:      parentTaint.SourcePID,
			SourceName:     parentTaint.SourceName,
			ContextName:    parentTaint.ContextName,
			IsAgent:        parentTaint.IsAgent,
			Via:            append(append([]string{}, parentTaint.Via...), info.Comm),
			ViaClasses:     append(append([]ProcessClass{}, parentTaint.ViaClasses...), class),
			Depth:          parentTaint.Depth + 1,
			InheritedAt:    time.Now(),
			SourceSnapshot: parentTaint.SourceSnapshot,
		}
		c.taints[pid] = childTaint

		if c.onTaintPropagated != nil {
			callbackPID = pid
			callbackTaint = childTaint.Clone()
			callbackType = 1
		}
		c.mu.Unlock()

		// Call callback outside lock to prevent deadlock
		if callbackType == 1 {
			c.onTaintPropagated(callbackPID, callbackTaint)
		}
		return
	}

	// Check if this process IS a taint source
	if c.matchesTaintSource != nil {
		if contextName, ok := c.matchesTaintSource(info); ok {
			taint := &ProcessTaint{
				SourcePID:   pid,
				SourceName:  info.Comm,
				ContextName: contextName,
				IsAgent:     false, // Will be detected separately
				Via:         []string{},
				ViaClasses:  []ProcessClass{},
				Depth:       0,
				InheritedAt: time.Now(),
				SourceSnapshot: ProcessSnapshot{
					Comm:      info.Comm,
					ExePath:   info.ExePath,
					Cmdline:   info.Cmdline,
					StartTime: info.StartTime,
				},
			}
			c.taints[pid] = taint

			if c.onTaintCreated != nil {
				callbackPID = pid
				callbackTaint = taint.Clone()
				callbackType = 2
			}
		}
	}
	c.mu.Unlock()

	// Call callback outside lock to prevent deadlock
	if callbackType == 2 {
		c.onTaintCreated(callbackPID, callbackTaint)
	}
}

// OnExit handles a process exit event by removing its taint entry.
func (c *TaintCache) OnExit(pid int) {
	c.mu.Lock()
	_, existed := c.taints[pid]
	delete(c.taints, pid)
	onRemoved := c.onTaintRemoved
	c.mu.Unlock()

	if existed && onRemoved != nil {
		onRemoved(pid)
	}
}

// MarkAsAgent marks a tainted process as an agent.
func (c *TaintCache) MarkAsAgent(pid int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if taint, ok := c.taints[pid]; ok {
		taint.IsAgent = true
		return true
	}
	return false
}

// Count returns the number of tainted processes.
func (c *TaintCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.taints)
}

// ListPIDs returns all tainted PIDs.
func (c *TaintCache) ListPIDs() []int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pids := make([]int, 0, len(c.taints))
	for pid := range c.taints {
		pids = append(pids, pid)
	}
	return pids
}

// Stop stops the cleanup goroutine and releases resources.
func (c *TaintCache) Stop() {
	close(c.done)
}

// cleanupLoop periodically removes expired taint entries.
func (c *TaintCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired taint entries.
func (c *TaintCache) cleanup() {
	var expiredPIDs []int

	c.mu.Lock()
	now := time.Now()
	for pid, taint := range c.taints {
		if now.Sub(taint.InheritedAt) > c.ttl {
			delete(c.taints, pid)
			if c.onTaintRemoved != nil {
				expiredPIDs = append(expiredPIDs, pid)
			}
		}
	}
	onRemoved := c.onTaintRemoved
	c.mu.Unlock()

	// Call callbacks outside lock to prevent deadlock
	if onRemoved != nil {
		for _, pid := range expiredPIDs {
			onRemoved(pid)
		}
	}
}

// Clear removes all taint entries.
func (c *TaintCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.taints = make(map[int]*ProcessTaint)
}
