package ancestry

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessClass_String(t *testing.T) {
	tests := []struct {
		class ProcessClass
		want  string
	}{
		{ClassUnknown, "unknown"},
		{ClassShell, "shell"},
		{ClassEditor, "editor"},
		{ClassAgent, "agent"},
		{ClassBuildTool, "build_tool"},
		{ClassLanguageServer, "language_server"},
		{ClassLanguageRuntime, "language_runtime"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.class.String())
		})
	}
}

func TestParseProcessClass(t *testing.T) {
	tests := []struct {
		input string
		want  ProcessClass
	}{
		{"shell", ClassShell},
		{"editor", ClassEditor},
		{"agent", ClassAgent},
		{"build_tool", ClassBuildTool},
		{"language_server", ClassLanguageServer},
		{"language_runtime", ClassLanguageRuntime},
		{"unknown", ClassUnknown},
		{"invalid", ClassUnknown},
		{"", ClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseProcessClass(tt.input))
		})
	}
}

func TestProcessTaint_Clone(t *testing.T) {
	original := &ProcessTaint{
		SourcePID:   1000,
		SourceName:  "cursor",
		ContextName: "ai-tools",
		IsAgent:     true,
		Via:         []string{"bash", "npm"},
		ViaClasses:  []ProcessClass{ClassShell, ClassBuildTool},
		Depth:       2,
		InheritedAt: time.Now(),
		SourceSnapshot: ProcessSnapshot{
			Comm:      "cursor",
			ExePath:   "/usr/bin/cursor",
			Cmdline:   []string{"cursor", "."},
			StartTime: 12345,
		},
	}

	clone := original.Clone()

	// Verify all fields are equal
	assert.Equal(t, original.SourcePID, clone.SourcePID)
	assert.Equal(t, original.SourceName, clone.SourceName)
	assert.Equal(t, original.ContextName, clone.ContextName)
	assert.Equal(t, original.IsAgent, clone.IsAgent)
	assert.Equal(t, original.Via, clone.Via)
	assert.Equal(t, original.ViaClasses, clone.ViaClasses)
	assert.Equal(t, original.Depth, clone.Depth)
	assert.Equal(t, original.SourceSnapshot, clone.SourceSnapshot)

	// Verify deep copy - modifying clone shouldn't affect original
	clone.Via[0] = "zsh"
	clone.ViaClasses[0] = ClassEditor
	clone.SourceSnapshot.Cmdline[0] = "modified"

	assert.Equal(t, "bash", original.Via[0])
	assert.Equal(t, ClassShell, original.ViaClasses[0])
	assert.Equal(t, "cursor", original.SourceSnapshot.Cmdline[0])
}

func TestProcessTaint_Clone_Nil(t *testing.T) {
	var taint *ProcessTaint
	assert.Nil(t, taint.Clone())
}

func TestNewTaintCache(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{
		TTL:      time.Hour,
		MaxDepth: 10,
	})
	defer cache.Stop()

	assert.NotNil(t, cache)
	assert.Equal(t, 0, cache.Count())
}

func TestTaintCache_IsTainted_NotTainted(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	assert.Nil(t, cache.IsTainted(1234))
}

func TestTaintCache_OnSpawn_TaintSource(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	// Set up matcher to detect "cursor" as a taint source
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Spawn cursor process
	cache.OnSpawn(1000, 1, &ProcessInfo{
		PID:       1000,
		PPID:      1,
		Comm:      "cursor",
		ExePath:   "/usr/bin/cursor",
		Cmdline:   []string{"cursor", "."},
		StartTime: 12345,
	})

	// Verify taint was created
	taint := cache.IsTainted(1000)
	require.NotNil(t, taint)
	assert.Equal(t, 1000, taint.SourcePID)
	assert.Equal(t, "cursor", taint.SourceName)
	assert.Equal(t, "ai-tools", taint.ContextName)
	assert.Equal(t, 0, taint.Depth)
	assert.Empty(t, taint.Via)
}

func TestTaintCache_OnSpawn_Propagation(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	// Set up matcher and classifier
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})
	cache.SetClassifyProcess(func(comm string) ProcessClass {
		switch comm {
		case "bash", "zsh", "fish":
			return ClassShell
		case "npm", "cargo":
			return ClassBuildTool
		default:
			return ClassUnknown
		}
	})

	// Spawn cursor (taint source)
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})

	// Spawn bash as child of cursor
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "bash"})

	// Verify bash inherited taint
	taint := cache.IsTainted(1001)
	require.NotNil(t, taint)
	assert.Equal(t, 1000, taint.SourcePID)
	assert.Equal(t, "cursor", taint.SourceName)
	assert.Equal(t, 1, taint.Depth)
	assert.Equal(t, []string{"bash"}, taint.Via)
	assert.Equal(t, []ProcessClass{ClassShell}, taint.ViaClasses)

	// Spawn npm as child of bash
	cache.OnSpawn(1002, 1001, &ProcessInfo{Comm: "npm"})

	// Verify npm inherited taint with longer chain
	taint = cache.IsTainted(1002)
	require.NotNil(t, taint)
	assert.Equal(t, 1000, taint.SourcePID)
	assert.Equal(t, 2, taint.Depth)
	assert.Equal(t, []string{"bash", "npm"}, taint.Via)
	assert.Equal(t, []ProcessClass{ClassShell, ClassBuildTool}, taint.ViaClasses)
}

func TestTaintCache_OnSpawn_MaxDepth(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{
		MaxDepth: 2,
	})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Spawn chain: cursor → bash → npm → node
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "bash"})  // depth 1
	cache.OnSpawn(1002, 1001, &ProcessInfo{Comm: "npm"})   // depth 2 (at limit)
	cache.OnSpawn(1003, 1002, &ProcessInfo{Comm: "node"})  // depth 3 (exceeds limit)

	// First three should be tainted
	assert.NotNil(t, cache.IsTainted(1000))
	assert.NotNil(t, cache.IsTainted(1001))
	assert.NotNil(t, cache.IsTainted(1002))

	// Last one should NOT be tainted (exceeds max depth)
	assert.Nil(t, cache.IsTainted(1003))
}

func TestTaintCache_OnSpawn_NonTaintedParent(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "", false // Nothing is a taint source
	})

	// Spawn process with non-tainted parent
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "bash"})

	// Should not be tainted
	assert.Nil(t, cache.IsTainted(1000))
}

func TestTaintCache_OnExit(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Spawn cursor
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})
	require.NotNil(t, cache.IsTainted(1000))

	// Exit cursor
	cache.OnExit(1000)
	assert.Nil(t, cache.IsTainted(1000))
}

func TestTaintCache_MarkAsAgent(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Spawn cursor
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})

	// Initially not marked as agent
	taint := cache.IsTainted(1000)
	require.NotNil(t, taint)
	assert.False(t, taint.IsAgent)

	// Mark as agent
	ok := cache.MarkAsAgent(1000)
	assert.True(t, ok)

	// Verify marked
	taint = cache.IsTainted(1000)
	assert.True(t, taint.IsAgent)
}

func TestTaintCache_MarkAsAgent_NotTainted(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	ok := cache.MarkAsAgent(9999)
	assert.False(t, ok)
}

func TestTaintCache_Callbacks(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	var (
		createdPID    int
		propagatedPID int
		removedPID    int
	)

	cache.SetOnTaintCreated(func(pid int, taint *ProcessTaint) {
		createdPID = pid
	})
	cache.SetOnTaintPropagated(func(pid int, taint *ProcessTaint) {
		propagatedPID = pid
	})
	cache.SetOnTaintRemoved(func(pid int) {
		removedPID = pid
	})

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Create taint source
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})
	assert.Equal(t, 1000, createdPID)

	// Propagate taint
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "bash"})
	assert.Equal(t, 1001, propagatedPID)

	// Remove taint
	cache.OnExit(1001)
	assert.Equal(t, 1001, removedPID)
}

func TestTaintCache_ListPIDs(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})

	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "p1"})
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "p2"})
	cache.OnSpawn(1002, 1001, &ProcessInfo{Comm: "p3"})

	pids := cache.ListPIDs()
	assert.Len(t, pids, 3)
	assert.Contains(t, pids, 1000)
	assert.Contains(t, pids, 1001)
	assert.Contains(t, pids, 1002)
}

func TestTaintCache_Count(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})

	assert.Equal(t, 0, cache.Count())

	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "p1"})
	assert.Equal(t, 1, cache.Count())

	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "p2"})
	assert.Equal(t, 2, cache.Count())

	cache.OnExit(1000)
	assert.Equal(t, 1, cache.Count())
}

func TestTaintCache_Clear(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})

	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "p1"})
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "p2"})
	assert.Equal(t, 2, cache.Count())

	cache.Clear()
	assert.Equal(t, 0, cache.Count())
}

func TestTaintCache_ConcurrentAccess(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent spawns
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			cache.OnSpawn(pid, 1, &ProcessInfo{Comm: "test"})
		}(1000 + i)
	}

	wg.Wait()

	// Verify all were added
	assert.Equal(t, goroutines, cache.Count())

	// Concurrent reads and exits
	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func(pid int) {
			defer wg.Done()
			cache.IsTainted(pid)
		}(1000 + i)
		go func(pid int) {
			defer wg.Done()
			cache.OnExit(pid)
		}(1000 + i)
	}

	wg.Wait()

	// All should be removed
	assert.Equal(t, 0, cache.Count())
}

func TestTaintCache_Branching(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "cursor" {
			return "ai-tools", true
		}
		return "", false
	})

	// Spawn cursor (taint source)
	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "cursor"})

	// Spawn two children from cursor
	cache.OnSpawn(1001, 1000, &ProcessInfo{Comm: "bash"})
	cache.OnSpawn(1002, 1000, &ProcessInfo{Comm: "node"})

	// Both should be tainted with depth 1
	taint1 := cache.IsTainted(1001)
	taint2 := cache.IsTainted(1002)

	require.NotNil(t, taint1)
	require.NotNil(t, taint2)

	assert.Equal(t, 1, taint1.Depth)
	assert.Equal(t, 1, taint2.Depth)
	assert.Equal(t, []string{"bash"}, taint1.Via)
	assert.Equal(t, []string{"node"}, taint2.Via)
}

func TestTaintCache_TTLCleanup(t *testing.T) {
	// Use a very short TTL for testing
	cache := NewTaintCache(TaintCacheConfig{
		TTL: 50 * time.Millisecond,
	})
	defer cache.Stop()

	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})

	cache.OnSpawn(1000, 1, &ProcessInfo{Comm: "test"})
	assert.Equal(t, 1, cache.Count())

	// Wait for TTL + cleanup interval
	time.Sleep(100 * time.Millisecond)

	// Should be cleaned up
	assert.Equal(t, 0, cache.Count())
}
