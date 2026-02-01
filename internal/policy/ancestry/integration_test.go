package ancestry

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTreeIntegration_TaintPropagation(t *testing.T) {
	// This test verifies that the integration wiring works correctly.
	// The actual ProcessTree detection depends on cgroups/polling timing,
	// which is unreliable in tests. The unit tests below verify the
	// handleSpawn/handleExit logic directly.
	//
	// This test serves as a smoke test that the integration doesn't panic
	// and the components can be wired together.

	if runtime.GOOS == "windows" {
		t.Skip("process tree test requires Unix shell and cgroups")
	}

	// Skip if we can't create subprocesses (e.g., in some CI environments)
	if os.Getenv("CI") != "" {
		t.Skip("Skipping process spawn test in CI environment")
	}

	// Create a TaintCache with a matcher that taints our test command
	cache := NewTaintCache(TaintCacheConfig{
		TTL:      time.Minute,
		MaxDepth: 10,
	})
	defer cache.Stop()

	// Set up matcher to taint 'sh' process (our test shell)
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "sh" || info.Comm == "bash" {
			return "test_context", true
		}
		return "", false
	})

	// Start a shell process
	cmd := exec.Command("sh", "-c", "sleep 0.2")
	require.NoError(t, cmd.Start())
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Create process tree for the shell
	tree, err := process.NewProcessTree(pid)
	require.NoError(t, err)
	defer tree.Stop()

	// Integrate with taint cache - this is the main thing we're testing
	integration := NewProcessTreeIntegration(tree, cache, nil)
	require.NotNil(t, integration)
	require.Equal(t, cache, integration.TaintCache())
	require.Equal(t, tree, integration.ProcessTree())

	// Wait for process to complete
	_ = cmd.Wait()

	// Note: We don't assert on taint detection here because the ProcessTree
	// uses polling (100ms intervals) and the process may complete before
	// a scan happens. The handleSpawn tests below verify the taint logic.
}

func TestProcessTreeIntegration_WithInfoProvider(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{
		MaxDepth: 10,
	})

	// Custom info provider
	infoCalled := false
	cfg := &IntegrationConfig{
		InfoProvider: func(pid int) (*ProcessInfo, error) {
			infoCalled = true
			return &ProcessInfo{
				PID:      pid,
				PPID:     1,
				Comm:     "test_command",
				ExePath:  "/usr/bin/test",
				Cmdline:  []string{"/usr/bin/test", "--flag"},
			}, nil
		},
	}

	// Set up taint source matcher
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "test_command" {
			return "test_context", true
		}
		return "", false
	})

	// Create integration (this wires up the callbacks)
	pti := &ProcessTreeIntegration{
		tree:         nil, // We'll call handleSpawn directly
		cache:        cache,
		infoProvider: cfg.InfoProvider,
	}

	// Simulate a spawn event
	pti.handleSpawn(&process.ProcessNode{
		PID:  1000,
		PPID: 1,
	})

	// Verify info provider was called
	assert.True(t, infoCalled, "InfoProvider should have been called")

	// Verify process was tainted
	taint := cache.IsTainted(1000)
	require.NotNil(t, taint, "Process should be tainted")
	assert.Equal(t, "test_context", taint.ContextName)
	assert.Equal(t, "test_command", taint.SourceName)
}

func TestProcessTreeIntegration_Exit(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{
		MaxDepth: 10,
	})

	// Pre-taint a process
	cache.OnSpawn(1000, 0, &ProcessInfo{
		PID:  1000,
		Comm: "test",
	})
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		return "test", true
	})
	cache.OnSpawn(1000, 0, &ProcessInfo{
		PID:  1000,
		Comm: "test",
	})

	require.NotNil(t, cache.IsTainted(1000))

	// Create integration
	pti := &ProcessTreeIntegration{
		cache: cache,
	}

	// Simulate exit
	pti.handleExit(&process.ProcessNode{
		PID: 1000,
	})

	// Verify taint was removed
	assert.Nil(t, cache.IsTainted(1000))
}

func TestProcessTreeIntegration_PropagateToChild(t *testing.T) {
	cache := NewTaintCache(TaintCacheConfig{
		MaxDepth: 10,
	})

	// Set up taint source matcher
	cache.SetMatchesTaintSource(func(info *ProcessInfo) (string, bool) {
		if info.Comm == "parent" {
			return "test_context", true
		}
		return "", false
	})

	pti := &ProcessTreeIntegration{
		cache: cache,
	}

	// Spawn parent (taint source)
	pti.handleSpawn(&process.ProcessNode{
		PID:     1000,
		PPID:    1,
		Command: "parent",
	})

	// Verify parent is tainted
	parentTaint := cache.IsTainted(1000)
	require.NotNil(t, parentTaint)
	assert.Equal(t, 0, parentTaint.Depth)

	// Spawn child
	pti.handleSpawn(&process.ProcessNode{
		PID:     2000,
		PPID:    1000,
		Command: "child",
	})

	// Verify child inherited taint
	childTaint := cache.IsTainted(2000)
	require.NotNil(t, childTaint)
	assert.Equal(t, 1, childTaint.Depth)
	assert.Equal(t, parentTaint.SourcePID, childTaint.SourcePID)
	assert.Contains(t, childTaint.Via, "child")
}
