//go:build !windows

// internal/signal/registry_test.go
package signal

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPIDRegistry(t *testing.T) {
	r := NewPIDRegistry("test-session", 1000)

	assert.Equal(t, "test-session", r.SessionID())
	assert.Equal(t, 1000, r.SupervisorPID())
}

func TestPIDRegistry(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000) // supervisor PID 1000

	// Register some processes
	r.Register(1001, 1000, "bash")   // child of supervisor
	r.Register(1002, 1001, "python") // grandchild
	r.Register(1003, 1000, "node")   // another child

	// Test classification
	ctx := r.ClassifyTarget(1001, 1001) // self
	assert.True(t, ctx.SourcePID == ctx.TargetPID)

	ctx = r.ClassifyTarget(1001, 1002) // child
	assert.True(t, ctx.IsChild)

	ctx = r.ClassifyTarget(1001, 1003) // sibling
	assert.True(t, ctx.IsSibling)

	ctx = r.ClassifyTarget(1001, 1000) // parent (supervisor)
	assert.True(t, ctx.IsParent)

	ctx = r.ClassifyTarget(1001, 9999) // external
	assert.False(t, ctx.InSession)
}

func TestPIDRegistryUnregister(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)
	r.Register(1001, 1000, "bash")

	ctx := r.ClassifyTarget(1000, 1001)
	assert.True(t, ctx.InSession)

	r.Unregister(1001)

	ctx = r.ClassifyTarget(1000, 1001)
	assert.False(t, ctx.InSession)
}

func TestPIDRegistryDescendantDetection(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Build a process tree:
	// supervisor (1000)
	//   -> bash (1001)
	//        -> python (1002)
	//             -> worker (1003)
	//                  -> thread (1004)
	r.Register(1001, 1000, "bash")
	r.Register(1002, 1001, "python")
	r.Register(1003, 1002, "worker")
	r.Register(1004, 1003, "thread")

	// Direct child should be both IsChild and IsDescendant
	ctx := r.ClassifyTarget(1001, 1002)
	assert.True(t, ctx.IsChild, "direct child should have IsChild=true")
	assert.True(t, ctx.IsDescendant, "direct child should have IsDescendant=true")

	// Grandchild should be IsDescendant but not IsChild
	ctx = r.ClassifyTarget(1001, 1003)
	assert.False(t, ctx.IsChild, "grandchild should have IsChild=false")
	assert.True(t, ctx.IsDescendant, "grandchild should have IsDescendant=true")

	// Great-grandchild should be IsDescendant but not IsChild
	ctx = r.ClassifyTarget(1001, 1004)
	assert.False(t, ctx.IsChild, "great-grandchild should have IsChild=false")
	assert.True(t, ctx.IsDescendant, "great-grandchild should have IsDescendant=true")

	// Supervisor's view of deep descendant
	ctx = r.ClassifyTarget(1000, 1004)
	assert.False(t, ctx.IsChild, "deep descendant from supervisor should have IsChild=false")
	assert.True(t, ctx.IsDescendant, "deep descendant from supervisor should have IsDescendant=true")

	// Non-descendant (sibling's child is not a descendant)
	r.Register(1010, 1000, "other")
	r.Register(1011, 1010, "other-child")
	ctx = r.ClassifyTarget(1001, 1011)
	assert.False(t, ctx.IsChild, "cousin should have IsChild=false")
	assert.False(t, ctx.IsDescendant, "cousin should have IsDescendant=false")
}

func TestPIDRegistryInSession(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Supervisor is always in session
	assert.True(t, r.InSession(1000), "supervisor should be in session")

	// Unregistered process is not in session
	assert.False(t, r.InSession(1001), "unregistered process should not be in session")

	// Register and check
	r.Register(1001, 1000, "bash")
	assert.True(t, r.InSession(1001), "registered process should be in session")

	// Deeply nested process
	r.Register(1002, 1001, "python")
	r.Register(1003, 1002, "worker")
	assert.True(t, r.InSession(1003), "deeply nested process should be in session")

	// External process
	assert.False(t, r.InSession(9999), "external process should not be in session")
}

func TestPIDRegistrySelfClassification(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)
	r.Register(1001, 1000, "bash")

	ctx := r.ClassifyTarget(1001, 1001)
	assert.Equal(t, 1001, ctx.SourcePID)
	assert.Equal(t, 1001, ctx.TargetPID)
	assert.True(t, ctx.InSession)
	assert.Equal(t, "bash", ctx.TargetCmd)
	// Self is not considered child, descendant, sibling, or parent
	assert.False(t, ctx.IsChild)
	assert.False(t, ctx.IsDescendant)
	assert.False(t, ctx.IsSibling)
	assert.False(t, ctx.IsParent)
}

func TestPIDRegistryParentClassification(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)
	r.Register(1001, 1000, "bash")
	r.Register(1002, 1001, "python")
	r.Register(1003, 1002, "worker")

	// Target is supervisor (parent of all)
	ctx := r.ClassifyTarget(1001, 1000)
	assert.True(t, ctx.IsParent, "supervisor should be parent")
	assert.True(t, ctx.InSession, "supervisor should be in session")

	// Target is direct parent
	ctx = r.ClassifyTarget(1002, 1001)
	assert.True(t, ctx.IsParent, "direct parent should have IsParent=true")

	// Grandparent is not marked as parent (only direct parent or supervisor)
	ctx = r.ClassifyTarget(1003, 1001)
	assert.False(t, ctx.IsParent, "grandparent should have IsParent=false")
	assert.True(t, ctx.InSession, "grandparent should be in session")
}

func TestPIDRegistrySiblingClassification(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Two children of the same parent
	r.Register(1001, 1000, "bash")
	r.Register(1002, 1000, "node")

	ctx := r.ClassifyTarget(1001, 1002)
	assert.True(t, ctx.IsSibling, "processes with same parent should be siblings")

	ctx = r.ClassifyTarget(1002, 1001)
	assert.True(t, ctx.IsSibling, "sibling relationship should be symmetric")

	// Children of different parents are not siblings
	r.Register(1003, 1001, "python")
	r.Register(1004, 1002, "ruby")

	ctx = r.ClassifyTarget(1003, 1004)
	assert.False(t, ctx.IsSibling, "children of different parents should not be siblings")
}

func TestPIDRegistryExternalClassification(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)
	r.Register(1001, 1000, "bash")

	// External process
	ctx := r.ClassifyTarget(1001, 9999)
	assert.False(t, ctx.InSession, "external process should not be in session")
	assert.False(t, ctx.IsChild)
	assert.False(t, ctx.IsDescendant)
	assert.False(t, ctx.IsSibling)
	assert.False(t, ctx.IsParent)
	assert.Equal(t, "", ctx.TargetCmd, "external process should have no command")
}

func TestPIDRegistryCommandTracking(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	r.Register(1001, 1000, "bash")
	r.Register(1002, 1001, "python3")
	r.Register(1003, 1002, "my-worker")

	ctx := r.ClassifyTarget(1000, 1001)
	assert.Equal(t, "bash", ctx.TargetCmd)

	ctx = r.ClassifyTarget(1000, 1002)
	assert.Equal(t, "python3", ctx.TargetCmd)

	ctx = r.ClassifyTarget(1000, 1003)
	assert.Equal(t, "my-worker", ctx.TargetCmd)

	// After unregister, command should be gone
	r.Unregister(1003)
	ctx = r.ClassifyTarget(1000, 1003)
	assert.Equal(t, "", ctx.TargetCmd)
}

func TestPIDRegistryUnregisterCleansParentChildren(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	r.Register(1001, 1000, "bash")
	r.Register(1002, 1000, "node")

	// Both should be children of supervisor
	ctx := r.ClassifyTarget(1000, 1001)
	assert.True(t, ctx.IsChild)
	ctx = r.ClassifyTarget(1000, 1002)
	assert.True(t, ctx.IsChild)

	// Unregister one
	r.Unregister(1001)

	// The other should still be a child
	ctx = r.ClassifyTarget(1000, 1002)
	assert.True(t, ctx.IsChild)
	assert.True(t, ctx.InSession)

	// The unregistered one should not be in session
	ctx = r.ClassifyTarget(1000, 1001)
	assert.False(t, ctx.InSession)
}

func TestPIDRegistryGetters(t *testing.T) {
	r := NewPIDRegistry("my-unique-session", 42)

	assert.Equal(t, "my-unique-session", r.SessionID())
	assert.Equal(t, 42, r.SupervisorPID())
}

func TestPIDRegistryThreadSafety(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100

	// Concurrent registrations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				pid := base*numOperations + j + 2000 // Start from 2000 to avoid conflicts
				r.Register(pid, 1000, "test")
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				r.InSession(2000 + j)
				r.ClassifyTarget(1000, 2000+j)
			}
		}()
	}

	wg.Wait()

	// Now do concurrent unregistrations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				pid := base*numOperations + j + 2000
				r.Unregister(pid)
			}
		}(i)
	}

	wg.Wait()

	// All should be unregistered now
	for i := 0; i < numGoroutines*numOperations; i++ {
		assert.False(t, r.InSession(2000+i), "all processes should be unregistered")
	}
}

func TestPIDRegistrySupervisorAlwaysInSession(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Supervisor is in session even without explicit registration
	assert.True(t, r.InSession(1000))

	// Classify from child to supervisor
	r.Register(1001, 1000, "bash")
	ctx := r.ClassifyTarget(1001, 1000)
	assert.True(t, ctx.InSession)
	assert.True(t, ctx.IsParent)
}

func TestPIDRegistryEmptyRegistry(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Only supervisor is in session
	assert.True(t, r.InSession(1000))
	assert.False(t, r.InSession(1001))

	// ClassifyTarget on empty registry
	ctx := r.ClassifyTarget(1000, 1001)
	assert.False(t, ctx.InSession)
	assert.False(t, ctx.IsChild)
	assert.False(t, ctx.IsDescendant)
	assert.False(t, ctx.IsSibling)
	assert.False(t, ctx.IsParent)
}

func TestPIDRegistryReRegister(t *testing.T) {
	r := NewPIDRegistry("session-1", 1000)

	// Register, unregister, re-register
	r.Register(1001, 1000, "bash")
	require.True(t, r.InSession(1001))

	r.Unregister(1001)
	require.False(t, r.InSession(1001))

	r.Register(1001, 1000, "zsh") // Re-register with different command
	assert.True(t, r.InSession(1001))

	ctx := r.ClassifyTarget(1000, 1001)
	assert.Equal(t, "zsh", ctx.TargetCmd, "re-registered process should have new command")
}

func TestClassifyTargetSameUser(t *testing.T) {
	r := NewPIDRegistryWithUID("test", 1000, 1000) // supervisor PID=1000, UID=1000

	// Register source process with UID 1000
	r.RegisterWithUID(1001, 1000, "myapp", 1000)

	// Target in session with same UID should have SameUser=true
	ctx := r.ClassifyTarget(1001, 1000) // Signal to supervisor
	assert.True(t, ctx.SameUser, "same user should be true when UIDs match")

	// External process - we don't know its UID, so SameUser should be false
	ctx = r.ClassifyTarget(1001, 9999)
	assert.False(t, ctx.SameUser, "same user should be false for unknown external process")
}
