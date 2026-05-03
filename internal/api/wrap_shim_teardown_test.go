//go:build linux

package api

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestWrapInit_ShimMode_ListenerExitsAfterOneConnection verifies that when
// wrap-init is called with Mode=="shim", the listener goroutine accepts at
// most one connection and then exits, instead of staying alive for the
// session lifetime. This prevents goroutine leaks on per-invocation use.
//
// acceptNotifyFD already exits naturally after a single accept (its retry
// loop only skips connections with the wrong UID), so the test also validates
// that the acceptNotifyFDForTest seam works correctly and that the shimMode
// flag is plumbed through the goroutine launch.
func TestWrapInit_ShimMode_ListenerExitsAfterOneConnection(t *testing.T) {
	cfg := &config.Config{}
	// Use /bin/true as a stable wrapper path so the test runs in any CI
	// without requiring agentsh-unixwrap to be preinstalled on PATH.
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"

	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var active int32
	app.acceptNotifyFDForTest = func(fn func()) {
		atomic.AddInt32(&active, 1)
		go func() {
			defer atomic.AddInt32(&active, -1)
			fn()
		}()
	}

	resp, code, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/true",
		Mode:         "shim",
	})
	if err != nil || code != 200 {
		t.Fatalf("wrap-init failed: code=%d err=%v", code, err)
	}
	defer os.RemoveAll(filepath.Dir(resp.NotifySocket))

	if got := atomic.LoadInt32(&active); got != 1 {
		t.Fatalf("expected 1 active listener after wrap-init, got %d", got)
	}

	// Connect and immediately close: simulates a wrapper that exited
	// without sending a notify fd. The listener should exit after
	// the connection is accepted (the for-loop breaks, recvFD fails/returns,
	// and the goroutine returns).
	c, err := net.DialTimeout("unix", resp.NotifySocket, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&active) == 0 {
			return // success — listener cleaned up
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener still active after 5s; expected exit after one connection in shim mode")
}
