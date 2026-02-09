//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/agentsh/agentsh/internal/stub"
)

// handleRedirect terminates the suspended process, creates a named pipe,
// spawns agentsh-stub.exe as a child of the original parent, and serves
// the original command through the stub protocol.
func handleRedirect(req *SuspendedProcessRequest, cfg RedirectConfig) error {
	if req == nil {
		return fmt.Errorf("nil request")
	}

	// 1. Terminate the suspended process
	if err := TerminateProcessByPID(req.ProcessId, 1); err != nil {
		slog.Warn("redirect: failed to terminate suspended process, continuing", "pid", req.ProcessId, "error", err)
	}

	// 2. Generate a unique pipe name
	pipeName := generateStubPipeNameForRedirect(cfg.SessionID, req.ProcessId)

	// 3. Create named pipe listener
	listener, err := ListenNamedPipe(pipeName)
	if err != nil {
		return fmt.Errorf("listen named pipe %s: %w", pipeName, err)
	}
	defer listener.Close()

	// 4. Spawn agentsh-stub.exe as child of the original parent.
	// Pass full environment so the stub inherits SystemRoot, Path, etc.
	stubEnv := append(os.Environ(), fmt.Sprintf("AGENTSH_STUB_PIPE=%s", pipeName))
	stubPID, err := CreateProcessAsChild(
		req.ParentId,
		cfg.StubBinary,
		cfg.StubBinary, // cmdLine
		stubEnv,
		"",    // inherit working directory
		false, // no handle inheritance
		nil,   // no extra handles
	)
	if err != nil {
		return fmt.Errorf("spawn stub as child of %d: %w", req.ParentId, err)
	}
	slog.Info("redirect: spawned stub", "stub_pid", stubPID, "parent_pid", req.ParentId, "pipe", pipeName)

	// 5. Accept the connection from the stub (with timeout via goroutine)
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		ch <- acceptResult{conn, err}
	}()

	var conn net.Conn
	select {
	case res := <-ch:
		if res.err != nil {
			_ = TerminateProcessByPID(stubPID, 1)
			return fmt.Errorf("accept stub connection: %w", res.err)
		}
		conn = res.conn
	case <-time.After(10 * time.Second):
		listener.Close() // unblock Accept
		_ = TerminateProcessByPID(stubPID, 1)
		return fmt.Errorf("timeout waiting for stub connection")
	}

	// 6. Parse original command line and serve through stub protocol
	args := SplitCommandLine(req.CommandLine)
	serveCfg := stub.ServeConfig{
		Command: req.ImagePath,
		Args:    args,
	}

	slog.Info("redirect: serving stub connection", "command", req.ImagePath, "args", args)
	return stub.ServeStubConnection(context.Background(), conn, serveCfg)
}

// HandleRedirect is the exported entry point for redirect operations.
func HandleRedirect(req *SuspendedProcessRequest, cfg RedirectConfig) error {
	return handleRedirect(req, cfg)
}
