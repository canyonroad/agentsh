// internal/shim/mcp_exec.go
package shim

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// MCPExecConfig configures MCP inspection for a command.
type MCPExecConfig struct {
	SessionID       string
	ServerID        string
	EnableDetection bool
	EventEmitter    func(interface{})
}

// MCPExecWrapper wraps a command's stdio with MCP inspection.
type MCPExecWrapper struct {
	bridge *MCPBridge
}

// BuildMCPExecWrapper creates a wrapper configured for MCP inspection.
func BuildMCPExecWrapper(cfg MCPExecConfig) *MCPExecWrapper {
	var bridge *MCPBridge
	if cfg.EnableDetection {
		bridge = NewMCPBridgeWithDetection(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	} else {
		bridge = NewMCPBridge(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	}

	return &MCPExecWrapper{
		bridge: bridge,
	}
}

// WrapCommand sets up stdio interception for the given command.
// Returns cleanup function to be called after command completes.
func (w *MCPExecWrapper) WrapCommand(cmd *exec.Cmd) (cleanup func(), err error) {
	// Get original stdin
	origStdin := cmd.Stdin
	if origStdin == nil {
		origStdin = os.Stdin
	}

	// Create pipes for stdin interception
	stdinReader, stdinWriter := io.Pipe()
	cmd.Stdin = stdinReader

	// Create pipes for stdout interception
	stdoutReader, stdoutWriter := io.Pipe()
	cmd.Stdout = stdoutWriter

	// WaitGroup to track goroutine completion
	var wg sync.WaitGroup
	wg.Add(2)

	// Start goroutines for inspection
	go func() {
		defer wg.Done()
		defer stdinWriter.Close()
		if err := ForwardWithInspection(origStdin, stdinWriter, MCPDirectionRequest, w.bridge.InspectorFunc()); err != nil {
			log.Printf("MCP stdin inspection error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer func() {
			// Drain any remaining data
			io.Copy(io.Discard, stdoutReader)
		}()
		if err := ForwardWithInspection(stdoutReader, os.Stdout, MCPDirectionResponse, w.bridge.InspectorFunc()); err != nil {
			log.Printf("MCP stdout inspection error: %v", err)
		}
	}()

	cleanup = func() {
		stdinReader.Close()
		stdoutWriter.Close()
		wg.Wait()
	}

	return cleanup, nil
}
