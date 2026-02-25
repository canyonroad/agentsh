// internal/shim/mcp_exec.go
package shim

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// BinaryPinVerifier abstracts binary pin operations (implemented by mcpinspect.PinStore).
type BinaryPinVerifier interface {
	TrustBinary(serverID, binaryPath, hash string) error
	// VerifyBinary returns status ("not_pinned", "match", "mismatch") and the pinned hash.
	VerifyBinary(serverID, hash string) (status, pinnedHash string, err error)
}

// MCPExecConfig configures MCP inspection for a command.
type MCPExecConfig struct {
	SessionID       string
	ServerID        string
	Command         string
	EnableDetection bool
	EventEmitter    func(interface{})
	// Binary pinning
	PinStore       BinaryPinVerifier
	PinBinary      bool
	AutoTrustFirst bool
	OnChange       string // "block", "alert", "allow"
}

// MCPExecWrapper wraps a command's stdio with MCP inspection.
type MCPExecWrapper struct {
	bridge          *MCPBridge
	resolvedCommand string // absolute path to the verified binary (set when pin verification runs)
}

// BuildMCPExecWrapper creates a wrapper configured for MCP inspection.
func BuildMCPExecWrapper(cfg MCPExecConfig) (*MCPExecWrapper, error) {
	var resolvedCmd string

	// Binary pinning check
	if cfg.PinBinary {
		if cfg.PinStore == nil || cfg.Command == "" {
			// Pinning enabled but misconfigured — fail closed in block mode
			if cfg.OnChange == "block" {
				return nil, fmt.Errorf("binary pin: enabled but PinStore or Command not configured for server %s", cfg.ServerID)
			}
			log.Printf("binary pin: enabled but PinStore or Command not configured for server %s, skipping", cfg.ServerID)
		} else {
			absPath, hash, err := HashBinary(cfg.Command)
			if err != nil {
				if cfg.OnChange == "block" {
					return nil, fmt.Errorf("binary pin: cannot hash %s: %w", cfg.Command, err)
				}
				// alert/allow: log but continue
			} else {
				// Bind the resolved absolute path to prevent TOCTOU attacks
				resolvedCmd = absPath

				status, pinnedHash, err := cfg.PinStore.VerifyBinary(cfg.ServerID, hash)
				if err != nil {
					return nil, fmt.Errorf("binary pin: verify failed: %w", err)
				}
				switch status {
				case "not_pinned":
					if cfg.AutoTrustFirst {
						if trustErr := cfg.PinStore.TrustBinary(cfg.ServerID, absPath, hash); trustErr != nil {
							if cfg.OnChange == "block" {
								return nil, fmt.Errorf("binary pin: failed to persist trust for %s: %w", cfg.ServerID, trustErr)
							}
							log.Printf("binary pin: failed to trust %s: %v", cfg.ServerID, trustErr)
						}
					}
				case "mismatch":
					if cfg.OnChange == "block" {
						return nil, fmt.Errorf("binary pin mismatch for server %s: expected %s, got %s", cfg.ServerID, pinnedHash, hash)
					}
					// alert mode: emit event if emitter available
					if cfg.OnChange == "alert" && cfg.EventEmitter != nil {
						cfg.EventEmitter(map[string]any{
							"type":         "mcp_server_binary_mismatch",
							"server_id":    cfg.ServerID,
							"pinned_hash":  pinnedHash,
							"current_hash": hash,
							"binary_path":  absPath,
							"action":       "alert",
						})
					}
				}
			}
		}
	}

	var bridge *MCPBridge
	if cfg.EnableDetection {
		bridge = NewMCPBridgeWithDetection(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	} else {
		bridge = NewMCPBridge(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	}

	return &MCPExecWrapper{bridge: bridge, resolvedCommand: resolvedCmd}, nil
}

// ResolvedCommand returns the absolute path to the binary that was verified
// during pin checking. If binary pinning was not enabled or the command was
// not resolved, it returns an empty string. Callers should use this path
// (when non-empty) to launch the actual process, preventing TOCTOU attacks
// where PATH changes between pin verification and execution.
func (w *MCPExecWrapper) ResolvedCommand() string {
	return w.resolvedCommand
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
