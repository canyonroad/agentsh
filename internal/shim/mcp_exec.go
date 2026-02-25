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
	// Environment filtering
	AllowedEnv []string
	DeniedEnv  []string
}

// MCPExecWrapper wraps a command's stdio with MCP inspection.
type MCPExecWrapper struct {
	bridge          *MCPBridge
	resolvedCommand string // absolute path to the verified binary (set when pin verification runs)
	allowedEnv      []string
	deniedEnv       []string
}

// BuildMCPExecWrapper creates a wrapper configured for MCP inspection.
func BuildMCPExecWrapper(cfg MCPExecConfig) (*MCPExecWrapper, error) {
	resolvedCmd, err := verifyBinaryPin(cfg)
	if err != nil {
		return nil, err
	}

	var bridge *MCPBridge
	if cfg.EnableDetection {
		bridge = NewMCPBridgeWithDetection(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	} else {
		bridge = NewMCPBridge(cfg.SessionID, cfg.ServerID, cfg.EventEmitter)
	}

	return &MCPExecWrapper{
		bridge:          bridge,
		resolvedCommand: resolvedCmd,
		allowedEnv:      cfg.AllowedEnv,
		deniedEnv:       cfg.DeniedEnv,
	}, nil
}

// verifyBinaryPin performs binary pin verification. Returns the resolved
// absolute path (empty if pinning disabled) or an error.
func verifyBinaryPin(cfg MCPExecConfig) (string, error) {
	if !cfg.PinBinary {
		return "", nil
	}

	if cfg.PinStore == nil || cfg.Command == "" {
		if cfg.OnChange == "block" {
			return "", fmt.Errorf("binary pin: enabled but PinStore or Command not configured for server %s", cfg.ServerID)
		}
		log.Printf("binary pin: enabled but PinStore or Command not configured for server %s, skipping", cfg.ServerID)
		return "", nil
	}

	absPath, hash, err := HashBinary(cfg.Command)
	if err != nil {
		if cfg.OnChange == "block" {
			return "", fmt.Errorf("binary pin: cannot hash %s: %w", cfg.Command, err)
		}
		log.Printf("binary pin: cannot hash %s for server %s: %v", cfg.Command, cfg.ServerID, err)
		return "", nil
	}

	status, pinnedHash, err := cfg.PinStore.VerifyBinary(cfg.ServerID, hash)
	if err != nil {
		return "", fmt.Errorf("binary pin: verify failed: %w", err)
	}

	switch status {
	case "match":
		// Pin verified successfully.
	case "not_pinned":
		if cfg.AutoTrustFirst {
			if trustErr := cfg.PinStore.TrustBinary(cfg.ServerID, absPath, hash); trustErr != nil {
				if cfg.OnChange == "block" {
					return "", fmt.Errorf("binary pin: failed to persist trust for %s: %w", cfg.ServerID, trustErr)
				}
				log.Printf("binary pin: failed to trust %s: %v", cfg.ServerID, trustErr)
			}
		} else {
			// AutoTrustFirst is off — enforce on_change policy for unknown binaries.
			switch cfg.OnChange {
			case "block":
				return "", fmt.Errorf("binary pin: server %s has no pinned binary and auto_trust_first is disabled", cfg.ServerID)
			case "alert":
				if cfg.EventEmitter != nil {
					cfg.EventEmitter(map[string]any{
						"type":        "mcp_server_binary_not_pinned",
						"server_id":   cfg.ServerID,
						"binary_hash": hash,
						"binary_path": absPath,
						"action":      "alert",
					})
				}
			}
		}
	case "mismatch":
		if cfg.OnChange == "block" {
			return "", fmt.Errorf("binary pin mismatch for server %s: expected %s, got %s", cfg.ServerID, pinnedHash, hash)
		}
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
	default:
		if cfg.OnChange == "block" {
			return "", fmt.Errorf("binary pin: unexpected verify status %q for server %s", status, cfg.ServerID)
		}
		log.Printf("binary pin: unexpected verify status %q for server %s, continuing", status, cfg.ServerID)
	}

	return absPath, nil
}

// ResolvedCommand returns the absolute path to the binary that was verified
// during pin checking. If binary pinning was not enabled or the command was
// not resolved, it returns an empty string. Callers should use this path
// (when non-empty) to launch the actual process, preventing TOCTOU attacks
// where PATH changes between pin verification and execution.
func (w *MCPExecWrapper) ResolvedCommand() string {
	return w.resolvedCommand
}

// syncWriter wraps an io.Writer with a mutex for thread-safe concurrent writes.
// Used when multiple goroutines (stdin block-error replies and stdout forwarding)
// both write to the same underlying writer (os.Stdout).
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// WriteFrame writes data followed by a newline atomically under a single lock
// acquisition, preventing interleaved writes from concurrent goroutines.
func (s *syncWriter) WriteFrame(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err != nil {
		return n, err
	}
	n2, err := s.w.Write([]byte("\n"))
	return n + n2, err
}

// WrapCommand sets up stdio interception for the given command.
// Returns cleanup function to be called after command completes.
func (w *MCPExecWrapper) WrapCommand(cmd *exec.Cmd) (cleanup func(), err error) {
	// Enforce the pinned binary path to prevent TOCTOU/PATH-hijack attacks.
	// When binary pinning resolved an absolute path, override cmd.Path so
	// the process launches the exact binary that was verified.
	if w.resolvedCommand != "" {
		cmd.Path = w.resolvedCommand
		if len(cmd.Args) > 0 {
			cmd.Args[0] = w.resolvedCommand
		}
	}

	// Apply environment filtering before process launch.
	if len(w.allowedEnv) > 0 || len(w.deniedEnv) > 0 {
		environ := cmd.Env
		if environ == nil {
			environ = os.Environ()
		}
		filtered, stripped := FilterEnvForMCPServer(environ, w.allowedEnv, w.deniedEnv)
		cmd.Env = filtered
		if len(stripped) > 0 {
			log.Printf("MCP env filter: stripped %d vars for server", len(stripped))
		}
	}

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

	// syncWriter provides thread-safe writes to os.Stdout, shared between
	// the stdout forwarder and the stdin goroutine's block-error replies.
	sw := &syncWriter{w: os.Stdout}

	// WaitGroup to track goroutine completion
	var wg sync.WaitGroup
	wg.Add(2)

	// Start goroutines for inspection
	go func() {
		defer wg.Done()
		defer stdinWriter.Close()
		// Pass sw as replyWriter so blocked request errors go back to client.
		if err := ForwardWithInspection(origStdin, stdinWriter, MCPDirectionRequest, w.bridge.InspectorFunc(), sw); err != nil {
			log.Printf("MCP stdin inspection error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer func() {
			// Drain any remaining data
			io.Copy(io.Discard, stdoutReader)
		}()
		// Use sw as dst so all client-facing writes are synchronized.
		// nil replyWriter — response blocking writes error to dst directly.
		if err := ForwardWithInspection(stdoutReader, sw, MCPDirectionResponse, w.bridge.InspectorFunc(), nil); err != nil {
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
