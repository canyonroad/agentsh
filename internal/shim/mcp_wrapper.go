// internal/shim/mcp_wrapper.go
package shim

import (
	"bufio"
	"io"
)

// MCPDirection indicates whether a message is a request or response.
type MCPDirection int

const (
	MCPDirectionRequest MCPDirection = iota
	MCPDirectionResponse
)

// String returns the string representation of MCPDirection.
func (d MCPDirection) String() string {
	switch d {
	case MCPDirectionRequest:
		return "request"
	case MCPDirectionResponse:
		return "response"
	default:
		return "unknown"
	}
}

// MCPInspector is called for each message passing through the wrapper.
// Returns true if the message should be blocked (not forwarded).
type MCPInspector func(data []byte, dir MCPDirection) bool

// ForwardWithInspection copies data from src to dst while calling inspector
// for each line (JSON-RPC message). If the inspector returns true (blocked),
// the line is not forwarded. Returns when src is exhausted.
func ForwardWithInspection(src io.Reader, dst io.Writer, dir MCPDirection, inspector MCPInspector) error {
	scanner := bufio.NewScanner(src)
	// Increase buffer size for large messages
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Inspect and check if blocked
		if inspector != nil && len(line) > 0 {
			if inspector(line, dir) {
				continue // blocked, do not forward
			}
		}

		// Forward
		if _, err := dst.Write(line); err != nil {
			return err
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return err
		}
	}

	return scanner.Err()
}
