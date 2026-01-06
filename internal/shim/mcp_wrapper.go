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
type MCPInspector func(data []byte, dir MCPDirection)

// ForwardWithInspection copies data from src to dst while calling inspector
// for each line (JSON-RPC message). Returns when src is exhausted.
func ForwardWithInspection(src io.Reader, dst io.Writer, dir MCPDirection, inspector MCPInspector) error {
	scanner := bufio.NewScanner(src)
	// Increase buffer size for large messages
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Inspect (non-blocking, errors logged internally)
		if inspector != nil && len(line) > 0 {
			inspector(line, dir)
		}

		// Always forward
		if _, err := dst.Write(line); err != nil {
			return err
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return err
		}
	}

	return scanner.Err()
}
