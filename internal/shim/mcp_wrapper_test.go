// internal/shim/mcp_wrapper_test.go
package shim

import (
	"bytes"
	"io"
	"testing"
)

func TestMCPWrapper_ForwardData(t *testing.T) {
	// Create a simple pipe to simulate stdin/stdout
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	output := &bytes.Buffer{}

	var capturedMessages [][]byte
	inspector := func(data []byte, dir MCPDirection) {
		capturedMessages = append(capturedMessages, append([]byte{}, data...))
	}

	// Run wrapper (forwards input to output)
	err := ForwardWithInspection(input, output, MCPDirectionRequest, inspector)
	if err != nil && err != io.EOF {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	// Verify data was forwarded
	if !bytes.Contains(output.Bytes(), []byte("tools/list")) {
		t.Error("expected output to contain forwarded data")
	}

	// Verify inspector was called
	if len(capturedMessages) == 0 {
		t.Error("expected inspector to be called")
	}
}

func TestMCPWrapper_DirectionTypes(t *testing.T) {
	if MCPDirectionRequest.String() != "request" {
		t.Errorf("MCPDirectionRequest.String() = %q, want request", MCPDirectionRequest.String())
	}
	if MCPDirectionResponse.String() != "response" {
		t.Errorf("MCPDirectionResponse.String() = %q, want response", MCPDirectionResponse.String())
	}
}
