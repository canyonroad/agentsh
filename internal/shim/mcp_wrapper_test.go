// internal/shim/mcp_wrapper_test.go
package shim

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestMCPWrapper_ForwardData(t *testing.T) {
	// Create a simple pipe to simulate stdin/stdout
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	output := &bytes.Buffer{}

	var capturedMessages [][]byte
	inspector := func(data []byte, dir MCPDirection) bool {
		capturedMessages = append(capturedMessages, append([]byte{}, data...))
		return false // don't block
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

func TestMCPWrapper_BlockedMessageNotForwarded(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"also_allowed"}}` + "\n",
	)
	output := &bytes.Buffer{}

	// Block the sampling request (id:2), allow everything else.
	inspector := func(data []byte, dir MCPDirection) bool {
		return bytes.Contains(data, []byte("sampling/createMessage"))
	}

	err := ForwardWithInspection(input, output, MCPDirectionRequest, inspector)
	if err != nil && err != io.EOF {
		t.Fatalf("ForwardWithInspection failed: %v", err)
	}

	out := output.String()
	if !strings.Contains(out, `"id":1`) {
		t.Error("expected first message (id:1) to be forwarded")
	}
	if strings.Contains(out, `"id":2`) {
		t.Error("expected second message (id:2) to be blocked (not forwarded)")
	}
	if !strings.Contains(out, `"id":3`) {
		t.Error("expected third message (id:3) to be forwarded")
	}
}
