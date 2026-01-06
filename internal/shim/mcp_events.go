// internal/shim/mcp_events.go
package shim

import (
	"encoding/json"
	"net"
	"sync"
)

// MCPEventForwarder sends MCP events to the agentsh server via Unix socket.
type MCPEventForwarder struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewMCPEventForwarder creates a forwarder connected to the event socket.
func NewMCPEventForwarder(socketPath string) (*MCPEventForwarder, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}

	return &MCPEventForwarder{
		conn: conn,
	}, nil
}

// Close closes the event forwarder connection.
func (f *MCPEventForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}

// Emit sends an event to the agentsh server.
func (f *MCPEventForwarder) Emit(event interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn == nil {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Write event as JSON line
	data = append(data, '\n')
	_, err = f.conn.Write(data)
	return err
}

// EmitFunc returns a function suitable for use as mcpinspect.EventEmitter.
func (f *MCPEventForwarder) EmitFunc() func(interface{}) {
	return func(event interface{}) {
		_ = f.Emit(event)
	}
}

// LocalEmitter creates an emitter that just logs events locally.
// Used when no event socket is available.
func LocalEmitter() func(interface{}) {
	return func(event interface{}) {
		// Silent - events are discarded when no socket available
		// Could add logging here if needed
	}
}
