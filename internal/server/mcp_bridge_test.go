package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/mcpregistry"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestBridgeEventToRegistry_ToolSeen(t *testing.T) {
	reg := mcpregistry.NewRegistry()
	ev := types.Event{
		Type:      "mcp_tool_seen",
		SessionID: "sess-1",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"server_id":   "weather-server",
			"server_type": "stdio",
			"tool_name":   "get_weather",
			"tool_hash":   "sha256:abc",
		},
	}

	bridgeEventToRegistry(ev, reg)

	entry := reg.Lookup("get_weather")
	if entry == nil {
		t.Fatal("expected tool to be registered")
	}
	if entry.ServerID != "weather-server" {
		t.Errorf("expected server_id=weather-server, got %q", entry.ServerID)
	}
	if entry.ServerType != "stdio" {
		t.Errorf("expected server_type=stdio, got %q", entry.ServerType)
	}
	if entry.ToolHash != "sha256:abc" {
		t.Errorf("expected tool_hash=sha256:abc, got %q", entry.ToolHash)
	}
}

func TestBridgeEventToRegistry_ToolChanged(t *testing.T) {
	reg := mcpregistry.NewRegistry()
	// Seed with original tool
	reg.Register("weather-server", "stdio", "", []mcpregistry.ToolInfo{
		{Name: "get_weather", Hash: "sha256:abc"},
	})

	ev := types.Event{
		Type:      "mcp_tool_changed",
		SessionID: "sess-1",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"server_id": "weather-server",
			"tool_name": "get_weather",
			"new_hash":  "sha256:def",
		},
	}

	bridgeEventToRegistry(ev, reg)

	entry := reg.Lookup("get_weather")
	if entry == nil {
		t.Fatal("expected tool to still be registered")
	}
	if entry.ToolHash != "sha256:def" {
		t.Errorf("expected updated hash sha256:def, got %q", entry.ToolHash)
	}
}

func TestBridgeEventToRegistry_MissingFields(t *testing.T) {
	reg := mcpregistry.NewRegistry()

	tests := []struct {
		name      string
		eventType string
		fields    map[string]interface{}
	}{
		{"seen/nil fields", "mcp_tool_seen", nil},
		{"seen/empty server_id", "mcp_tool_seen", map[string]interface{}{"server_id": "", "tool_name": "t"}},
		{"seen/empty tool_name", "mcp_tool_seen", map[string]interface{}{"server_id": "s", "tool_name": ""}},
		{"seen/missing tool_name", "mcp_tool_seen", map[string]interface{}{"server_id": "s"}},
		{"changed/nil fields", "mcp_tool_changed", nil},
		{"changed/empty server_id", "mcp_tool_changed", map[string]interface{}{"server_id": "", "tool_name": "t"}},
		{"changed/empty tool_name", "mcp_tool_changed", map[string]interface{}{"server_id": "s", "tool_name": ""}},
		{"changed/missing tool_name", "mcp_tool_changed", map[string]interface{}{"server_id": "s"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := types.Event{Type: tt.eventType, Fields: tt.fields}
			bridgeEventToRegistry(ev, reg) // should not panic
		})
	}
}

func TestBridgeEventToRegistry_UnrelatedEvent(t *testing.T) {
	reg := mcpregistry.NewRegistry()
	ev := types.Event{
		Type:   "session_started",
		Fields: map[string]interface{}{"server_id": "s", "tool_name": "t"},
	}
	bridgeEventToRegistry(ev, reg)
	if entry := reg.Lookup("t"); entry != nil {
		t.Error("unrelated event type should not register tools")
	}
}

func TestBridgeEventToRegistry_DefaultServerType(t *testing.T) {
	reg := mcpregistry.NewRegistry()
	ev := types.Event{
		Type: "mcp_tool_seen",
		Fields: map[string]interface{}{
			"server_id": "s1",
			"tool_name": "t1",
			"tool_hash": "h1",
			// no server_type field
		},
	}
	bridgeEventToRegistry(ev, reg)

	entry := reg.Lookup("t1")
	if entry == nil {
		t.Fatal("expected tool to be registered")
	}
	if entry.ServerType != "stdio" {
		t.Errorf("expected default server_type=stdio, got %q", entry.ServerType)
	}
}

func TestServerEmitter_BridgesToRegistry(t *testing.T) {
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	store := composite.New(st, st)
	broker := events.NewBroker()
	reg := mcpregistry.NewRegistry()

	emitter := serverEmitter{
		store:  store,
		broker: broker,
		registryFor: func(sessionID string) *mcpregistry.Registry {
			if sessionID == "sess-1" {
				return reg
			}
			return nil
		},
	}

	ev := types.Event{
		ID:        "evt-1",
		Type:      "mcp_tool_seen",
		SessionID: "sess-1",
		Source:    "shim",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"server_id":   "db-server",
			"server_type": "stdio",
			"tool_name":   "query_db",
			"tool_hash":   "sha256:xyz",
		},
	}

	if err := emitter.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	entry := reg.Lookup("query_db")
	if entry == nil {
		t.Fatal("expected tool to be in enforcement registry after AppendEvent")
	}
	if entry.ServerID != "db-server" {
		t.Errorf("expected server_id=db-server, got %q", entry.ServerID)
	}
}

func TestServerEmitter_NilRegistryNoOp(t *testing.T) {
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	store := composite.New(st, st)
	broker := events.NewBroker()

	emitter := serverEmitter{
		store:  store,
		broker: broker,
		registryFor: func(sessionID string) *mcpregistry.Registry {
			return nil
		},
	}

	ev := types.Event{
		ID:        "evt-2",
		Type:      "mcp_tool_seen",
		SessionID: "sess-2",
		Source:    "shim",
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"server_id": "s", "tool_name": "t",
		},
	}

	if err := emitter.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
}
