package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/store/sqlite"
)

func newMCPTestApp(t *testing.T, st *sqlite.Store) http.Handler {
	t.Helper()
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	app := NewApp(cfg, sessions, store, nil, events.NewBroker(), nil, nil, nil, metrics.New(), nil)
	return app.Router()
}

func seedMCPTools(t *testing.T, st *sqlite.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	tools := []sqlite.MCPTool{
		{
			ServerID:       "weather-server",
			ToolName:       "get_weather",
			ToolHash:       "sha256:aaa",
			Description:    "Get weather for a city",
			FirstSeen:      now.Add(-1 * time.Hour),
			LastSeen:       now,
			DetectionCount: 0,
			MaxSeverity:    "",
		},
		{
			ServerID:       "weather-server",
			ToolName:       "get_forecast",
			ToolHash:       "sha256:bbb",
			Description:    "Get 5-day forecast",
			FirstSeen:      now.Add(-30 * time.Minute),
			LastSeen:       now,
			DetectionCount: 2,
			MaxSeverity:    "high",
		},
		{
			ServerID:       "db-server",
			ToolName:       "query_db",
			ToolHash:       "sha256:ccc",
			Description:    "Run a database query",
			FirstSeen:      now.Add(-2 * time.Hour),
			LastSeen:       now.Add(-10 * time.Minute),
			DetectionCount: 0,
			MaxSeverity:    "",
		},
		{
			ServerID:       "db-server",
			ToolName:       "delete_records",
			ToolHash:       "sha256:ddd",
			Description:    "Delete records from table",
			FirstSeen:      now.Add(-2 * time.Hour),
			LastSeen:       now,
			DetectionCount: 5,
			MaxSeverity:    "critical",
		},
	}

	for _, tool := range tools {
		if err := st.UpsertMCPTool(ctx, tool); err != nil {
			t.Fatalf("seed MCP tool %s/%s: %v", tool.ServerID, tool.ToolName, err)
		}
	}
}

func TestMCPListTools_Empty(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tools []sqlite.MCPTool
	if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestMCPListTools_All(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read body once and use for both checks
	raw := rr.Body.Bytes()

	var tools []sqlite.MCPTool
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}

	// Verify JSON tags work: check that at least one tool has expected fields
	var rawList []map[string]any
	if err := json.Unmarshal(raw, &rawList); err != nil {
		t.Fatal(err)
	}
	if _, ok := rawList[0]["server_id"]; !ok {
		t.Error("expected JSON key 'server_id' (json tag), not found")
	}
	if _, ok := rawList[0]["tool_name"]; !ok {
		t.Error("expected JSON key 'tool_name' (json tag), not found")
	}
}

func TestMCPListTools_FilterByServer(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools?server=weather-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tools []sqlite.MCPTool
	if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools for weather-server, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.ServerID != "weather-server" {
			t.Errorf("expected server_id=weather-server, got %q", tool.ServerID)
		}
	}
}

func TestMCPListTools_FilterByDetections(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools?detections=true", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tools []sqlite.MCPTool
	if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools with detections, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.DetectionCount == 0 {
			t.Errorf("expected detection_count > 0 for tool %s/%s", tool.ServerID, tool.ToolName)
		}
	}
}

func TestMCPListTools_FilterByServerAndDetections(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools?server=weather-server&detections=true", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tools []sqlite.MCPTool
	if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool for weather-server with detections, got %d", len(tools))
	}
	if tools[0].ToolName != "get_forecast" {
		t.Errorf("expected get_forecast, got %q", tools[0].ToolName)
	}
}

func TestMCPListTools_NonexistentServer(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools?server=no-such-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var tools []sqlite.MCPTool
	if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Errorf("expected 0 tools for nonexistent server, got %d", len(tools))
	}
}

func TestMCPListServers_Empty(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/servers", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var servers []sqlite.MCPServerSummary
	if err := json.NewDecoder(rr.Body).Decode(&servers); err != nil {
		t.Fatal(err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestMCPListServers_WithData(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/servers", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Read body once and use for both checks
	raw := rr.Body.Bytes()

	var servers []sqlite.MCPServerSummary
	if err := json.Unmarshal(raw, &servers); err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	// Verify JSON tags work
	var rawList []map[string]any
	if err := json.Unmarshal(raw, &rawList); err != nil {
		t.Fatal(err)
	}
	if _, ok := rawList[0]["server_id"]; !ok {
		t.Error("expected JSON key 'server_id' (json tag), not found")
	}
	if _, ok := rawList[0]["tool_count"]; !ok {
		t.Error("expected JSON key 'tool_count' (json tag), not found")
	}

	// Build map for easier lookup
	serverByID := make(map[string]sqlite.MCPServerSummary)
	for _, s := range servers {
		serverByID[s.ServerID] = s
	}

	// Check db-server
	dbSrv, ok := serverByID["db-server"]
	if !ok {
		t.Fatal("expected db-server in results")
	}
	if dbSrv.ToolCount != 2 {
		t.Errorf("db-server: expected 2 tools, got %d", dbSrv.ToolCount)
	}
	if dbSrv.DetectionCount != 5 {
		t.Errorf("db-server: expected 5 detections, got %d", dbSrv.DetectionCount)
	}

	// Check weather-server
	wSrv, ok := serverByID["weather-server"]
	if !ok {
		t.Fatal("expected weather-server in results")
	}
	if wSrv.ToolCount != 2 {
		t.Errorf("weather-server: expected 2 tools, got %d", wSrv.ToolCount)
	}
	if wSrv.DetectionCount != 2 {
		t.Errorf("weather-server: expected 2 detections, got %d", wSrv.DetectionCount)
	}
}

func TestMCPListTools_DetectionsParseBool(t *testing.T) {
	st := newSQLiteStore(t)
	seedMCPTools(t, st)
	h := newMCPTestApp(t, st)

	tests := []struct {
		name      string
		query     string
		wantCount int
	}{
		{name: "true", query: "detections=true", wantCount: 2},
		{name: "1", query: "detections=1", wantCount: 2},
		{name: "false", query: "detections=false", wantCount: 4},
		{name: "0", query: "detections=0", wantCount: 4},
		{name: "invalid treats as false", query: "detections=bogus", wantCount: 4},
		{name: "empty treats as false", query: "detections=", wantCount: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools?"+tt.query, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
			}

			var tools []sqlite.MCPTool
			if err := json.NewDecoder(rr.Body).Decode(&tools); err != nil {
				t.Fatal(err)
			}
			if len(tools) != tt.wantCount {
				t.Errorf("expected %d tools, got %d", tt.wantCount, len(tools))
			}
		})
	}
}

func TestMCPListTools_StoreError(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	// Close the store to force an error on the next query.
	st.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	errMsg, _ := body["error"].(string)
	if errMsg != "internal server error" {
		t.Errorf("expected generic error message, got %q", errMsg)
	}
}

func TestMCPListServers_StoreError(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	// Close the store to force an error on the next query.
	st.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/servers", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	errMsg, _ := body["error"].(string)
	if errMsg != "internal server error" {
		t.Errorf("expected generic error message, got %q", errMsg)
	}
}

func TestMCPListTools_ContentType(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", ct)
	}
}

func TestMCPListServers_ContentType(t *testing.T) {
	st := newSQLiteStore(t)
	h := newMCPTestApp(t, st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/servers", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", ct)
	}
}
