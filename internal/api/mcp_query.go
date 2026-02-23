package api

import (
	"net/http"

	"github.com/agentsh/agentsh/internal/store/sqlite"
)

// listMCPTools returns MCP tools, optionally filtered by server and/or detections.
func (a *App) listMCPTools(w http.ResponseWriter, r *http.Request) {
	filter := sqlite.MCPToolFilter{
		ServerID:      r.URL.Query().Get("server"),
		HasDetections: r.URL.Query().Get("detections") == "true",
	}
	tools, err := a.store.ListMCPTools(r.Context(), filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if tools == nil {
		tools = []sqlite.MCPTool{}
	}
	writeJSON(w, http.StatusOK, tools)
}

// listMCPServers returns MCP server summaries aggregated from tool data.
func (a *App) listMCPServers(w http.ResponseWriter, r *http.Request) {
	servers, err := a.store.ListMCPServers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if servers == nil {
		servers = []sqlite.MCPServerSummary{}
	}
	writeJSON(w, http.StatusOK, servers)
}
