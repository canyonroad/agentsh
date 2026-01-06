// internal/mcpinspect/inspector.go
package mcpinspect

import (
	"time"
)

// Direction indicates whether a message is a request or response.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// EventEmitter is a function that emits events.
type EventEmitter func(event interface{})

// Inspector processes MCP messages and emits audit events.
type Inspector struct {
	sessionID string
	serverID  string
	registry  *Registry
	detector  *Detector
	emitEvent EventEmitter
}

// NewInspector creates a new MCP inspector for a server connection.
func NewInspector(sessionID, serverID string, emitter EventEmitter) *Inspector {
	return &Inspector{
		sessionID: sessionID,
		serverID:  serverID,
		registry:  NewRegistry(true), // pin on first use
		detector:  nil,
		emitEvent: emitter,
	}
}

// NewInspectorWithDetection creates a new MCP inspector with pattern detection enabled.
func NewInspectorWithDetection(sessionID, serverID string, emitter EventEmitter) *Inspector {
	return &Inspector{
		sessionID: sessionID,
		serverID:  serverID,
		registry:  NewRegistry(true),
		detector:  NewDetector(),
		emitEvent: emitter,
	}
}

// Inspect processes an MCP message and emits relevant events.
func (i *Inspector) Inspect(data []byte, dir Direction) error {
	msgType, err := DetectMessageType(data)
	if err != nil {
		return err
	}

	switch msgType {
	case MessageToolsListResponse:
		return i.handleToolsListResponse(data)
	}

	return nil
}

func (i *Inspector) handleToolsListResponse(data []byte) error {
	resp, err := ParseToolsListResponse(data)
	if err != nil {
		return err
	}

	now := time.Now()

	for _, tool := range resp.Result.Tools {
		result := i.registry.Register(i.serverID, tool)

		// Run detection if detector is configured
		var detections []DetectionResult
		var maxSeverity string
		if i.detector != nil {
			detections = i.detector.Inspect(tool)
			if len(detections) > 0 {
				maxSeverity = detections[0].Severity.String()
			}
		}

		switch result.Status {
		case StatusNew:
			event := MCPToolSeenEvent{
				Type:        "mcp_tool_seen",
				Timestamp:   now,
				SessionID:   i.sessionID,
				ServerID:    i.serverID,
				ServerType:  "stdio",
				ToolName:    tool.Name,
				ToolHash:    result.Tool.Hash,
				Description: tool.Description,
				Status:      result.Status.String(),
				Detections:  detections,
				MaxSeverity: maxSeverity,
			}
			i.emitEvent(event)

		case StatusChanged:
			changes := computeChanges(result.PreviousDefinition, tool)
			event := MCPToolChangedEvent{
				Type:         "mcp_tool_changed",
				Timestamp:    now,
				SessionID:    i.sessionID,
				ServerID:     i.serverID,
				ToolName:     tool.Name,
				PreviousHash: result.PreviousHash,
				NewHash:      result.NewHash,
				Changes:      changes,
				Detections:   detections,
			}
			i.emitEvent(event)
		}
		// StatusUnchanged: no event (too noisy)
	}

	return nil
}

// computeChanges compares old and new tool definitions.
func computeChanges(old, new ToolDefinition) []FieldChange {
	var changes []FieldChange

	if old.Description != new.Description {
		changes = append(changes, FieldChange{
			Field:    "description",
			Previous: old.Description,
			New:      new.Description,
		})
	}

	oldSchema := string(old.InputSchema)
	newSchema := string(new.InputSchema)
	if oldSchema != newSchema {
		changes = append(changes, FieldChange{
			Field:    "inputSchema",
			Previous: oldSchema,
			New:      newSchema,
		})
	}

	return changes
}
