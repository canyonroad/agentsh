// internal/mcpinspect/inspector.go
package mcpinspect

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
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
	sessionID    string
	serverID     string
	registry     *Registry
	detector     *Detector
	policyEval   *PolicyEvaluator
	rateLimiter  *RateLimiterRegistry
	emitEvent    EventEmitter
	mu           sync.Mutex
	pendingCalls map[string]string // JSON-RPC ID string → tool name
	cfg          config.SandboxMCPConfig
	samplingCfg  config.SamplingConfig
}

// maxPendingCalls is the cap on the pending call correlation map.
const maxPendingCalls = 1000

// NewInspector creates a new MCP inspector for a server connection.
func NewInspector(sessionID, serverID string, emitter EventEmitter) *Inspector {
	return &Inspector{
		sessionID:    sessionID,
		serverID:     serverID,
		registry:     NewRegistry(true), // pin on first use
		detector:     nil,
		emitEvent:    emitter,
		pendingCalls: make(map[string]string),
	}
}

// NewInspectorWithDetection creates a new MCP inspector with pattern detection enabled.
func NewInspectorWithDetection(sessionID, serverID string, emitter EventEmitter) *Inspector {
	return &Inspector{
		sessionID:    sessionID,
		serverID:     serverID,
		registry:     NewRegistry(true),
		detector:     NewDetector(),
		emitEvent:    emitter,
		pendingCalls: make(map[string]string),
	}
}

// NewInspectorWithPolicy creates an inspector with policy enforcement.
func NewInspectorWithPolicy(sessionID, serverID string, emitter EventEmitter, cfg config.SandboxMCPConfig) *Inspector {
	return &Inspector{
		sessionID:    sessionID,
		serverID:     serverID,
		registry:     NewRegistry(cfg.VersionPinning.AutoTrustFirst),
		detector:     NewDetector(),
		policyEval:   NewPolicyEvaluator(cfg),
		rateLimiter:  NewRateLimiterRegistry(cfg.RateLimits),
		emitEvent:    emitter,
		pendingCalls: make(map[string]string),
		cfg:          cfg,
		samplingCfg:  cfg.Sampling,
	}
}

// InspectResult holds the outcome of inspecting an MCP message.
type InspectResult struct {
	Action string // "allow" | "block" | "" (empty = allow)
	Reason string // Human-readable explanation when blocked
}

// Inspect processes an MCP message and emits relevant events.
// Returns an InspectResult indicating whether the message should be forwarded.
func (i *Inspector) Inspect(data []byte, dir Direction) (*InspectResult, error) {
	msgType, err := DetectMessageType(data)
	if err != nil {
		return nil, err
	}

	switch msgType {
	case MessageToolsListResponse:
		return nil, i.handleToolsListResponse(data)
	case MessageToolsCall:
		return nil, i.handleToolsCall(data)
	case MessageToolsCallResponse:
		return i.handleToolsCallResponse(data)
	case MessageToolsListChanged:
		return nil, i.handleToolsListChanged()
	case MessageSamplingRequest:
		return i.handleSamplingRequest(data)
	case MessageUnknown:
		// Clean up pending-call entries for unrecognised responses (e.g.
		// JSON-RPC error responses that lack result.content). Only run for
		// response direction to avoid accidentally deleting entries when an
		// unknown request happens to carry an id field.
		if dir == DirectionResponse {
			i.cleanupPendingCall(data)
		}
	}

	return nil, nil
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

func (i *Inspector) handleToolsCall(data []byte) error {
	req, err := ParseToolsCallRequest(data)
	if err != nil {
		return err
	}

	// Record the pending call for correlation with the response.
	// Cap at maxPendingCalls to bound memory; skip recording if full.
	idKey := string(req.ID)
	i.mu.Lock()
	if len(i.pendingCalls) < maxPendingCalls {
		i.pendingCalls[idKey] = req.Params.Name
	}
	i.mu.Unlock()

	event := MCPToolCalledEvent{
		Type:      "mcp_tool_called",
		Timestamp: time.Now(),
		SessionID: i.sessionID,
		ServerID:  i.serverID,
		ToolName:  req.Params.Name,
		JSONRPCID: req.ID,
		Input:     req.Params.Arguments,
	}

	// Scan arguments for dangerous patterns (alert-only, never blocks)
	if i.detector != nil && len(req.Params.Arguments) > 0 {
		detections := i.detector.InspectText(string(req.Params.Arguments), "arguments")
		if len(detections) > 0 {
			event.Detections = detections
			event.MaxSeverity = detections[0].Severity.String()
		}
	}

	i.emitEvent(event)
	return nil
}

func (i *Inspector) handleToolsListChanged() error {
	i.emitEvent(MCPToolsListChangedEvent{
		Type:      "mcp_tools_list_changed",
		Timestamp: time.Now(),
		SessionID: i.sessionID,
		ServerID:  i.serverID,
	})
	return nil
}

func (i *Inspector) handleSamplingRequest(data []byte) (*InspectResult, error) {
	req, err := ParseSamplingRequest(data)
	if err != nil {
		return nil, err
	}

	// Determine the effective policy for this server.
	policy := i.samplingCfg.Policy
	if policy == "" {
		policy = "block" // default: sampling is dangerous
	}
	if override, ok := i.samplingCfg.PerServer[i.serverID]; ok {
		policy = override
	}

	// Extract model hint from preferences.
	var modelHint string
	if req.Params.ModelPreferences != nil && len(req.Params.ModelPreferences.Hints) > 0 {
		modelHint = req.Params.ModelPreferences.Hints[0].Name
	}

	// Inspect message text content for hidden instructions.
	var allDetections []DetectionResult
	if i.detector != nil {
		for _, msg := range req.Params.Messages {
			if msg.Content.Type == "text" && msg.Content.Text != "" {
				detections := i.detector.InspectText(msg.Content.Text, "sampling_prompt")
				allDetections = append(allDetections, detections...)
			}
		}
	}

	// Check rate limit (sampling counts against the server's rate limit).
	if i.rateLimiter != nil && !i.rateLimiter.Allow(i.serverID, "sampling/createMessage") {
		policy = "block"
	}

	// Emit the sampling request event.
	action := policy
	i.emitEvent(MCPSamplingRequestEvent{
		Type:         "mcp_sampling_request",
		Timestamp:    time.Now(),
		SessionID:    i.sessionID,
		ServerID:     i.serverID,
		ModelHint:    modelHint,
		MaxTokens:    req.Params.MaxTokens,
		MessageCount: len(req.Params.Messages),
		Detections:   allDetections,
		Action:       action,
	})

	if action == "block" {
		return &InspectResult{
			Action: "block",
			Reason: "sampling/createMessage blocked by policy",
		}, nil
	}

	return nil, nil
}

func (i *Inspector) handleToolsCallResponse(data []byte) (*InspectResult, error) {
	resp, err := ParseToolsCallResponse(data)
	if err != nil {
		return nil, err
	}

	// Look up tool name from pending calls correlation.
	idKey := string(resp.ID)
	toolName := "unknown"
	i.mu.Lock()
	if name, ok := i.pendingCalls[idKey]; ok {
		toolName = name
		delete(i.pendingCalls, idKey)
	}
	i.mu.Unlock()

	// Extract all text content blocks.
	var allText []string
	totalLen := 0
	for _, block := range resp.Result.Content {
		if block.Type == "text" {
			allText = append(allText, block.Text)
			totalLen += len(block.Text)
		}
	}

	// Run detection on each text block if detector is set and output inspection is enabled.
	var allDetections []DetectionResult
	if i.detector != nil && i.cfg.OutputInspection.Enabled {
		for _, text := range allText {
			detections := i.detector.InspectText(text, "tool_result")
			allDetections = append(allDetections, detections...)
		}
	}

	// Determine max severity.
	var maxSeverity string
	if len(allDetections) > 0 {
		highest := allDetections[0].Severity
		for _, d := range allDetections[1:] {
			if d.Severity > highest {
				highest = d.Severity
			}
		}
		maxSeverity = highest.String()
	}

	// Determine action based on config.
	action := "allow"
	if len(allDetections) > 0 {
		action = "alert" // default on detection
		onDetection := i.cfg.OutputInspection.OnDetection
		if onDetection == "block" {
			action = "block"
		} else if onDetection != "" {
			action = onDetection
		}
	}

	event := MCPToolResultInspectedEvent{
		Type:          "mcp_tool_result_inspected",
		Timestamp:     time.Now(),
		SessionID:     i.sessionID,
		ServerID:      i.serverID,
		ToolName:      toolName,
		JSONRPCID:     resp.ID,
		Detections:    allDetections,
		MaxSeverity:   maxSeverity,
		ContentLength: totalLen,
		Action:        action,
	}
	i.emitEvent(event)

	if action == "block" {
		return &InspectResult{
			Action: "block",
			Reason: "tool result contains suspicious content: " + maxSeverity + " severity detection",
		}, nil
	}

	return nil, nil
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

// CheckPolicy checks if a tool invocation is allowed by policy.
func (i *Inspector) CheckPolicy(toolName, hash string) (allowed bool, reason string) {
	if i.policyEval == nil {
		return true, "no policy configured"
	}

	decision := i.policyEval.Evaluate(i.serverID, toolName, hash)
	return decision.Allowed, decision.Reason
}

// CheckRateLimit checks if a tool call is within rate limits.
func (i *Inspector) CheckRateLimit(toolName string) bool {
	if i.rateLimiter == nil {
		return true
	}
	return i.rateLimiter.Allow(i.serverID, toolName)
}

// cleanupPendingCall removes the pending-call entry for a response message
// that was not classified as a tools/call response (e.g. JSON-RPC error
// responses). This prevents the pendingCalls map from leaking entries.
func (i *Inspector) cleanupPendingCall(data []byte) {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &msg); err != nil || len(msg.ID) == 0 {
		return
	}
	idKey := string(msg.ID)
	i.mu.Lock()
	delete(i.pendingCalls, idKey)
	i.mu.Unlock()
}
