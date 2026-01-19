package types

import "time"

// TaintInfo contains information about a tainted process.
type TaintInfo struct {
	PID         int       `json:"pid"`
	SourcePID   int       `json:"source_pid"`
	SourceName  string    `json:"source_name"`
	ContextName string    `json:"context_name"`
	IsAgent     bool      `json:"is_agent"`
	Via         []string  `json:"via"`
	ViaClasses  []string  `json:"via_classes"`
	Depth       int       `json:"depth"`
	InheritedAt time.Time `json:"inherited_at"`
}

// TaintTrace contains a full ancestry trace for a process.
type TaintTrace struct {
	Taint        *TaintInfo         `json:"taint"`
	MatchedRules []TaintMatchedRule `json:"matched_rules,omitempty"`
}

// TaintMatchedRule represents a chain rule that matched during evaluation.
type TaintMatchedRule struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Message string `json:"message,omitempty"`
}

// TaintEvent represents a taint-related event for streaming.
type TaintEvent struct {
	Type        string    `json:"type"` // taint_created, taint_propagated, taint_removed, agent_detected
	PID         int       `json:"pid"`
	SourcePID   int       `json:"source_pid,omitempty"`
	SourceName  string    `json:"source_name,omitempty"`
	ContextName string    `json:"context_name,omitempty"`
	Depth       int       `json:"depth,omitempty"`
	IsAgent     bool      `json:"is_agent,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"` // For agent_detected events
	Timestamp   time.Time `json:"timestamp"`
}
