package types

import "time"

type PolicyInfo struct {
	Decision          Decision      `json:"decision,omitempty"`
	EffectiveDecision Decision      `json:"effective_decision,omitempty"`
	Rule              string        `json:"rule,omitempty"`
	Message           string        `json:"message,omitempty"`
	Approval          *ApprovalInfo `json:"approval,omitempty"`
	Redirect          *RedirectInfo `json:"redirect,omitempty"`
	ThreatFeed        string        `json:"threat_feed,omitempty"`
	ThreatMatch       string        `json:"threat_match,omitempty"`
	ThreatAction      string        `json:"threat_action,omitempty"`
}

type ApprovalInfo struct {
	Required bool         `json:"required"`
	Mode     ApprovalMode `json:"mode,omitempty"`
	ID       string       `json:"id,omitempty"`
}

type Event struct {
	ID        string      `json:"id,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Type      string      `json:"type"`
	SessionID string      `json:"session_id"`
	CommandID string      `json:"command_id,omitempty"`
	Source    string      `json:"source,omitempty"`
	PID       int         `json:"pid,omitempty"`
	Policy    *PolicyInfo `json:"policy,omitempty"`

	// Process context (for execve events)
	ParentPID int `json:"parent_pid,omitempty"`
	Depth     int `json:"depth,omitempty"`

	// Execve details
	Filename    string   `json:"filename,omitempty"`
	RawFilename string   `json:"raw_filename,omitempty"`
	Argv        []string `json:"argv,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`

	// Transparent command unwrapping
	UnwrappedFrom  string `json:"unwrapped_from,omitempty"`
	PayloadCommand string `json:"payload_command,omitempty"`

	// Common convenience fields for indexing/search.
	Path      string `json:"path,omitempty"`
	Abstract  bool   `json:"abstract,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Operation string `json:"operation,omitempty"`
	// Unix socket remote or peer may reuse Remote field; kept for compatibility.

	// Policy result
	EffectiveAction string `json:"effective_action,omitempty"`

	Fields map[string]any `json:"fields,omitempty"`

	// Chain is the shared (sequence, generation) allocated by the composite
	// store before fanout. Used by chained sinks to produce sink-local
	// integrity hashes. Nil until composite stamps it.
	//
	// json:"-" is load-bearing: this field must never appear in any
	// user-visible serialization. Tested by TestEvent_ChainFieldNotMarshaled.
	//
	// Sinks MUST treat the pointed-to ChainState as read-only — see the
	// ChainState type comment for the per-sink-copy contract.
	Chain *ChainState `json:"-"`
}

type EventQuery struct {
	SessionID string
	CommandID string
	Types     []string
	Since     *time.Time
	Until     *time.Time

	Decision *Decision

	PathLike   string
	DomainLike string
	TextLike   string

	Limit  int
	Offset int
	Asc    bool
}

// ChainState is the shared (sequence, generation) tuple that the composite
// store will stamp on each event before fanout to chained sinks. See
// docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md.
//
// Contract for consumers: ChainState MUST be treated as read-only. Sinks
// must never mutate the fields of a *ChainState they receive on
// types.Event.Chain.
//
// Lifecycle: this type and the Event.Chain field exist now so downstream
// tasks can build against a stable type, but no caller writes to Chain
// yet. Task 5 of the Phase 0 plan will land the composite-store wiring
// that allocates a (sequence, generation) tuple via
// audit.SequenceAllocator and stamps a separate *ChainState per
// fanned-out sink (so the pointer is never aliased across sinks).
type ChainState struct {
	Sequence   uint64
	Generation uint32
}
