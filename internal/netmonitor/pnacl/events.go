package pnacl

import (
	"context"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// Event types for PNACL
const (
	EventNetworkACL         events.EventType = "network_acl"
	EventNetworkACLApproval events.EventType = "network_acl_approval"
	EventNetworkACLAudit    events.EventType = "network_acl_audit"
)

func init() {
	// Register PNACL event types
	events.EventCategory[EventNetworkACL] = "network"
	events.EventCategory[EventNetworkACLApproval] = "network"
	events.EventCategory[EventNetworkACLAudit] = "network"
}

// BrokerEventEmitter adapts the events.Broker to the EventEmitter interface.
type BrokerEventEmitter struct {
	broker    *events.Broker
	sessionID string
	appender  EventAppender
}

// EventAppender is the interface for appending events to persistent storage.
type EventAppender interface {
	AppendEvent(ctx context.Context, ev types.Event) error
}

// NewBrokerEventEmitter creates a new event emitter backed by an events.Broker.
func NewBrokerEventEmitter(broker *events.Broker, sessionID string, appender EventAppender) *BrokerEventEmitter {
	return &BrokerEventEmitter{
		broker:    broker,
		sessionID: sessionID,
		appender:  appender,
	}
}

// EmitNetworkACLEvent emits a network ACL event.
func (e *BrokerEventEmitter) EmitNetworkACLEvent(ctx context.Context, event NetworkACLEvent) error {
	// Convert to types.Event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: event.Timestamp,
		Type:      string(EventNetworkACL),
		SessionID: e.sessionID,
		PID:       event.PID,
		Fields: map[string]any{
			"process_name": event.ProcessName,
			"process_path": event.ProcessPath,
			"parent_pid":   event.ParentPID,
			"target":       event.Target,
			"port":         event.Port,
			"protocol":     event.Protocol,
			"decision":     event.Decision,
			"rule_source":  event.RuleSource,
			"user_action":  event.UserAction,
		},
		Remote:   event.Target,
		Domain:   event.Target,
		Path:     event.ProcessPath,
	}

	// Set decision in policy if appropriate
	if event.Decision != "" {
		decision := types.Decision(event.Decision)
		ev.Policy = &types.PolicyInfo{
			Decision: decision,
		}
	}

	// Append to persistent storage if available
	if e.appender != nil {
		if err := e.appender.AppendEvent(ctx, ev); err != nil {
			// Ignore error - event emission is best-effort
			_ = err
		}
	}

	// Publish to broker
	if e.broker != nil {
		e.broker.Publish(ev)
	}

	return nil
}

// ApprovalEventEmitter wraps an EventEmitter with approval-specific event types.
type ApprovalEventEmitter struct {
	base      EventEmitter
	sessionID string
}

// NewApprovalEventEmitter creates a new approval event emitter.
func NewApprovalEventEmitter(base EventEmitter, sessionID string) *ApprovalEventEmitter {
	return &ApprovalEventEmitter{
		base:      base,
		sessionID: sessionID,
	}
}

// EmitNetworkACLEvent emits the event with the appropriate type based on decision.
func (e *ApprovalEventEmitter) EmitNetworkACLEvent(ctx context.Context, event NetworkACLEvent) error {
	return e.base.EmitNetworkACLEvent(ctx, event)
}

// EmitApprovalRequested emits an event when an approval is requested.
func (e *ApprovalEventEmitter) EmitApprovalRequested(ctx context.Context, req ApprovalRequest) error {
	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: req.ProcessName,
		ProcessPath: req.ProcessPath,
		PID:         req.PID,
		ParentPID:   req.ParentPID,
		Target:      req.Target,
		Port:        req.Port,
		Protocol:    req.Protocol,
		Decision:    "approval_requested",
		RuleSource:  "",
		UserAction:  "",
	}
	return e.base.EmitNetworkACLEvent(ctx, event)
}

// EmitApprovalResolved emits an event when an approval is resolved.
func (e *ApprovalEventEmitter) EmitApprovalResolved(ctx context.Context, req ApprovalRequest, decision UserDecision, reason string) error {
	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: req.ProcessName,
		ProcessPath: req.ProcessPath,
		PID:         req.PID,
		ParentPID:   req.ParentPID,
		Target:      req.Target,
		Port:        req.Port,
		Protocol:    req.Protocol,
		Decision:    "approval_resolved",
		RuleSource:  reason,
		UserAction:  string(decision),
	}
	return e.base.EmitNetworkACLEvent(ctx, event)
}

// ProcessFilterEventAdapter adapts ProcessFilter callbacks to emit events.
type ProcessFilterEventAdapter struct {
	emitter   EventEmitter
	sessionID string
}

// NewProcessFilterEventAdapter creates a new adapter.
func NewProcessFilterEventAdapter(emitter EventEmitter, sessionID string) *ProcessFilterEventAdapter {
	return &ProcessFilterEventAdapter{
		emitter:   emitter,
		sessionID: sessionID,
	}
}

// OnAllow handles allowed connection events.
func (a *ProcessFilterEventAdapter) OnAllow(ctx context.Context, proc ProcessInfo, target string, port int, protocol string, ruleSource string) {
	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: proc.Name,
		ProcessPath: proc.Path,
		PID:         proc.PID,
		ParentPID:   proc.ParentPID,
		Target:      target,
		Port:        port,
		Protocol:    protocol,
		Decision:    "allow",
		RuleSource:  ruleSource,
		UserAction:  "",
	}
	_ = a.emitter.EmitNetworkACLEvent(ctx, event)
}

// OnDeny handles denied connection events.
func (a *ProcessFilterEventAdapter) OnDeny(ctx context.Context, proc ProcessInfo, target string, port int, protocol string, ruleSource string) {
	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: proc.Name,
		ProcessPath: proc.Path,
		PID:         proc.PID,
		ParentPID:   proc.ParentPID,
		Target:      target,
		Port:        port,
		Protocol:    protocol,
		Decision:    "deny",
		RuleSource:  ruleSource,
		UserAction:  "",
	}
	_ = a.emitter.EmitNetworkACLEvent(ctx, event)
}

// OnAudit handles audit events (allowed but logged).
func (a *ProcessFilterEventAdapter) OnAudit(ctx context.Context, proc ProcessInfo, target string, port int, protocol string, ruleSource string) {
	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: proc.Name,
		ProcessPath: proc.Path,
		PID:         proc.PID,
		ParentPID:   proc.ParentPID,
		Target:      target,
		Port:        port,
		Protocol:    protocol,
		Decision:    "audit",
		RuleSource:  ruleSource,
		UserAction:  "",
	}
	_ = a.emitter.EmitNetworkACLEvent(ctx, event)
}

// NoOpEventEmitter is an event emitter that does nothing (for testing).
type NoOpEventEmitter struct{}

// EmitNetworkACLEvent does nothing.
func (e *NoOpEventEmitter) EmitNetworkACLEvent(ctx context.Context, event NetworkACLEvent) error {
	return nil
}
