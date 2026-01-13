package pnacl

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
)

// MockAppender implements EventAppender for testing.
type MockAppender struct {
	mu     sync.Mutex
	events []types.Event
}

func (m *MockAppender) AppendEvent(ctx context.Context, ev types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *MockAppender) GetEvents() []types.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events
}

func TestBrokerEventEmitter_EmitNetworkACLEvent(t *testing.T) {
	broker := events.NewBroker()
	appender := &MockAppender{}
	emitter := NewBrokerEventEmitter(broker, "test-session", appender)

	// Subscribe to events
	ch := broker.Subscribe("test-session", 10)
	defer broker.Unsubscribe("test-session", ch)

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: "test-process",
		ProcessPath: "/usr/bin/test",
		PID:         1234,
		ParentPID:   1000,
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
		Decision:    "allow",
		RuleSource:  "explicit rule",
		UserAction:  "",
	}

	err := emitter.EmitNetworkACLEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("EmitNetworkACLEvent failed: %v", err)
	}

	// Check appender received event
	appenderEvents := appender.GetEvents()
	if len(appenderEvents) != 1 {
		t.Fatalf("expected 1 appended event, got %d", len(appenderEvents))
	}

	ev := appenderEvents[0]
	if ev.SessionID != "test-session" {
		t.Errorf("expected session test-session, got %s", ev.SessionID)
	}
	if ev.Type != string(EventNetworkACL) {
		t.Errorf("expected type %s, got %s", EventNetworkACL, ev.Type)
	}
	if ev.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", ev.PID)
	}

	// Check fields
	if ev.Fields["process_name"] != "test-process" {
		t.Errorf("expected process_name test-process, got %v", ev.Fields["process_name"])
	}
	if ev.Fields["target"] != "api.example.com" {
		t.Errorf("expected target api.example.com, got %v", ev.Fields["target"])
	}
	if ev.Fields["decision"] != "allow" {
		t.Errorf("expected decision allow, got %v", ev.Fields["decision"])
	}

	// Check broker received event
	select {
	case brokerEvent := <-ch:
		if brokerEvent.SessionID != "test-session" {
			t.Errorf("broker event session mismatch: %s", brokerEvent.SessionID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("broker did not receive event")
	}
}

func TestBrokerEventEmitter_NilAppender(t *testing.T) {
	broker := events.NewBroker()
	emitter := NewBrokerEventEmitter(broker, "test-session", nil)

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: "test",
		Target:      "example.com",
		Decision:    "allow",
	}

	// Should not panic with nil appender
	err := emitter.EmitNetworkACLEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBrokerEventEmitter_NilBroker(t *testing.T) {
	appender := &MockAppender{}
	emitter := NewBrokerEventEmitter(nil, "test-session", appender)

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: "test",
		Target:      "example.com",
		Decision:    "allow",
	}

	// Should not panic with nil broker
	err := emitter.EmitNetworkACLEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Appender should still receive event
	if len(appender.GetEvents()) != 1 {
		t.Error("appender should receive event even with nil broker")
	}
}

func TestApprovalEventEmitter(t *testing.T) {
	mockEmitter := &MockEventEmitter{}
	approvalEmitter := NewApprovalEventEmitter(mockEmitter, "test-session")

	req := ApprovalRequest{
		ID:          "test-req-1",
		ProcessName: "test-process",
		ProcessPath: "/usr/bin/test",
		PID:         1234,
		Target:      "api.example.com",
		Port:        443,
		Protocol:    "tcp",
	}

	// Test EmitApprovalRequested
	err := approvalEmitter.EmitApprovalRequested(context.Background(), req)
	if err != nil {
		t.Fatalf("EmitApprovalRequested failed: %v", err)
	}

	events := mockEmitter.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Decision != "approval_requested" {
		t.Errorf("expected decision approval_requested, got %s", events[0].Decision)
	}

	// Test EmitApprovalResolved
	err = approvalEmitter.EmitApprovalResolved(context.Background(), req, UserDecisionAllowPermanent, "user approved")
	if err != nil {
		t.Fatalf("EmitApprovalResolved failed: %v", err)
	}

	events = mockEmitter.GetEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1].Decision != "approval_resolved" {
		t.Errorf("expected decision approval_resolved, got %s", events[1].Decision)
	}
	if events[1].UserAction != string(UserDecisionAllowPermanent) {
		t.Errorf("expected user action %s, got %s", UserDecisionAllowPermanent, events[1].UserAction)
	}
}

func TestProcessFilterEventAdapter(t *testing.T) {
	mockEmitter := &MockEventEmitter{}
	adapter := NewProcessFilterEventAdapter(mockEmitter, "test-session")

	proc := ProcessInfo{
		Name:      "test-process",
		Path:      "/usr/bin/test",
		PID:       1234,
		ParentPID: 1000,
	}

	ctx := context.Background()

	// Test OnAllow
	adapter.OnAllow(ctx, proc, "api.example.com", 443, "tcp", "explicit rule")
	events := mockEmitter.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Decision != "allow" {
		t.Errorf("expected decision allow, got %s", events[0].Decision)
	}

	// Test OnDeny
	adapter.OnDeny(ctx, proc, "blocked.example.com", 80, "tcp", "deny rule")
	events = mockEmitter.GetEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[1].Decision != "deny" {
		t.Errorf("expected decision deny, got %s", events[1].Decision)
	}

	// Test OnAudit
	adapter.OnAudit(ctx, proc, "audit.example.com", 8080, "tcp", "audit mode")
	events = mockEmitter.GetEvents()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[2].Decision != "audit" {
		t.Errorf("expected decision audit, got %s", events[2].Decision)
	}
}

func TestNoOpEventEmitter(t *testing.T) {
	emitter := &NoOpEventEmitter{}

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: "test",
		Target:      "example.com",
		Decision:    "allow",
	}

	// Should not panic
	err := emitter.EmitNetworkACLEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEventCategory(t *testing.T) {
	// Verify PNACL event types are registered in the category map
	if events.EventCategory[EventNetworkACL] != "network" {
		t.Errorf("EventNetworkACL category = %s, want network", events.EventCategory[EventNetworkACL])
	}
	if events.EventCategory[EventNetworkACLApproval] != "network" {
		t.Errorf("EventNetworkACLApproval category = %s, want network", events.EventCategory[EventNetworkACLApproval])
	}
	if events.EventCategory[EventNetworkACLAudit] != "network" {
		t.Errorf("EventNetworkACLAudit category = %s, want network", events.EventCategory[EventNetworkACLAudit])
	}
}

func TestBrokerEventEmitter_PolicyInfo(t *testing.T) {
	appender := &MockAppender{}
	emitter := NewBrokerEventEmitter(nil, "test-session", appender)

	event := NetworkACLEvent{
		Timestamp:   time.Now().UTC(),
		ProcessName: "test",
		Target:      "example.com",
		Port:        443,
		Decision:    "allow",
	}

	err := emitter.EmitNetworkACLEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := appender.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Policy == nil {
		t.Fatal("expected Policy to be set")
	}
	if ev.Policy.Decision != "allow" {
		t.Errorf("expected policy decision allow, got %s", ev.Policy.Decision)
	}
}
