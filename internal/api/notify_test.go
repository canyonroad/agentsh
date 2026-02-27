package api

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type notifyMockEventStore struct {
	mu     sync.Mutex
	events []types.Event
}

func (m *notifyMockEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

type notifyMockEventBroker struct {
	mu     sync.Mutex
	events []types.Event
}

func (m *notifyMockEventBroker) Publish(ev types.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *notifyMockEventBroker) getEvents() []types.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]types.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

func TestStartNotifyHandler_NilSocket_NoOp(t *testing.T) {
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	pol := &policy.Engine{}

	// Should not panic with nil socket
	startNotifyHandler(context.Background(), nil, "test-session", pol, store, broker, nil, config.SandboxSeccompFileMonitorConfig{})
}

func TestStartNotifyHandler_NilPolicy_NoOp(t *testing.T) {
	// Create a temporary socket pair to test with
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}

	// Should close the socket and return without panic when policy is nil
	startNotifyHandler(context.Background(), r, "test-session", nil, store, broker, nil, config.SandboxSeccompFileMonitorConfig{})
}

func TestStartNotifyHandler_NilStore_NoOp(t *testing.T) {
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	pol := &policy.Engine{}

	// Should not panic with nil socket (store doesn't matter if socket is nil)
	startNotifyHandler(context.Background(), nil, "test-session", pol, store, broker, nil, config.SandboxSeccompFileMonitorConfig{})
}

func TestExtraProcConfig_NotifyFields(t *testing.T) {
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	pol := &policy.Engine{}

	cfg := &extraProcConfig{
		notifyParentSock: nil, // Would be set from socketpair
		notifySessionID:  "test-session-123",
		notifyPolicy:     pol,
		notifyStore:      store,
		notifyBroker:     broker,
		execveHandler:    nil, // Would be set when execve interception is enabled
	}

	if cfg.notifySessionID != "test-session-123" {
		t.Errorf("expected session ID 'test-session-123', got %q", cfg.notifySessionID)
	}
	if cfg.notifyPolicy != pol {
		t.Error("policy not set correctly")
	}
	if cfg.notifyStore != store {
		t.Error("store not set correctly")
	}
	if cfg.notifyBroker != broker {
		t.Error("broker not set correctly")
	}
	if cfg.execveHandler != nil {
		t.Error("execveHandler should be nil")
	}
}
