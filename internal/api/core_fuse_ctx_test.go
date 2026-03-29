package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// ctxAwareEventStore respects context cancellation, like the real SQLite store.
type ctxAwareEventStore struct {
	mu     sync.Mutex
	events []types.Event
}

func (f *ctxAwareEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *ctxAwareEventStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (f *ctxAwareEventStore) Close() error { return nil }

func (f *ctxAwareEventStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// TestProcessIOEvents_PersistsAfterContextCancellation verifies that
// processIOEvents uses its own background context, not a caller-provided
// context that may already be canceled. This is a regression test for a bug
// where the HTTP request context was captured and used for event persistence,
// causing silent drops after the first exec response was sent.
func TestProcessIOEvents_PersistsAfterContextCancellation(t *testing.T) {
	fake := &ctxAwareEventStore{}
	cStore := composite.New(fake, nil)
	broker := events.NewBroker()
	app := &App{
		store:    cStore,
		broker:   broker,
		sessions: session.NewManager(0),
	}

	ch := make(chan platform.IOEvent, 10)

	// Send 3 events
	for i := 0; i < 3; i++ {
		ch <- platform.IOEvent{
			Timestamp: time.Now(),
			SessionID: "test-session",
			Type:      platform.EventFileWrite,
			Path:      "/tmp/test",
		}
	}
	close(ch)

	// processIOEvents no longer takes a context — it creates its own
	// background context per event. All 3 events should be persisted.
	app.processIOEvents(ch)

	if got := fake.count(); got != 3 {
		t.Fatalf("expected 3 events persisted, got %d", got)
	}
}
