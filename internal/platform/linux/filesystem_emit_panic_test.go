//go:build linux

package linux

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestEventEmitter_AppendEventSurvivesClosedChannel exercises the
// defense-in-depth recover guard: even if the event channel is closed
// out-of-band (i.e. NOT via eventEmitter.Close(), so the done flag is
// never set), an in-flight AppendEvent must recover from the resulting
// "send on closed channel" panic and return cleanly rather than crashing
// the daemon. The done flag (see TestEventEmitter_CloseQuiescesChannel)
// is the primary fix; this guard covers the narrow window between the
// done check and the send.
func TestEventEmitter_AppendEventSurvivesClosedChannel(t *testing.T) {
	ch := make(chan platform.IOEvent, 1)
	close(ch)

	em := &eventEmitter{
		eventChan: ch,
		sessionID: "session-teardown",
	}

	ev := types.Event{
		Timestamp: time.Now(),
		Type:      "file_read",
		Path:      "/workspace/a.txt",
		Operation: "read",
	}

	// Must not panic; must return nil.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AppendEvent panicked on closed channel: %v", r)
		}
	}()

	if err := em.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent returned %v on closed channel; expected nil", err)
	}
}

// TestEventEmitter_CloseQuiescesChannel verifies the fix:
// Close() sets the done flag *before* closing eventChan,
// so a subsequent AppendEvent short-circuits (no send, no
// panic) and the channel is observably closed for the consumer.
func TestEventEmitter_CloseQuiescesChannel(t *testing.T) {
	ch := make(chan platform.IOEvent, 4)
	em := &eventEmitter{eventChan: ch, sessionID: "s"}

	// Before Close: AppendEvent delivers to the channel.
	if err := em.AppendEvent(context.Background(), types.Event{Type: "file_read"}); err != nil {
		t.Fatalf("pre-Close AppendEvent: %v", err)
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected an event on the channel before Close()")
	}

	em.Close()

	// After Close: the done flag short-circuits AppendEvent -- it returns
	// nil without sending, so nothing new lands on the channel.
	if err := em.AppendEvent(context.Background(), types.Event{Type: "file_read"}); err != nil {
		t.Fatalf("post-Close AppendEvent: %v", err)
	}

	// The channel is closed: a receive yields the zero value with ok==false.
	if _, ok := <-ch; ok {
		t.Fatal("expected eventChan to be closed after Close()")
	}
}

// TestEventEmitter_CloseIsIdempotent verifies Close() can be called more
// than once without a double-close panic. This matters because m.Close()
// may run twice and both Mount.Close() and Filesystem.Unmount() route
// through closeEmitter().
func TestEventEmitter_CloseIsIdempotent(t *testing.T) {
	ch := make(chan platform.IOEvent, 1)
	em := &eventEmitter{eventChan: ch, sessionID: "s"}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("repeated Close() panicked: %v", r)
		}
	}()
	em.Close()
	em.Close() // must be a no-op, not a double-close panic
	em.Close()
}

// TestEventEmitter_NilChannelClose verifies Close() and AppendEvent are
// safe no-ops on an emitter with no channel (closeEmitter() type-asserts
// and calls Close() unconditionally, so this path must not panic).
func TestEventEmitter_NilChannelClose(t *testing.T) {
	em := &eventEmitter{sessionID: "s"} // eventChan == nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close()/AppendEvent on nil-channel emitter panicked: %v", r)
		}
	}()
	em.Close()
	if err := em.AppendEvent(context.Background(), types.Event{Type: "x"}); err != nil {
		t.Fatalf("AppendEvent on nil-channel emitter: %v", err)
	}
}
