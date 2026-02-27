//go:build linux && cgo

package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func TestStartNotifyHandler_GracefulErrorExit(t *testing.T) {
	// Create a unix socketpair so RecvFD can be attempted.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "parent")
	writeSock := os.NewFile(uintptr(fds[1]), "child")

	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}

	// Close write end immediately so RecvFD returns an error.
	writeSock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startNotifyHandler(ctx, parentSock, "test-graceful", nil, store, broker, nil, config.SandboxSeccompFileMonitorConfig{})

	// Poll until the goroutine exits (parentSock gets closed by the deferred Close).
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for goroutine to finish")
		default:
		}
		// parentSock.Fd() returns ^0 (invalid) after the goroutine closes it.
		if int(parentSock.Fd()) == -1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// No panic event should be published for a clean error exit.
	evs := broker.getEvents()
	for _, ev := range evs {
		if ev.Type == string(events.EventNotifyHandlerPanic) {
			t.Error("unexpected panic event for clean error exit")
		}
	}
}

func TestNotifyHandlerRecover_PublishesPanicEvent(t *testing.T) {
	// Test the real notifyHandlerRecover function (used by startNotifyHandler)
	// by triggering a panic in a goroutine guarded by it.
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	sessID := "test-recover-panic"

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover(sessID, store, broker)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery")
	}

	// Verify broker received the event.
	evs := broker.getEvents()
	if len(evs) != 1 {
		t.Fatalf("expected 1 broker event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Type != string(events.EventNotifyHandlerPanic) {
		t.Errorf("event type = %q, want %q", ev.Type, string(events.EventNotifyHandlerPanic))
	}
	if ev.SessionID != sessID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, sessID)
	}
	if ev.Fields["error"] != "injected test panic" {
		t.Errorf("error field = %q, want %q", ev.Fields["error"], "injected test panic")
	}
	if ev.ID == "" {
		t.Error("event ID should be set")
	}
	if ev.Timestamp.IsZero() {
		t.Error("event Timestamp should be set")
	}

	// Verify store also received the event.
	store.mu.Lock()
	storeEvs := store.events
	store.mu.Unlock()
	if len(storeEvs) != 1 {
		t.Fatalf("expected 1 store event, got %d", len(storeEvs))
	}
	if storeEvs[0].Type != string(events.EventNotifyHandlerPanic) {
		t.Errorf("store event type = %q, want %q", storeEvs[0].Type, string(events.EventNotifyHandlerPanic))
	}
}

func TestNotifyHandlerRecover_NilBrokerAndStore_NoPanic(t *testing.T) {
	// Verify that nil broker and store don't cause a secondary panic
	// in the recovery path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-nil-deps", nil, nil)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery with nil broker/store")
	}
	// Reaching here without crashing proves the nil guards work.
}

func TestNotifyHandlerRecover_NoPanic_NoOp(t *testing.T) {
	// Verify notifyHandlerRecover is a no-op when no panic occurred.
	store := &notifyMockEventStore{}
	broker := &notifyMockEventBroker{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-no-panic", store, broker)
		// no panic
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	evs := broker.getEvents()
	if len(evs) != 0 {
		t.Errorf("expected 0 events, got %d", len(evs))
	}
}

// panickingBroker is an eventBroker whose Publish method always panics,
// used to test the nested recover() in notifyHandlerRecover.
type panickingBroker struct{}

func (b *panickingBroker) Publish(ev types.Event) {
	panic("broker panic")
}

func TestNotifyHandlerRecover_BrokerPanic_NoCrash(t *testing.T) {
	// Verify the nested recover() catches panics from broker.Publish
	// so a faulty broker doesn't crash the process.
	store := &notifyMockEventStore{}
	broker := &panickingBroker{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-broker-panic", store, broker)
		panic("original panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — broker panic likely crashed the goroutine")
	}

	// The store should still have received the event (AppendEvent runs
	// before Publish in the recovery function).
	store.mu.Lock()
	storeEvs := store.events
	store.mu.Unlock()
	if len(storeEvs) != 1 {
		t.Fatalf("expected 1 store event, got %d", len(storeEvs))
	}
	if storeEvs[0].Fields["error"] != "original panic" {
		t.Errorf("store error = %q, want %q", storeEvs[0].Fields["error"], "original panic")
	}
}
