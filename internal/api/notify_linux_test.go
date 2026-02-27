//go:build linux && cgo

package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
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
	broker := &notifyMockEventBroker{}
	sessID := "test-recover-panic"

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover(sessID, broker)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery")
	}

	evs := broker.getEvents()
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
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
}

func TestNotifyHandlerRecover_NilBroker_NoPanic(t *testing.T) {
	// Verify that a nil broker doesn't cause a secondary panic in the
	// recovery path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-nil-broker", nil)
		panic("injected test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery with nil broker")
	}
	// Reaching here without crashing proves the nil guard works.
}

func TestNotifyHandlerRecover_NoPanic_NoOp(t *testing.T) {
	// Verify notifyHandlerRecover is a no-op when no panic occurred.
	broker := &notifyMockEventBroker{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer notifyHandlerRecover("test-no-panic", broker)
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
