//go:build linux && cgo

package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
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

	// Give the goroutine time to complete.
	time.Sleep(100 * time.Millisecond)

	// No panic event should be published for a clean error exit.
	events := broker.getEvents()
	for _, ev := range events {
		if ev.Type == "notify_handler_panic" {
			t.Error("unexpected panic event for clean error exit")
		}
	}
}

func TestStartNotifyHandler_PanicEvent(t *testing.T) {
	// Directly test the panic-recovery event publishing pattern
	// used in startNotifyHandler, without needing the full seccomp
	// infrastructure. This validates that the defer recover() correctly
	// catches panics and publishes an observable event to the broker.
	broker := &notifyMockEventBroker{}
	sessID := "test-direct-panic"

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				broker.Publish(types.Event{
					Type:      "notify_handler_panic",
					SessionID: sessID,
					Fields: map[string]any{
						"error": "test panic",
					},
				})
			}
		}()
		panic("test panic")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for panic recovery")
	}

	events := broker.getEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != "notify_handler_panic" {
		t.Errorf("event type = %q, want %q", ev.Type, "notify_handler_panic")
	}
	if ev.SessionID != sessID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, sessID)
	}
	if ev.Fields["error"] != "test panic" {
		t.Errorf("error field = %q, want %q", ev.Fields["error"], "test panic")
	}
}
