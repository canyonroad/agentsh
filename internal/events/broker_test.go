package events

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestBrokerPublishAndSubscribe(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe("sess1", 10)
	defer b.Unsubscribe("sess1", ch)

	ev := types.Event{SessionID: "sess1", Type: "test"}
	b.Publish(ev)

	select {
	case got := <-ch:
		if got.SessionID != ev.SessionID || got.Type != ev.Type {
			t.Fatalf("event mismatch: got %+v want %+v", got, ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBrokerDropsWhenSlowSubscriber(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe("sess1", 1)
	defer b.Unsubscribe("sess1", ch)

	ev := types.Event{SessionID: "sess1", Type: "test"}
	b.Publish(ev) // fills buffer
	b.Publish(ev) // should drop

	if n := len(ch); n != 1 {
		t.Fatalf("expected buffer length 1 after drop, got %d", n)
	}
}

func TestBrokerUnsubscribeClosesChannel(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe("sess1", 1)
	b.Unsubscribe("sess1", ch)

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel closed")
		}
	default:
		t.Fatal("expected channel to be closed and readable")
	}
}
