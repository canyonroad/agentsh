package events

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/agentsh/agentsh/pkg/types"
)

type Broker struct {
	mu      sync.RWMutex
	subs    map[string]map[chan types.Event]struct{} // sessionID -> subscribers
	dropped atomic.Int64
}

func NewBroker() *Broker {
	return &Broker{subs: make(map[string]map[chan types.Event]struct{})}
}

func (b *Broker) Subscribe(sessionID string, buf int) chan types.Event {
	if buf <= 0 {
		buf = 100
	}
	ch := make(chan types.Event, buf)

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[sessionID]; !ok {
		b.subs[sessionID] = make(map[chan types.Event]struct{})
	}
	b.subs[sessionID][ch] = struct{}{}
	return ch
}

func (b *Broker) Unsubscribe(sessionID string, ch chan types.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m, ok := b.subs[sessionID]; ok {
		delete(m, ch)
		if len(m) == 0 {
			delete(b.subs, sessionID)
		}
	}
	close(ch)
}

func (b *Broker) Publish(ev types.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	m := b.subs[ev.SessionID]
	for ch := range m {
		select {
		case ch <- ev:
		default:
			// Drop on slow subscriber, log and count.
			count := b.dropped.Add(1)
			if count == 1 || count%100 == 0 {
				fmt.Fprintf(os.Stderr, "events: dropped event (session=%s type=%s, total dropped=%d)\n",
					ev.SessionID, ev.Type, count)
			}
		}
	}
}

// DroppedCount returns the total number of events dropped due to slow subscribers.
func (b *Broker) DroppedCount() int64 {
	return b.dropped.Load()
}
